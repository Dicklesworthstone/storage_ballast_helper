//! Special location registry: /tmp, /dev/shm, RAM-backed mounts with buffer targets.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::core::config::TelemetryConfig;
use crate::core::errors::Result;
use crate::monitor::ewma::DiskRateEstimator;
use crate::monitor::fs_stats::FsStatsSample;
use crate::platform::pal::{FsStats, MountPoint, Platform};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialKind {
    Tmpfs,
    DevShm,
    Ramfs,
    UserTmp,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialLocation {
    pub path: PathBuf,
    pub kind: SpecialKind,
    pub buffer_pct: u8,
    pub scan_interval: Duration,
    pub priority: u8,
}

impl SpecialLocation {
    #[must_use]
    pub fn needs_attention(&self, stats: &FsStats) -> bool {
        stats.free_pct() < f64::from(self.buffer_pct)
    }

    #[must_use]
    pub fn scan_due(&self, last_scan: Option<Instant>, now: Instant) -> bool {
        last_scan.is_none_or(|last| now.duration_since(last) >= self.scan_interval)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpecialLocationRegistry {
    locations: Vec<SpecialLocation>,
}

impl SpecialLocationRegistry {
    #[must_use]
    pub fn new(locations: Vec<SpecialLocation>) -> Self {
        let mut deduped = HashMap::<PathBuf, SpecialLocation>::new();
        for location in locations {
            // Later entries intentionally win so operator-provided custom paths
            // can override auto-discovered defaults for the same location.
            deduped.insert(location.path.clone(), location);
        }
        let mut unique: Vec<SpecialLocation> = deduped.into_values().collect();
        unique.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.path.cmp(&right.path))
        });
        Self { locations: unique }
    }

    pub fn discover(platform: &dyn Platform, custom_paths: &[PathBuf]) -> Result<Self> {
        let mounts = platform.mount_points()?;
        let mut locations = Vec::<SpecialLocation>::new();

        for mount in mounts {
            if !is_actionable_special_mount(&mount) {
                continue;
            }
            let kind = match mount.path.as_path() {
                p if p == Path::new("/dev/shm") => SpecialKind::DevShm,
                p if p == Path::new("/tmp") => SpecialKind::Tmpfs,
                _ if mount.fs_type == "ramfs" => SpecialKind::Ramfs,
                _ => SpecialKind::Tmpfs,
            };
            let (buffer_pct, scan_interval, priority) = match kind {
                SpecialKind::DevShm => (20, Duration::from_secs(3), 255),
                SpecialKind::Ramfs => (18, Duration::from_secs(4), 220),
                SpecialKind::Tmpfs => (15, Duration::from_secs(5), 200),
                SpecialKind::UserTmp | SpecialKind::Custom(_) => (15, Duration::from_secs(5), 150),
            };
            locations.push(SpecialLocation {
                path: mount.path,
                kind,
                buffer_pct,
                scan_interval,
                priority,
            });
        }

        for path in custom_paths {
            locations.push(SpecialLocation {
                path: path.clone(),
                kind: SpecialKind::Custom(path.display().to_string()),
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 140,
            });
        }

        if locations
            .iter()
            .all(|location| location.path != Path::new("/tmp"))
        {
            locations.push(SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::UserTmp,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 160,
            });
        }

        if locations
            .iter()
            .all(|location| location.path != Path::new("/data/tmp"))
        {
            locations.push(SpecialLocation {
                path: PathBuf::from("/data/tmp"),
                kind: SpecialKind::UserTmp,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 155,
            });
        }

        Ok(Self::new(locations))
    }

    #[must_use]
    pub fn all(&self) -> &[SpecialLocation] {
        &self.locations
    }
}

fn is_actionable_special_mount(mount: &MountPoint) -> bool {
    if !mount.is_ram_backed {
        return false;
    }

    if mount.path == Path::new("/dev/shm") {
        return true;
    }

    let fs_type = mount.fs_type.to_ascii_lowercase();
    if matches!(fs_type.as_str(), "devfs" | "devtmpfs") {
        return false;
    }

    // `/dev` and its device pseudo-filesystems are not reclaimable scratch
    // space. Linux `/dev/shm` is handled explicitly above.
    if mount.path == Path::new("/dev") || mount.path.starts_with("/dev") {
        return false;
    }

    // Systemd runtime dirs are small credential/session tmpfs mounts that are
    // often "full" by design and not actionable.
    let path_str = mount.path.to_string_lossy();
    !(path_str.starts_with("/run/credentials/")
        || path_str.starts_with("/run/user/")
        || path_str == "/run/lock"
        || path_str == "/run")
}

/// Rate evidence for special mounts which need not be scanner roots. Each
/// location learns from capacity observations; a current main-monitor rate is
/// only a prior while this independent estimator warms up.
#[derive(Debug, Default)]
pub(crate) struct SpecialLocationRates {
    locations: HashMap<PathBuf, LocationRate>,
    mount_priors: HashMap<PathBuf, (FsStatsSample, f64)>,
}

#[derive(Debug)]
struct LocationRate {
    sample: FsStatsSample,
    estimator: DiskRateEstimator,
    rate: Option<f64>,
    allow_prior: bool,
}

impl SpecialLocationRates {
    /// Main-monitor observations remain available after pressure dispatch
    /// consumes its mount responses, but never survive a new sampling tick.
    pub fn begin_tick(&mut self) {
        self.mount_priors.clear();
    }

    pub fn record_mount(&mut self, sample: &FsStatsSample, rate: f64) {
        if rate.is_finite()
            && sample.stats.total_bytes > 0
            && sample.stats.free_bytes <= sample.stats.total_bytes
            && sample.stats.available_bytes <= sample.stats.free_bytes
        {
            self.mount_priors
                .insert(sample.stats.mount_point.clone(), (sample.clone(), rate));
        } else {
            self.mount_priors.remove(&sample.stats.mount_point);
        }
    }

    pub fn retain(&mut self, registry: &SpecialLocationRegistry) {
        self.locations
            .retain(|path, _| registry.all().iter().any(|location| &location.path == path));
    }

    pub fn forget(&mut self, path: &Path) {
        self.locations.remove(path);
    }

    /// Cached observations retain their original timestamp and never train
    /// the estimator twice. Three missed nominal polls break continuity;
    /// invalid, future-dated and stale samples provide no horizon evidence.
    /// A replacement filesystem or resized volume begins a new history.
    pub fn observe(
        &mut self,
        location: &SpecialLocation,
        sample: &FsStatsSample,
        now: Instant,
        poll_interval: Duration,
        telemetry: &TelemetryConfig,
    ) -> Option<f64> {
        let max_gap = location
            .scan_interval
            .max(poll_interval)
            .max(Duration::from_secs(1))
            .saturating_mul(3);
        let stats = &sample.stats;
        if stats.total_bytes == 0
            || stats.free_bytes > stats.total_bytes
            || stats.available_bytes > stats.free_bytes
            || now
                .checked_duration_since(sample.collected_at)
                .is_none_or(|age| age > max_gap)
        {
            self.forget(&location.path);
            return None;
        }
        let reset = self.locations.get(&location.path).is_some_and(|old| {
            !old.sample.same_filesystem_as(sample)
                || sample
                    .collected_at
                    .checked_duration_since(old.sample.collected_at)
                    .is_none_or(|gap| gap > max_gap)
        });
        if reset {
            self.forget(&location.path);
        }
        let mount_prior = self
            .mount_priors
            .get(&stats.mount_point)
            .filter(|(prior, _)| {
                prior.same_filesystem_as(sample)
                    && sample.collected_at >= prior.collected_at
                    && now
                        .checked_duration_since(prior.collected_at)
                        .is_some_and(|age| age <= max_gap)
            })
            .map(|(_, rate)| *rate);
        let rate_state = self
            .locations
            .entry(location.path.clone())
            .or_insert_with(|| {
                let mut estimator = DiskRateEstimator::with_history_cap(
                    telemetry.ewma_base_alpha,
                    telemetry.ewma_min_alpha,
                    telemetry.ewma_max_alpha,
                    telemetry.ewma_min_samples,
                    telemetry.ewma_rate_history_size,
                );
                estimator.update(stats.available_bytes, sample.collected_at, 0);
                LocationRate {
                    sample: sample.clone(),
                    estimator,
                    rate: None,
                    allow_prior: !reset,
                }
            });
        if sample.collected_at > rate_state.sample.collected_at {
            let estimate =
                rate_state
                    .estimator
                    .update(stats.available_bytes, sample.collected_at, 0);
            // A positive trailing EWMA must not keep a horizon alert alive
            // once the current interval shows that space stopped shrinking.
            rate_state.rate = if stats.available_bytes >= rate_state.sample.stats.available_bytes {
                Some(0.0)
            } else {
                (!estimate.fallback_active && estimate.bytes_per_second.is_finite())
                    .then(|| estimate.bytes_per_second.max(0.0))
            };
            rate_state.sample = sample.clone();
        }
        let prior = rate_state
            .allow_prior
            .then_some(mount_prior)
            .flatten()
            .filter(|rate| rate.is_finite())
            .map(|rate| rate.max(0.0));
        Some(rate_state.rate.or(prior).unwrap_or(0.0))
    }
}

// ──────────────────── horizon rule (Q2) ────────────────────

/// Default absolute floor for disk-backed temp roots: below this many free
/// bytes a location is short of room no matter how large the volume is.
pub const DEFAULT_ABSOLUTE_FLOOR_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// Default time-to-harm horizon.
pub const DEFAULT_ALERT_HORIZON: Duration = Duration::from_mins(30);
/// Default minimum spacing between repeated alerts for one location.
pub const DEFAULT_ALERT_INTERVAL: Duration = Duration::from_mins(15);
/// Floor on the write rate used for the horizon, so a quiet volume has a
/// finite (long) horizon instead of an infinite one: 1 MiB/s.
pub const MIN_HORIZON_RATE_BYTES_PER_SEC: f64 = 1_048_576.0;
/// RAM-backed locations also alert on plain fullness, since their capacity
/// is small and shared with memory.
pub const RAM_BACKED_MIN_FREE_PCT: f64 = 20.0;

/// Severity of a special-location alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpecialAlert {
    /// Nothing to say.
    None,
    /// Disk-backed location short of room or filling fast.
    Warning,
    /// RAM-backed location short of room or filling fast.
    Critical,
}

impl SpecialAlert {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// The time-to-harm rule: alert on how soon a location runs out.
///
/// Not on a percentage alone: 760 GiB free on a 5.5 TiB volume is not an
/// incident because it is below 15%; 10 GiB free with a 1 GiB/min writer
/// is, even though it may be above the percentage.
#[derive(Debug, Clone, Copy)]
pub struct HorizonRule {
    /// Alert when the location would be exhausted within this.
    pub alert_horizon: Duration,
    /// Disk-backed roots: the percent buffer is capped at this many bytes.
    pub absolute_floor_bytes: u64,
    /// RAM-backed roots also alert below this free percent.
    pub ram_backed_min_free_pct: f64,
    /// Floor on the rate used for the horizon.
    pub min_rate_bytes_per_sec: f64,
}

impl Default for HorizonRule {
    fn default() -> Self {
        Self {
            alert_horizon: DEFAULT_ALERT_HORIZON,
            absolute_floor_bytes: DEFAULT_ABSOLUTE_FLOOR_BYTES,
            ram_backed_min_free_pct: RAM_BACKED_MIN_FREE_PCT,
            min_rate_bytes_per_sec: MIN_HORIZON_RATE_BYTES_PER_SEC,
        }
    }
}

/// What the rule concluded about one location.
#[derive(Debug, Clone, PartialEq)]
pub struct SpecialAssessment {
    pub alert: SpecialAlert,
    /// Seconds until exhaustion at the observed (floored) write rate.
    pub horizon_secs: f64,
    /// Scan urgency: `clamp(1 - horizon / alert_horizon, 0, 1)`, with a small
    /// floor when the alert comes from room rather than rate.
    pub urgency: f64,
    /// Bytes below which the location is short of room.
    pub floor_bytes: u64,
    pub reason: String,
}

/// Time to exhaustion in seconds at `rate_bytes_per_sec`, floored at
/// `min_rate` so quiet volumes get a long but finite horizon.
#[must_use]
pub fn horizon_secs(free_bytes: u64, rate_bytes_per_sec: f64, min_rate: f64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let free = free_bytes as f64;
    let rate = if rate_bytes_per_sec.is_finite() {
        rate_bytes_per_sec.max(min_rate.max(1.0))
    } else {
        min_rate.max(1.0)
    };
    free / rate
}

impl HorizonRule {
    /// Assess a location from its stats, the mount's write rate (bytes per
    /// second, positive when filling) and whether it is RAM-backed.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn assess(
        &self,
        location: &SpecialLocation,
        stats: &FsStats,
        rate_bytes_per_sec: f64,
        ram_backed: bool,
    ) -> SpecialAssessment {
        let horizon = horizon_secs(
            stats.available_bytes,
            rate_bytes_per_sec,
            self.min_rate_bytes_per_sec,
        );
        let horizon_limit = self.alert_horizon.as_secs_f64().max(1.0);
        let percent_floor =
            (stats.total_bytes as f64 * f64::from(location.buffer_pct) / 100.0) as u64;
        let floor_bytes = if ram_backed {
            (stats.total_bytes as f64 * self.ram_backed_min_free_pct / 100.0) as u64
        } else {
            percent_floor.min(self.absolute_floor_bytes)
        };
        let short_of_room = stats.available_bytes < floor_bytes;
        let actual_horizon = if rate_bytes_per_sec > 0.0 {
            stats.available_bytes as f64 / rate_bytes_per_sec
        } else {
            f64::INFINITY
        };
        let filling_fast = actual_horizon < horizon_limit;
        let severity = if ram_backed {
            SpecialAlert::Critical
        } else {
            SpecialAlert::Warning
        };
        let alert = if short_of_room || filling_fast {
            severity
        } else {
            SpecialAlert::None
        };
        let urgency = if alert == SpecialAlert::None {
            0.0
        } else if filling_fast {
            (1.0 - actual_horizon / horizon_limit).clamp(0.2, 1.0)
        } else {
            0.2
        };
        let reason = match (short_of_room, filling_fast) {
            (true, true) => format!(
                "{} free below the {} floor and {:.0}s to exhaustion",
                stats.available_bytes, floor_bytes, actual_horizon
            ),
            (true, false) => format!(
                "{} free below the {} floor",
                stats.available_bytes, floor_bytes
            ),
            (false, true) => format!(
                "{:.0}s to exhaustion at {:.0} B/s",
                actual_horizon,
                rate_bytes_per_sec.max(0.0)
            ),
            (false, false) => format!(
                "{} free above the {} floor, {:.0}s horizon",
                stats.available_bytes, floor_bytes, horizon
            ),
        };
        SpecialAssessment {
            alert,
            horizon_secs: horizon,
            urgency,
            floor_bytes,
            reason,
        }
    }
}

/// One alert per location per interval; a change of severity is reported
/// at once.
#[derive(Debug, Default)]
pub struct AlertThrottle {
    last: HashMap<PathBuf, (SpecialAlert, Instant)>,
}

impl AlertThrottle {
    /// Whether an alert of `severity` for `path` should be emitted now.
    /// `SpecialAlert::None` clears the location (the recovery is reported
    /// once) and never repeats.
    pub fn should_emit(
        &mut self,
        path: &Path,
        severity: SpecialAlert,
        now: Instant,
        interval: Duration,
    ) -> bool {
        let previous = self.last.get(path).copied();
        let emit = match previous {
            None => severity != SpecialAlert::None,
            Some((last_severity, at)) => {
                last_severity != severity
                    || (severity != SpecialAlert::None
                        && now.saturating_duration_since(at) >= interval)
            }
        };
        if emit {
            if severity == SpecialAlert::None {
                self.last.remove(path);
            } else {
                self.last.insert(path.to_path_buf(), (severity, now));
            }
        }
        emit
    }
}

#[cfg(test)]
mod rate_tests {
    use super::*;
    use crate::monitor::fs_stats::FsStatsCollector;
    use crate::platform::pal::{MemoryInfo, MockPlatform, PlatformPaths};
    use std::sync::Arc;

    const GIB: u64 = 1 << 30;

    fn location() -> SpecialLocation {
        SpecialLocation {
            path: PathBuf::from("/special-only"),
            kind: SpecialKind::DevShm,
            buffer_pct: 20,
            scan_interval: Duration::from_secs(5),
            priority: 255,
        }
    }

    fn sample(mount: &str, device: &str, free: u64, at: Instant) -> FsStatsSample {
        let mount = PathBuf::from(mount);
        let platform = Arc::new(MockPlatform::new(
            vec![MountPoint {
                path: mount.clone(),
                device: device.into(),
                fs_type: "tmpfs".into(),
                is_ram_backed: true,
            }],
            HashMap::from([(
                mount.clone(),
                FsStats {
                    total_bytes: 16 * GIB,
                    free_bytes: free,
                    available_bytes: free,
                    fs_type: "tmpfs".into(),
                    mount_point: mount.clone(),
                    is_readonly: false,
                },
            )]),
            MemoryInfo {
                total_bytes: 32 * GIB,
                available_bytes: 24 * GIB,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        ));
        let collector = FsStatsCollector::new(platform, Duration::ZERO);
        let mut sample = collector.collect_sample(&mount).unwrap();
        sample.collected_at = at;
        sample
    }

    fn observe(
        rates: &mut SpecialLocationRates,
        sample: &FsStatsSample,
        now: Instant,
        prior: Option<f64>,
    ) -> Option<f64> {
        rates.begin_tick();
        if let Some(rate) = prior {
            rates.record_mount(sample, rate);
        }
        rates.observe(
            &location(),
            sample,
            now,
            Duration::from_secs(5),
            &TelemetryConfig::default(),
        )
    }

    fn filling_history(rates: &mut SpecialLocationRates, start: Instant) -> FsStatsSample {
        let mut last = sample("/", "tmpfs-a", 12 * GIB, start);
        for step in 0..=4 {
            let at = start + Duration::from_secs(step * 5);
            last = sample("/", "tmpfs-a", (12 - step) * GIB, at);
            observe(rates, &last, at, None).unwrap();
        }
        last
    }

    #[test]
    fn unmonitored_special_mount_warns_before_fullness_and_stops_on_recovery() {
        let start = Instant::now();
        let mut rates = SpecialLocationRates::default();
        let last = filling_history(&mut rates, start);
        let rate = observe(&mut rates, &last, last.collected_at, None).unwrap();
        let rule = HorizonRule::default();
        assert!(last.stats.free_pct() > RAM_BACKED_MIN_FREE_PCT);
        assert_eq!(
            rule.assess(&location(), &last.stats, 0.0, true).alert,
            SpecialAlert::None,
            "the old zero-rate path missed this shrinking but not-full mount",
        );
        let filling = rule.assess(&location(), &last.stats, rate, true);
        assert_eq!(filling.alert, SpecialAlert::Critical);
        assert!(filling.horizon_secs < rule.alert_horizon.as_secs_f64());

        for (offset, free) in [(25, 8 * GIB), (30, 10 * GIB)] {
            let at = start + Duration::from_secs(offset);
            let recovered = sample("/", "tmpfs-a", free, at);
            let rate = observe(&mut rates, &recovered, at, Some(1e12)).unwrap();
            assert_eq!(rate, 0.0, "observed nonconsumption beats a positive prior");
            assert_eq!(
                rule.assess(&location(), &recovered.stats, rate, true).alert,
                SpecialAlert::None,
            );
        }
    }

    #[test]
    fn cache_hits_do_not_train_or_renew_rate_evidence() {
        let start = Instant::now();
        let mut rates = SpecialLocationRates::default();
        let seed = sample("/", "tmpfs-a", 12 * GIB, start);
        for seconds in 0..=15 {
            assert_eq!(
                observe(
                    &mut rates,
                    &seed,
                    start + Duration::from_secs(seconds),
                    None
                ),
                Some(0.0),
            );
        }
        assert_eq!(
            rates.locations[&location().path].estimator.sample_count(),
            0
        );
        assert_eq!(
            observe(
                &mut rates,
                &seed,
                start + Duration::from_secs(16),
                Some(1e12)
            ),
            None,
            "a warm main-monitor prior cannot refresh stale capacity",
        );
        assert!(rates.locations.is_empty());
    }

    #[test]
    fn replacement_resized_and_interrupted_mounts_restart_without_old_rate_or_prior() {
        let start = Instant::now();
        for case in ["device", "mount", "resize", "readonly", "gap"] {
            let mut rates = SpecialLocationRates::default();
            filling_history(&mut rates, start);
            let at = start + Duration::from_secs(if case == "gap" { 60 } else { 25 });
            let mut next = sample(
                if case == "mount" { "/new-special" } else { "/" },
                if case == "device" {
                    "tmpfs-b"
                } else {
                    "tmpfs-a"
                },
                4 * GIB,
                at,
            );
            if case == "resize" {
                next.stats.total_bytes = 8 * GIB;
            }
            if case == "readonly" {
                next.stats.is_readonly = true;
            }
            assert_eq!(
                observe(&mut rates, &next, at, Some(1e12)),
                Some(0.0),
                "{case}"
            );
            assert_eq!(
                observe(&mut rates, &next, at + Duration::from_secs(1), Some(1e12)),
                Some(0.0),
                "cache hits must not resurrect the replaced mount's prior: {case}",
            );
            assert_eq!(
                rates.locations[&location().path].estimator.sample_count(),
                0
            );
        }
    }

    #[test]
    fn invalid_future_and_failed_observations_cannot_bridge_a_history() {
        let start = Instant::now();
        for case in ["capacity", "available", "zero", "future", "missing"] {
            let mut rates = SpecialLocationRates::default();
            filling_history(&mut rates, start);
            let now = start + Duration::from_secs(25);
            let mut bad = sample("/", "tmpfs-a", 7 * GIB, now);
            match case {
                "capacity" => bad.stats.free_bytes = 17 * GIB,
                "available" => bad.stats.available_bytes = 8 * GIB,
                "zero" => {
                    bad.stats.total_bytes = 0;
                    bad.stats.free_bytes = 0;
                    bad.stats.available_bytes = 0;
                }
                "future" => bad.collected_at = now + Duration::from_secs(1),
                _ => rates.forget(&location().path),
            }
            if case != "missing" {
                assert_eq!(observe(&mut rates, &bad, now, Some(1e12)), None, "{case}");
            }
            assert!(rates.locations.is_empty(), "{case}");
            let next = sample("/", "tmpfs-a", GIB, now + Duration::from_secs(5));
            assert_eq!(
                observe(&mut rates, &next, next.collected_at, None),
                Some(0.0),
                "{case}"
            );
        }
    }

    #[test]
    fn cold_start_uses_only_a_finite_prior_and_removed_locations_drop_their_state() {
        let start = Instant::now();
        let mut rates = SpecialLocationRates::default();
        let seed = sample("/", "tmpfs-a", 12 * GIB, start);
        assert_eq!(observe(&mut rates, &seed, start, Some(123.0)), Some(123.0));
        for prior in [f64::INFINITY, f64::NAN, -12.0] {
            assert_eq!(observe(&mut rates, &seed, start, Some(prior)), Some(0.0));
        }
        rates.retain(&SpecialLocationRegistry::default());
        assert!(rates.locations.is_empty());
    }

    #[test]
    fn mount_prior_must_match_fresh_capacity_evidence_from_the_current_tick() {
        let start = Instant::now();
        let now = start + Duration::from_secs(20);
        let current = sample("/", "tmpfs-a", 12 * GIB, now);
        for case in ["fresh", "stale", "replacement", "future", "next_tick"] {
            let mut rates = SpecialLocationRates::default();
            let prior = match case {
                "stale" => sample("/", "tmpfs-a", 12 * GIB, start),
                "replacement" => sample("/", "tmpfs-b", 12 * GIB, now),
                "future" => sample("/", "tmpfs-a", 12 * GIB, now + Duration::from_secs(1)),
                _ => current.clone(),
            };
            rates.record_mount(&prior, 123.0);
            if case == "next_tick" {
                rates.begin_tick();
            }
            assert_eq!(
                rates.observe(
                    &location(),
                    &current,
                    now,
                    Duration::from_secs(5),
                    &TelemetryConfig::default(),
                ),
                Some(if case == "fresh" { 123.0 } else { 0.0 }),
                "{case}",
            );
        }
    }
}

#[cfg(test)]
mod horizon_tests {
    use super::{
        AlertThrottle, HorizonRule, SpecialAlert, SpecialKind, SpecialLocation, horizon_secs,
    };
    use crate::platform::pal::FsStats;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * GIB;

    fn location(buffer_pct: u8) -> SpecialLocation {
        SpecialLocation {
            path: PathBuf::from("/data/tmp"),
            kind: SpecialKind::UserTmp,
            buffer_pct,
            scan_interval: Duration::from_secs(60),
            priority: 128,
        }
    }

    fn stats(total: u64, free: u64) -> FsStats {
        FsStats {
            total_bytes: total,
            free_bytes: free,
            available_bytes: free,
            fs_type: "btrfs".to_string(),
            mount_point: PathBuf::from("/data"),
            is_readonly: false,
        }
    }

    #[test]
    fn horizon_is_monotone_in_free_space_and_rate() {
        let rate = 10.0 * 1_048_576.0;
        let min = 1_048_576.0;
        assert!(horizon_secs(10 * GIB, rate, min) < horizon_secs(20 * GIB, rate, min));
        assert!(horizon_secs(10 * GIB, 2.0 * rate, min) < horizon_secs(10 * GIB, rate, min));
        // A quiet or recovering volume gets the floored rate, never infinity.
        let quiet = horizon_secs(10 * GIB, 0.0, min);
        assert!(quiet.is_finite());
        assert!((quiet - 10240.0).abs() < 1e-6);
        assert_eq!(horizon_secs(10 * GIB, -5.0e6, min), quiet);
        assert!(horizon_secs(10 * GIB, f64::NAN, min).is_finite());
    }

    /// The operator workstation: 13.9% free of 5.5 TiB (760 GiB) at a low
    /// write rate is not an incident, whatever the percent buffer says.
    #[test]
    fn large_volume_below_percent_buffer_but_above_the_floor_does_not_alert() {
        let rule = HorizonRule::default();
        let total = 5_632 * GIB; // 5.5 TiB
        let free = 760 * GIB;
        let assessment = rule.assess(&location(15), &stats(total, free), 2_000_000.0, false);
        assert_eq!(
            assessment.alert,
            SpecialAlert::None,
            "{}",
            assessment.reason
        );
        assert!((assessment.urgency - 0.0).abs() < f64::EPSILON);
        assert_eq!(
            assessment.floor_bytes,
            32 * GIB,
            "percent floor capped at 32 GiB"
        );
    }

    /// Alerts are decided in horizon terms, so two volumes with the same
    /// time-to-harm get the same answer regardless of their size.
    #[test]
    fn alert_depends_on_horizon_not_on_volume_size() {
        let rule = HorizonRule::default();
        let writer = 1024.0 * 1_048_576.0 / 60.0; // 1 GiB/min
        let small = rule.assess(&location(15), &stats(100 * GIB, 10 * GIB), writer, false);
        let large = rule.assess(&location(15), &stats(10 * TIB, 10 * GIB), writer, false);
        assert_eq!(small.alert, SpecialAlert::Warning, "{}", small.reason);
        assert_eq!(large.alert, SpecialAlert::Warning, "{}", large.reason);
        assert!((small.horizon_secs - large.horizon_secs).abs() < 1e-6);
        assert!((small.urgency - large.urgency).abs() < 1e-9);
        assert!(
            small.urgency > 0.6,
            "10 minutes to harm is urgent: {}",
            small.urgency
        );
    }

    #[test]
    fn horizon_cases_above_the_absolute_floor() {
        let rule = HorizonRule::default();
        // 100 GiB free with a 10 GiB/min writer: ten minutes to harm -> warning.
        let fast = rule.assess(
            &location(15),
            &stats(2 * TIB, 100 * GIB),
            10.0 * 1024.0 * 1_048_576.0 / 60.0,
            false,
        );
        assert_eq!(fast.alert, SpecialAlert::Warning, "{}", fast.reason);
        assert!(fast.urgency > 0.5);
        // 100 GiB free at 1 GiB/h: a hundred hours -> nothing.
        let slow = rule.assess(
            &location(15),
            &stats(2 * TIB, 100 * GIB),
            1024.0 * 1_048_576.0 / 3600.0,
            false,
        );
        assert_eq!(slow.alert, SpecialAlert::None, "{}", slow.reason);
    }

    #[test]
    fn ram_backed_locations_alert_critical_on_fullness_or_horizon() {
        let rule = HorizonRule::default();
        let shm = SpecialLocation {
            path: PathBuf::from("/dev/shm"),
            kind: SpecialKind::DevShm,
            ..location(25)
        };
        // 15% free of 64 GiB, quiet: below the 20% RAM floor -> critical.
        let full = rule.assess(&shm, &stats(64 * GIB, 10 * GIB), 0.0, true);
        assert_eq!(full.alert, SpecialAlert::Critical, "{}", full.reason);
        assert!(
            full.urgency >= 0.2,
            "room-only alerts keep a minimum urgency"
        );
        // 50% free but filling at 1 GiB/s: 32 s to harm -> critical.
        let fast = rule.assess(&shm, &stats(64 * GIB, 32 * GIB), 1024.0 * 1_048_576.0, true);
        assert_eq!(fast.alert, SpecialAlert::Critical, "{}", fast.reason);
        assert!(fast.urgency > 0.95);
        // 50% free and quiet -> nothing.
        let quiet = rule.assess(&shm, &stats(64 * GIB, 32 * GIB), 0.0, true);
        assert_eq!(quiet.alert, SpecialAlert::None, "{}", quiet.reason);

        // Small RAM-backed location (e.g. 256 MiB /dev/shm with 254 MiB free, quiet)
        // must NOT alert critical or filling_fast.
        let small_quiet = rule.assess(
            &shm,
            &stats(256 * 1024 * 1024, 254 * 1024 * 1024),
            0.0,
            true,
        );
        assert_eq!(
            small_quiet.alert,
            SpecialAlert::None,
            "{}",
            small_quiet.reason
        );
        assert_eq!(small_quiet.urgency, 0.0);
    }

    #[test]
    fn throttle_reports_changes_at_once_and_repeats_once_per_interval() {
        let mut throttle = AlertThrottle::default();
        let path = Path::new("/data/tmp");
        let now = Instant::now();
        let interval = Duration::from_mins(15);
        assert!(!throttle.should_emit(path, SpecialAlert::None, now, interval));
        assert!(throttle.should_emit(path, SpecialAlert::Warning, now, interval));
        assert!(!throttle.should_emit(
            path,
            SpecialAlert::Warning,
            now + Duration::from_mins(5),
            interval
        ));
        assert!(throttle.should_emit(
            path,
            SpecialAlert::Critical,
            now + Duration::from_mins(6),
            interval
        ));
        assert!(throttle.should_emit(
            path,
            SpecialAlert::Critical,
            now + Duration::from_mins(21),
            interval
        ));
        // Recovery is reported once, then stays quiet.
        assert!(throttle.should_emit(
            path,
            SpecialAlert::None,
            now + Duration::from_mins(22),
            interval
        ));
        assert!(!throttle.should_emit(
            path,
            SpecialAlert::None,
            now + Duration::from_mins(40),
            interval
        ));
        // Ten minutes of the same reading: zero alerts.
        let mut quiet = AlertThrottle::default();
        for minute in 0..10 {
            assert!(!quiet.should_emit(
                path,
                SpecialAlert::None,
                now + Duration::from_mins(minute),
                interval
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SpecialKind, SpecialLocationRegistry};
    use crate::core::errors::{Result, SbhError};
    use crate::platform::pal::{
        FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
    };
    use std::path::{Path, PathBuf};

    #[derive(Default)]
    struct TestServiceManager;
    impl ServiceManager for TestServiceManager {
        fn install(&self) -> Result<()> {
            Ok(())
        }
        fn uninstall(&self) -> Result<()> {
            Ok(())
        }
        fn status(&self) -> Result<String> {
            Ok("ok".to_string())
        }
    }

    struct TestPlatform {
        mounts: Vec<MountPoint>,
    }

    impl Platform for TestPlatform {
        fn fs_stats(&self, _path: &Path) -> Result<FsStats> {
            Err(SbhError::Runtime {
                details: "not used in this test".to_string(),
            })
        }
        fn mount_points(&self) -> Result<Vec<MountPoint>> {
            Ok(self.mounts.clone())
        }
        fn is_ram_backed(&self, _path: &Path) -> Result<bool> {
            Ok(false)
        }
        fn default_paths(&self) -> PlatformPaths {
            PlatformPaths::default()
        }
        fn memory_info(&self) -> Result<MemoryInfo> {
            Ok(MemoryInfo {
                total_bytes: 1,
                available_bytes: 1,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            })
        }
        fn service_manager(&self) -> Box<dyn ServiceManager> {
            Box::<TestServiceManager>::default()
        }
    }

    #[test]
    fn discover_includes_tmpfs_and_custom_locations() {
        let platform = TestPlatform {
            mounts: vec![MountPoint {
                path: PathBuf::from("/dev/shm"),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            }],
        };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[PathBuf::from("/data/tmp/custom")])
                .expect("discovery should succeed");
        assert!(
            registry
                .all()
                .iter()
                .any(|location| location.path == Path::new("/dev/shm"))
        );
        assert!(
            registry
                .all()
                .iter()
                .any(|location| matches!(location.kind, SpecialKind::Custom(_)))
        );
        assert!(
            registry
                .all()
                .iter()
                .any(|location| location.path == Path::new("/tmp"))
        );
    }

    #[test]
    fn needs_attention_when_below_buffer() {
        use super::{FsStats, SpecialKind, SpecialLocation};
        use std::time::Duration;

        let loc = SpecialLocation {
            path: PathBuf::from("/tmp"),
            kind: SpecialKind::Tmpfs,
            buffer_pct: 15,
            scan_interval: Duration::from_secs(5),
            priority: 200,
        };
        let stats_low = FsStats {
            total_bytes: 1000,
            free_bytes: 100, // 10% free — below buffer_pct 15
            available_bytes: 100,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        assert!(loc.needs_attention(&stats_low));

        let stats_ok = FsStats {
            total_bytes: 1000,
            free_bytes: 200, // 20% free — above buffer_pct 15
            available_bytes: 200,
            fs_type: "tmpfs".to_string(),
            mount_point: PathBuf::from("/tmp"),
            is_readonly: false,
        };
        assert!(!loc.needs_attention(&stats_ok));
    }

    #[test]
    fn scan_due_when_never_scanned() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::{Duration, Instant};

        let loc = SpecialLocation {
            path: PathBuf::from("/tmp"),
            kind: SpecialKind::Tmpfs,
            buffer_pct: 15,
            scan_interval: Duration::from_mins(1),
            priority: 200,
        };
        assert!(loc.scan_due(None, Instant::now()));
    }

    #[test]
    fn scan_not_due_when_recently_scanned() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::{Duration, Instant};

        let loc = SpecialLocation {
            path: PathBuf::from("/tmp"),
            kind: SpecialKind::Tmpfs,
            buffer_pct: 15,
            scan_interval: Duration::from_mins(1),
            priority: 200,
        };
        let now = Instant::now();
        assert!(!loc.scan_due(Some(now), now));
    }

    #[test]
    fn registry_deduplicates_paths() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::Duration;

        let locations = vec![
            SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::Tmpfs,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 200,
            },
            SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::UserTmp,
                buffer_pct: 10,
                scan_interval: Duration::from_secs(5),
                priority: 160,
            },
        ];
        let registry = SpecialLocationRegistry::new(locations);
        assert_eq!(registry.all().len(), 1);
        assert!(matches!(registry.all()[0].kind, SpecialKind::UserTmp));
    }

    #[test]
    fn registry_sorts_by_priority_descending() {
        use super::{SpecialKind, SpecialLocation};
        use std::time::Duration;

        let locations = vec![
            SpecialLocation {
                path: PathBuf::from("/data/tmp"),
                kind: SpecialKind::Custom("custom".to_string()),
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 100,
            },
            SpecialLocation {
                path: PathBuf::from("/dev/shm"),
                kind: SpecialKind::DevShm,
                buffer_pct: 20,
                scan_interval: Duration::from_secs(3),
                priority: 255,
            },
            SpecialLocation {
                path: PathBuf::from("/tmp"),
                kind: SpecialKind::Tmpfs,
                buffer_pct: 15,
                scan_interval: Duration::from_secs(5),
                priority: 200,
            },
        ];
        let registry = SpecialLocationRegistry::new(locations);
        let all = registry.all();
        assert_eq!(all[0].priority, 255);
        assert_eq!(all[1].priority, 200);
        assert_eq!(all[2].priority, 100);
    }

    #[test]
    fn discover_adds_tmp_fallback_when_no_tmpfs_mount() {
        let platform = TestPlatform { mounts: vec![] };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[]).expect("discovery should succeed");
        assert!(
            registry
                .all()
                .iter()
                .any(|loc| loc.path == Path::new("/tmp")),
            "/tmp should be added as fallback"
        );
    }

    #[test]
    fn discover_adds_data_tmp_fallback() {
        let platform = TestPlatform { mounts: vec![] };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[]).expect("discovery should succeed");
        assert!(
            registry
                .all()
                .iter()
                .any(|loc| loc.path == Path::new("/data/tmp")),
            "/data/tmp should be added as fallback"
        );
    }

    #[test]
    fn discover_skips_non_reclaimable_devfs_mount() {
        let platform = TestPlatform {
            mounts: vec![MountPoint {
                path: PathBuf::from("/dev"),
                device: "devfs".to_string(),
                fs_type: "devfs".to_string(),
                is_ram_backed: true,
            }],
        };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[]).expect("discovery should succeed");

        assert!(
            registry
                .all()
                .iter()
                .all(|location| location.path != Path::new("/dev")),
            "/dev device filesystem must not be treated as reclaimable scratch space"
        );
    }

    #[test]
    fn discover_keeps_dev_shm_special_mount() {
        let platform = TestPlatform {
            mounts: vec![MountPoint {
                path: PathBuf::from("/dev/shm"),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            }],
        };
        let registry =
            SpecialLocationRegistry::discover(&platform, &[]).expect("discovery should succeed");

        let dev_shm = registry
            .all()
            .iter()
            .find(|location| location.path == Path::new("/dev/shm"))
            .expect("/dev/shm should stay registered");
        assert!(matches!(dev_shm.kind, SpecialKind::DevShm));
    }

    #[test]
    fn discover_custom_path_overrides_mount_defaults() {
        let platform = TestPlatform {
            mounts: vec![MountPoint {
                path: PathBuf::from("/tmp"),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            }],
        };
        let registry = SpecialLocationRegistry::discover(&platform, &[PathBuf::from("/tmp")])
            .expect("discovery should succeed");

        let tmp = registry
            .all()
            .iter()
            .find(|location| location.path == Path::new("/tmp"))
            .expect("/tmp entry should exist");
        assert!(matches!(tmp.kind, SpecialKind::Custom(_)));
        assert_eq!(tmp.priority, 140);
    }
}
