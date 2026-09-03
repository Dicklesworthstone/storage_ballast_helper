//! Write-burst statistics per mount and the emergency reserve they imply
//! (bd-rc-master-ajg1.2.18).
//!
//! The reserve on a mount has one job: absorb what lands on the mount between
//! the moment pressure is observed and the moment the first reclaim
//! completes, the *reaction window*. Every window's peak used-bytes growth is
//! one sample. The reserve target is the 0.99 quantile of those samples: read
//! from a t-digest once enough windows exist, extrapolated from a generalized
//! Pareto fit to the tail before that, and never below two ballast files.
//!
//! The samples come from the mount's own `statfs` readings, not from
//! per-process I/O counters: used-bytes growth is exactly what the reserve
//! must cover, it is free (the daemon already polls it), and it sees every
//! writer, including ones without `/proc` I/O accounting. The reaction window
//! is a daemon-wide EWMA of the observed cycle latency (poll interval plus
//! scan duration plus scan-to-reclaim latency), with a five-minute prior.

#![allow(missing_docs)]

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// File beside `state.json` that carries the digests across restarts.
pub const SNAPSHOT_FILE_NAME: &str = "burst_stats.bin";
const SNAPSHOT_VERSION: u32 = 1;
/// t-digest compression: the centroid budget is about this many.
pub const DIGEST_COMPRESSION: usize = 100;
/// Unmerged samples buffered before a compaction.
const DIGEST_BUFFER: usize = 256;
/// Reaction window before any cycle has been observed.
pub const REACTION_WINDOW_PRIOR: Duration = Duration::from_mins(5);
const REACTION_WINDOW_ALPHA: f64 = 0.2;
const REACTION_WINDOW_MIN: Duration = Duration::from_secs(5);
const REACTION_WINDOW_MAX: Duration = Duration::from_mins(30);
/// Windows before the digest quantile is trusted on its own.
pub const QUANTILE_WINDOWS: u64 = 50;
/// Windows before the Pareto tail is fitted; below this only the floor.
pub const TAIL_WINDOWS: u64 = 10;
/// Raw window sums kept for the tail fit.
const RAW_WINDOWS_KEPT: usize = 256;
/// The reserve covers this share of reaction windows.
pub const RESERVE_QUANTILE: f64 = 0.99;
/// Exceedances above this empirical quantile feed the tail fit.
pub const TAIL_THRESHOLD_QUANTILE: f64 = 0.90;
/// The reserve is never smaller than this many ballast files.
pub const FLOOR_FILES: u64 = 2;
const PERSIST_INTERVAL: Duration = Duration::from_mins(5);

// ──────────────────── t-digest ────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Centroid {
    pub mean: f64,
    pub weight: f64,
}

/// A merging t-digest (Dunning & Ertl) with the `k1` scale function.
///
/// Exact for a few hundred samples, bounded at about `compression` centroids
/// afterwards, with the best resolution at the tails, which is where the
/// reserve quantile lives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TDigest {
    compression: usize,
    centroids: Vec<Centroid>,
    buffer: Vec<f64>,
    count: f64,
    min: f64,
    max: f64,
}

impl Default for TDigest {
    fn default() -> Self {
        Self::new(DIGEST_COMPRESSION)
    }
}

impl TDigest {
    #[must_use]
    pub fn new(compression: usize) -> Self {
        Self {
            compression: compression.max(10),
            centroids: Vec::new(),
            buffer: Vec::new(),
            count: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    pub fn add(&mut self, value: f64) {
        if !value.is_finite() {
            return;
        }
        self.buffer.push(value);
        self.count += 1.0;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        if self.buffer.len() >= DIGEST_BUFFER {
            self.compress();
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn count(&self) -> u64 {
        self.count.max(0.0) as u64
    }

    #[must_use]
    pub fn centroid_count(&self) -> usize {
        self.centroids.len() + self.buffer.len()
    }

    #[allow(clippy::cast_precision_loss)]
    fn scale(&self, q: f64) -> f64 {
        let compression = self.compression as f64;
        compression * 2.0f64.mul_add(q, -1.0).clamp(-1.0, 1.0).asin() / (2.0 * std::f64::consts::PI)
    }

    /// Merge the buffer into the centroids under the size bound.
    pub fn compress(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let mut all: Vec<Centroid> = std::mem::take(&mut self.centroids);
        all.extend(
            self.buffer
                .drain(..)
                .map(|mean| Centroid { mean, weight: 1.0 }),
        );
        all.sort_by(|a, b| a.mean.total_cmp(&b.mean));
        let total: f64 = all.iter().map(|c| c.weight).sum();
        if total <= 0.0 {
            return;
        }
        let mut merged: Vec<Centroid> = Vec::with_capacity(self.compression * 2);
        let mut weight_before = 0.0;
        let mut current = all[0];
        let mut k_low = self.scale(0.0);
        for next in all.into_iter().skip(1) {
            let q_after = (weight_before + current.weight + next.weight) / total;
            if self.scale(q_after) - k_low <= 1.0 {
                let weight = current.weight + next.weight;
                current.mean = next
                    .mean
                    .mul_add(next.weight, current.mean * current.weight)
                    / weight;
                current.weight = weight;
            } else {
                merged.push(current);
                weight_before += current.weight;
                k_low = self.scale(weight_before / total);
                current = next;
            }
        }
        merged.push(current);
        self.centroids = merged;
    }

    /// The `q` quantile by interpolation between centroid centers, clamped to
    /// the observed range; `None` before any sample.
    #[must_use]
    pub fn quantile(&self, q: f64) -> Option<f64> {
        if self.count <= 0.0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        let mut all: Vec<Centroid> = self.centroids.clone();
        all.extend(
            self.buffer
                .iter()
                .map(|&mean| Centroid { mean, weight: 1.0 }),
        );
        all.sort_by(|a, b| a.mean.total_cmp(&b.mean));
        let total: f64 = all.iter().map(|c| c.weight).sum();
        let target = q * total;

        let mut cumulative = 0.0;
        let mut previous: Option<(f64, f64)> = None; // (center, mean)
        for centroid in &all {
            let center = cumulative + centroid.weight / 2.0;
            if target <= center {
                let value = match previous {
                    None => {
                        // Below the first center: between the minimum and
                        // the first mean.
                        if center <= 0.0 {
                            centroid.mean
                        } else {
                            let t = (target / center).clamp(0.0, 1.0);
                            (centroid.mean - self.min).mul_add(t, self.min)
                        }
                    }
                    Some((prev_center, prev_mean)) => {
                        let span = center - prev_center;
                        let t = if span <= 0.0 {
                            1.0
                        } else {
                            ((target - prev_center) / span).clamp(0.0, 1.0)
                        };
                        (centroid.mean - prev_mean).mul_add(t, prev_mean)
                    }
                };
                return Some(value.clamp(self.min, self.max));
            }
            cumulative += centroid.weight;
            previous = Some((center, centroid.mean));
        }
        // Above the last center: between the last mean and the maximum.
        let (last_center, last_mean) = previous?;
        let span = total - last_center;
        let t = if span <= 0.0 {
            1.0
        } else {
            ((target - last_center) / span).clamp(0.0, 1.0)
        };
        Some(
            (self.max - last_mean)
                .mul_add(t, last_mean)
                .clamp(self.min, self.max),
        )
    }

    #[must_use]
    pub fn min(&self) -> Option<f64> {
        (self.count > 0.0).then_some(self.min)
    }

    #[must_use]
    pub fn max(&self) -> Option<f64> {
        (self.count > 0.0).then_some(self.max)
    }
}

// ──────────────────── generalized Pareto tail ────────────────────

/// A generalized Pareto fit to the exceedances above a threshold.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TailFit {
    pub threshold: f64,
    /// Share of samples above the threshold.
    pub exceed_fraction: f64,
    pub shape: f64,
    pub scale: f64,
    pub exceedances: usize,
}

/// Probability-weighted-moment fit (Hosking & Wallis 1987) of the GPD shape
/// and scale to positive exceedances.
///
/// Uses `a0 = E[Y]` and `a1 = E[Y (1 - F(Y))]`, estimated from the order
/// statistics; the exponential (`shape = 0`, `scale = mean`) when the
/// moments do not identify a shape. `None` without data.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn fit_gpd_pwm(exceedances: &[f64]) -> Option<(f64, f64)> {
    let mut sorted: Vec<f64> = exceedances
        .iter()
        .copied()
        .filter(|y| y.is_finite() && *y > 0.0)
        .collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let b0 = sorted.iter().sum::<f64>() / n as f64;
    if n < 4 {
        return Some((0.0, b0));
    }
    // a1 weights the i-th smallest by its estimated survival (n - 1 - i) / (n - 1).
    let b1 = sorted
        .iter()
        .enumerate()
        .map(|(i, y)| ((n - 1 - i) as f64 / (n as f64 - 1.0)) * y)
        .sum::<f64>()
        / n as f64;
    let denominator = 2.0f64.mul_add(-b1, b0);
    if denominator.abs() < 1e-9 * b0.max(1.0) {
        return Some((0.0, b0));
    }
    let shape = (2.0 - b0 / denominator).clamp(-0.5, 0.95);
    let scale = (2.0 * b0 * b1 / denominator).abs().max(f64::MIN_POSITIVE);
    Some((shape, scale))
}

impl TailFit {
    /// Fit the tail above the empirical `threshold_quantile` of `samples`.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn fit(samples: &[f64], threshold_quantile: f64) -> Option<Self> {
        let mut sorted: Vec<f64> = samples.iter().copied().filter(|x| x.is_finite()).collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_by(f64::total_cmp);
        let n = sorted.len();
        let index = ((n as f64) * threshold_quantile.clamp(0.0, 1.0))
            .ceil()
            .max(1.0) as usize;
        let threshold = sorted[index.min(n) - 1];
        let exceedances: Vec<f64> = sorted
            .iter()
            .filter(|x| **x > threshold)
            .map(|x| x - threshold)
            .collect();
        let exceed_fraction = exceedances.len() as f64 / n as f64;
        let (shape, scale) = fit_gpd_pwm(&exceedances).unwrap_or((0.0, 0.0));
        Some(Self {
            threshold,
            exceed_fraction,
            shape,
            scale,
            exceedances: exceedances.len(),
        })
    }

    /// The `q` quantile under the fitted tail, never below the threshold.
    #[must_use]
    pub fn quantile(&self, q: f64) -> f64 {
        let q = q.clamp(0.0, 1.0 - f64::EPSILON);
        if self.exceedances == 0 || self.scale <= 0.0 || self.exceed_fraction <= 0.0 {
            return self.threshold;
        }
        let ratio = self.exceed_fraction / (1.0 - q);
        if ratio <= 1.0 {
            // The requested quantile sits below the threshold.
            return self.threshold;
        }
        let excess = if self.shape.abs() < 1e-6 {
            self.scale * ratio.ln()
        } else {
            self.scale / self.shape * (ratio.powf(self.shape) - 1.0)
        };
        if excess.is_finite() && excess > 0.0 {
            self.threshold + excess
        } else {
            self.threshold
        }
    }
}

// ──────────────────── reaction window ────────────────────

/// EWMA of the observed cycle latency: poll interval plus scan duration plus
/// the scan-to-reclaim latency, clamped to `[5 s, 30 min]`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReactionWindow {
    ewma_secs: f64,
    observations: u32,
}

impl Default for ReactionWindow {
    fn default() -> Self {
        Self {
            ewma_secs: REACTION_WINDOW_PRIOR.as_secs_f64(),
            observations: 0,
        }
    }
}

impl ReactionWindow {
    pub fn record(&mut self, cycle: Duration) {
        let secs = cycle
            .clamp(REACTION_WINDOW_MIN, REACTION_WINDOW_MAX)
            .as_secs_f64();
        if self.observations == 0 {
            self.ewma_secs = secs;
        } else {
            self.ewma_secs = REACTION_WINDOW_ALPHA.mul_add(secs - self.ewma_secs, self.ewma_secs);
        }
        self.observations = self.observations.saturating_add(1);
    }

    #[must_use]
    pub fn secs(&self) -> f64 {
        self.ewma_secs
    }

    #[must_use]
    pub fn observations(&self) -> u32 {
        self.observations
    }
}

// ──────────────────── per-mount tracker ────────────────────

/// How the reserve target was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveMethod {
    /// Fewer than [`TAIL_WINDOWS`] windows: the floor only.
    Floor,
    /// Generalized Pareto tail extrapolated from the exceedances.
    Tail,
    /// The digest's own quantile.
    Quantile,
}

impl ReserveMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Floor => "floor",
            Self::Tail => "tail",
            Self::Quantile => "quantile",
        }
    }
}

/// The reserve a mount needs, and where the number came from.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReserveEstimate {
    /// Bytes the reserve should hold.
    pub bytes: u64,
    pub method: ReserveMethod,
    pub windows: u64,
    pub window_secs: f64,
    /// The 0.99 burst quantile before the floor.
    pub burst_q99_bytes: u64,
    pub floor_bytes: u64,
}

impl ReserveEstimate {
    /// Whole ballast files needed for `bytes`.
    #[must_use]
    pub fn file_count(&self, file_size_bytes: u64) -> u64 {
        if file_size_bytes == 0 {
            return 0;
        }
        self.bytes.div_ceil(file_size_bytes)
    }

    /// Bytes per second of the 0.99 burst spread over its window.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn burst_bytes_per_sec(&self) -> Option<f64> {
        (self.burst_q99_bytes > 0 && self.window_secs > 0.0)
            .then(|| self.burst_q99_bytes as f64 / self.window_secs)
    }

    /// Minutes `present_bytes` buys at the burst rate.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn horizon_minutes(&self, present_bytes: u64) -> Option<f64> {
        let rate = self.burst_bytes_per_sec()?;
        Some(present_bytes as f64 / rate / 60.0)
    }
}

/// One mount's window samples.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountBurstTracker {
    digest: TDigest,
    raw: VecDeque<f64>,
    windows: u64,
    #[serde(skip)]
    window: Option<OpenWindow>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct OpenWindow {
    started: Instant,
    used_at_start: u64,
    peak_used: u64,
}

impl Default for MountBurstTracker {
    fn default() -> Self {
        Self {
            digest: TDigest::default(),
            raw: VecDeque::with_capacity(RAW_WINDOWS_KEPT),
            windows: 0,
            window: None,
        }
    }
}

impl MountBurstTracker {
    /// Feed one `statfs` reading. A window closes after `window_secs`; its
    /// sample is the peak used-bytes growth inside it, so a burst that is
    /// reclaimed before the window ends still counts.
    pub fn observe(&mut self, now: Instant, used_bytes: u64, window_secs: f64) {
        let Some(open) = self.window.as_mut() else {
            self.window = Some(OpenWindow {
                started: now,
                used_at_start: used_bytes,
                peak_used: used_bytes,
            });
            return;
        };
        open.peak_used = open.peak_used.max(used_bytes);
        if now.duration_since(open.started).as_secs_f64() < window_secs.max(1.0) {
            return;
        }
        #[allow(clippy::cast_precision_loss)]
        let growth = open.peak_used.saturating_sub(open.used_at_start) as f64;
        self.push_sample(growth);
        self.window = Some(OpenWindow {
            started: now,
            used_at_start: used_bytes,
            peak_used: used_bytes,
        });
    }

    /// Record a closed window's growth directly (tests and replays).
    pub fn push_sample(&mut self, growth_bytes: f64) {
        if !growth_bytes.is_finite() || growth_bytes < 0.0 {
            return;
        }
        self.digest.add(growth_bytes);
        if self.raw.len() >= RAW_WINDOWS_KEPT {
            self.raw.pop_front();
        }
        self.raw.push_back(growth_bytes);
        self.windows = self.windows.saturating_add(1);
    }

    #[must_use]
    pub fn windows(&self) -> u64 {
        self.windows
    }

    /// The reserve this mount needs for ballast files of `file_size_bytes`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn estimate(&self, file_size_bytes: u64, window_secs: f64) -> ReserveEstimate {
        let floor_bytes = file_size_bytes.saturating_mul(FLOOR_FILES);
        let (q99, method) = if self.windows >= QUANTILE_WINDOWS {
            // Finite-sample correction, `(n + 1) / n`, as in the conformal
            // calibrator: with 60 windows the 0.99 quantile is the largest
            // burst seen, not an interpolation just below it.
            #[allow(clippy::cast_precision_loss)]
            let n = self.windows as f64;
            let q = (RESERVE_QUANTILE * (n + 1.0) / n).min(1.0);
            (
                self.digest.quantile(q).unwrap_or(0.0),
                ReserveMethod::Quantile,
            )
        } else if self.windows >= TAIL_WINDOWS {
            let raw: Vec<f64> = self.raw.iter().copied().collect();
            let tail = TailFit::fit(&raw, TAIL_THRESHOLD_QUANTILE)
                .map_or(0.0, |fit| fit.quantile(RESERVE_QUANTILE));
            (tail, ReserveMethod::Tail)
        } else {
            (0.0, ReserveMethod::Floor)
        };
        let burst_q99_bytes = q99.max(0.0).ceil() as u64;
        ReserveEstimate {
            bytes: burst_q99_bytes.max(floor_bytes),
            method,
            windows: self.windows,
            window_secs,
            burst_q99_bytes,
            floor_bytes,
        }
    }
}

// ──────────────────── all mounts, persisted ────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BurstSnapshot {
    version: u32,
    reaction: ReactionWindow,
    mounts: Vec<(PathBuf, MountBurstTracker)>,
}

/// Burst statistics for every mount the daemon watches, persisted beside
/// `state.json` so a restart does not forget a week of windows.
#[derive(Debug)]
pub struct BurstStats {
    snapshot_path: PathBuf,
    reaction: ReactionWindow,
    mounts: BTreeMap<PathBuf, MountBurstTracker>,
    last_persist: Option<Instant>,
    dirty: bool,
}

impl BurstStats {
    #[must_use]
    pub fn new(snapshot_path: PathBuf) -> Self {
        Self {
            snapshot_path,
            reaction: ReactionWindow::default(),
            mounts: BTreeMap::new(),
            last_persist: None,
            dirty: false,
        }
    }

    #[must_use]
    pub fn snapshot_path_for_state_file(state_file: &Path) -> PathBuf {
        state_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(SNAPSHOT_FILE_NAME)
    }

    /// Load the snapshot beside `state.json`, or start empty when it is
    /// missing, unreadable, or from another version.
    #[must_use]
    pub fn load_or_new(snapshot_path: PathBuf) -> Self {
        let mut stats = Self::new(snapshot_path);
        if let Ok(raw) = fs::read(&stats.snapshot_path)
            && let Ok((snapshot, _)) = bincode::serde::decode_from_slice::<BurstSnapshot, _>(
                &raw,
                bincode::config::standard(),
            )
            && snapshot.version == SNAPSHOT_VERSION
        {
            stats.reaction = snapshot.reaction;
            stats.mounts = snapshot.mounts.into_iter().collect();
        }
        stats
    }

    #[must_use]
    pub fn reaction_window(&self) -> ReactionWindow {
        self.reaction
    }

    pub fn record_cycle(&mut self, cycle: Duration) {
        self.reaction.record(cycle);
        self.dirty = true;
    }

    /// Feed one mount's reading; persists every five minutes while windows
    /// keep closing.
    pub fn observe(&mut self, mount: &Path, now: Instant, used_bytes: u64) {
        let window_secs = self.reaction.secs();
        let tracker = self.mounts.entry(mount.to_path_buf()).or_default();
        let windows_before = tracker.windows;
        tracker.observe(now, used_bytes, window_secs);
        if tracker.windows != windows_before {
            self.dirty = true;
        }
        if self.dirty
            && self
                .last_persist
                .is_none_or(|last| now.duration_since(last) >= PERSIST_INTERVAL)
        {
            self.persist();
            self.last_persist = Some(now);
        }
    }

    #[must_use]
    pub fn mount(&self, mount: &Path) -> Option<&MountBurstTracker> {
        self.mounts.get(mount)
    }

    pub fn mount_mut(&mut self, mount: &Path) -> &mut MountBurstTracker {
        self.dirty = true;
        self.mounts.entry(mount.to_path_buf()).or_default()
    }

    /// The reserve estimate for `mount`, or `None` when the mount has never
    /// been observed.
    #[must_use]
    pub fn estimate(&self, mount: &Path, file_size_bytes: u64) -> Option<ReserveEstimate> {
        self.mounts
            .get(mount)
            .map(|tracker| tracker.estimate(file_size_bytes, self.reaction.secs()))
    }

    pub fn mounts(&self) -> impl Iterator<Item = (&Path, &MountBurstTracker)> {
        self.mounts
            .iter()
            .map(|(mount, tracker)| (mount.as_path(), tracker))
    }

    /// Write the snapshot atomically; failures are silent because the file
    /// is a cache of what the next windows will rebuild.
    pub fn persist(&mut self) {
        let snapshot = BurstSnapshot {
            version: SNAPSHOT_VERSION,
            reaction: self.reaction,
            mounts: self
                .mounts
                .iter()
                .map(|(mount, tracker)| (mount.clone(), tracker.clone()))
                .collect(),
        };
        let Ok(encoded) = bincode::serde::encode_to_vec(&snapshot, bincode::config::standard())
        else {
            return;
        };
        let temp = self.snapshot_path.with_extension("bin.tmp");
        if fs::write(&temp, encoded).is_ok() && fs::rename(&temp, &self.snapshot_path).is_ok() {
            self.dirty = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(values: &[f64]) -> TDigest {
        let mut digest = TDigest::default();
        for &value in values {
            digest.add(value);
        }
        digest
    }

    #[test]
    fn digest_is_exact_on_small_inputs_and_bounded_on_large_ones() {
        let digest = digest_of(&[5.0, 1.0, 3.0, 2.0, 4.0]);
        assert_eq!(digest.count(), 5);
        assert_eq!(digest.min(), Some(1.0));
        assert_eq!(digest.max(), Some(5.0));
        let median = digest.quantile(0.5).unwrap();
        assert!((median - 3.0).abs() < 1e-9, "{median}");
        assert_eq!(digest.quantile(0.0), Some(1.0));
        assert_eq!(digest.quantile(1.0), Some(5.0));

        let mut large = TDigest::default();
        for i in 0..100_000u32 {
            large.add(f64::from(i));
        }
        large.compress();
        assert!(
            large.centroid_count() <= 2 * DIGEST_COMPRESSION,
            "{} centroids",
            large.centroid_count()
        );
        let q99 = large.quantile(0.99).unwrap();
        assert!((q99 - 99_000.0).abs() < 500.0, "{q99}");
        let q50 = large.quantile(0.5).unwrap();
        assert!((q50 - 50_000.0).abs() < 2_000.0, "{q50}");
        assert!(TDigest::default().quantile(0.5).is_none());
    }

    #[test]
    fn digest_survives_serde() {
        let mut digest = digest_of(&(0..1000).map(f64::from).collect::<Vec<_>>());
        digest.compress();
        let json = serde_json::to_string(&digest).unwrap();
        let back: TDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count(), 1000);
        assert_eq!(back.quantile(0.99), digest.quantile(0.99));
    }

    #[test]
    fn pwm_fit_recovers_an_exponential_tail() {
        // Exponential(mean 100) quantiles as a deterministic sample.
        let sample: Vec<f64> = (1..=400)
            .map(|i| -100.0 * (1.0 - f64::from(i) / 401.0).ln())
            .collect();
        let (shape, scale) = fit_gpd_pwm(&sample).unwrap();
        assert!(shape.abs() < 0.08, "shape {shape}");
        assert!((scale - 100.0).abs() < 10.0, "scale {scale}");

        let fit = TailFit::fit(&sample, 0.9).unwrap();
        assert!(fit.threshold > 0.0);
        let q99 = fit.quantile(0.99);
        // True q99 of Exponential(100) is 460.5.
        assert!((q99 - 460.5).abs() < 60.0, "{q99}");
        assert!(q99 >= fit.threshold);
        assert!(fit_gpd_pwm(&[]).is_none());
    }

    #[test]
    fn reaction_window_starts_at_the_prior_and_clamps() {
        let mut window = ReactionWindow::default();
        assert!((window.secs() - 300.0).abs() < 1e-9);
        window.record(Duration::from_secs(1));
        assert!((window.secs() - 5.0).abs() < 1e-9, "{}", window.secs());
        window.record(Duration::from_hours(3));
        assert!(window.secs() <= 1800.0);
        assert_eq!(window.observations(), 2);
    }

    #[test]
    fn windows_close_on_the_reaction_window_and_take_the_peak() {
        let mut tracker = MountBurstTracker::default();
        let t0 = Instant::now();
        tracker.observe(t0, 1_000, 60.0);
        tracker.observe(t0 + Duration::from_secs(10), 5_000, 60.0);
        // Reclaimed inside the window: the peak still counts.
        tracker.observe(t0 + Duration::from_secs(20), 1_000, 60.0);
        assert_eq!(tracker.windows(), 0);
        tracker.observe(t0 + Duration::from_secs(61), 1_500, 60.0);
        assert_eq!(tracker.windows(), 1);
        assert_eq!(tracker.raw.back().copied(), Some(4_000.0));
        // A shrinking mount contributes a zero, never a negative.
        tracker.observe(t0 + Duration::from_secs(130), 200, 60.0);
        assert_eq!(tracker.raw.back().copied(), Some(0.0));

        let estimate = tracker.estimate(4096, 60.0);
        assert_eq!(estimate.method, ReserveMethod::Floor);
        assert_eq!(estimate.bytes, 8192);
        assert_eq!(estimate.file_count(4096), 2);
        assert_eq!(estimate.horizon_minutes(8192), None);
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn estimate_uses_the_tail_then_the_quantile() {
        let mut tracker = MountBurstTracker::default();
        for i in 0..TAIL_WINDOWS {
            #[allow(clippy::cast_precision_loss)]
            tracker.push_sample(1_000.0 * (i + 1) as f64);
        }
        let tail = tracker.estimate(100, 300.0);
        assert_eq!(tail.method, ReserveMethod::Tail);
        // Never below the empirical 0.9 quantile of the samples (9_000).
        assert!(tail.burst_q99_bytes >= 9_000, "{tail:?}");
        assert!(tail.bytes >= tail.floor_bytes);

        for _ in TAIL_WINDOWS..QUANTILE_WINDOWS {
            tracker.push_sample(500.0);
        }
        let quantile = tracker.estimate(100, 300.0);
        assert_eq!(quantile.method, ReserveMethod::Quantile);
        assert!(quantile.burst_q99_bytes >= 9_000, "{quantile:?}");
        assert!(quantile.burst_q99_bytes <= 10_000, "{quantile:?}");
        let rate = quantile.burst_bytes_per_sec().unwrap();
        assert!((rate - quantile.burst_q99_bytes as f64 / 300.0).abs() < 1e-9);
    }

    /// A writer that lands 1 GiB in 30 s every 10 min (and is reclaimed in
    /// between) must yield a reserve of at least 1 GiB.
    #[test]
    fn bursty_writer_yields_a_reserve_of_at_least_one_gib() {
        let gib = 1u64 << 30;
        let mut stats = BurstStats::new(PathBuf::from("/nonexistent/burst.bin"));
        let mount = Path::new("/data");
        let t0 = Instant::now();
        let base = 100 * gib;
        // 24 hours at 15 s: cycle of 600 s, the burst fills over 0..30 s
        // and is reclaimed at 300 s.
        for step in 0..(24 * 3600 / 15) {
            let secs = step * 15;
            let phase = secs % 600;
            let used = if phase < 30 {
                base + gib * phase / 30
            } else if phase < 300 {
                base + gib
            } else {
                base
            };
            stats.observe(mount, t0 + Duration::from_secs(secs), used);
        }
        let estimate = stats.estimate(mount, 64 << 20).unwrap();
        assert!(estimate.windows >= QUANTILE_WINDOWS, "{estimate:?}");
        assert_eq!(estimate.method, ReserveMethod::Quantile);
        assert!(estimate.bytes >= gib, "{estimate:?}");
        assert_eq!(estimate.file_count(64 << 20), 16);
        let horizon = estimate.horizon_minutes(gib).unwrap();
        assert!((horizon - 5.0).abs() < 0.5, "{horizon}");
    }

    #[test]
    fn snapshot_round_trips_and_ignores_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SNAPSHOT_FILE_NAME);
        let mut stats = BurstStats::new(path.clone());
        stats.record_cycle(Duration::from_secs(120));
        let mount = Path::new("/data");
        for i in 0..20 {
            stats.mount_mut(mount).push_sample(f64::from(i) * 1e6);
        }
        stats.persist();
        assert!(path.exists());

        let loaded = BurstStats::load_or_new(path.clone());
        assert_eq!(loaded.reaction_window().observations(), 1);
        assert_eq!(
            loaded.mount(mount).map(MountBurstTracker::windows),
            Some(20)
        );
        assert_eq!(
            loaded.estimate(mount, 4096).map(|e| e.burst_q99_bytes),
            stats.estimate(mount, 4096).map(|e| e.burst_q99_bytes)
        );

        fs::write(&path, b"not a snapshot").unwrap();
        let fresh = BurstStats::load_or_new(path);
        assert!(fresh.mount(mount).is_none());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(200))]

        /// Quantiles are monotone in `q`, bounded by the sample range, and
        /// with enough samples the median stays within 10% of the range of
        /// the exact one (the digest interpolates, so tiny samples differ).
        #[test]
        fn digest_quantiles_are_monotone_and_bounded(
            values in proptest::collection::vec(0.0f64..1e12, 1..600),
        ) {
            let digest = digest_of(&values);
            let mut sorted = values;
            sorted.sort_by(f64::total_cmp);
            let (min, max) = (sorted[0], sorted[sorted.len() - 1]);
            let mut previous = f64::NEG_INFINITY;
            for step in 0..=100 {
                let q = f64::from(step) / 100.0;
                let value = digest.quantile(q).unwrap();
                proptest::prop_assert!(value >= previous - 1e-6, "q={q} {value} < {previous}");
                proptest::prop_assert!(value >= min && value <= max);
                previous = value;
            }
            if sorted.len() >= 30 {
                let exact_median = sorted[(sorted.len() - 1) / 2];
                let median = digest.quantile(0.5).unwrap();
                proptest::prop_assert!(
                    (median - exact_median).abs() <= (max - min).mul_add(0.1, 1.0),
                    "median {median} vs {exact_median}"
                );
            }
        }

        /// A bigger burst never lowers the reserve: feeding samples in
        /// non-decreasing order keeps the top quantile non-decreasing.
        #[test]
        fn larger_samples_never_lower_the_top_quantile(
            values in proptest::collection::vec(0.0f64..1e9, 2..300),
        ) {
            let mut ascending = values;
            ascending.sort_by(f64::total_cmp);
            let mut digest = TDigest::default();
            let mut best = 0.0f64;
            for &value in &ascending {
                digest.add(value);
                let q99 = digest.quantile(0.99).unwrap();
                proptest::prop_assert!(q99 >= best - 1e-6, "{q99} < {best}");
                best = best.max(q99);
                proptest::prop_assert!(q99 <= digest.max().unwrap() + 1e-6);
            }
        }

        /// The tail extrapolation never falls below the empirical threshold
        /// quantile and stays finite.
        #[test]
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        fn tail_extrapolation_never_below_threshold(
            values in proptest::collection::vec(0.0f64..1e9, 10..200),
        ) {
            let fit = TailFit::fit(&values, TAIL_THRESHOLD_QUANTILE).unwrap();
            let q = fit.quantile(RESERVE_QUANTILE);
            proptest::prop_assert!(q.is_finite());
            proptest::prop_assert!(q >= fit.threshold);
            let mut sorted = values;
            sorted.sort_by(f64::total_cmp);
            let n = sorted.len();
            let index = ((n as f64) * TAIL_THRESHOLD_QUANTILE).ceil().max(1.0) as usize;
            proptest::prop_assert!(q >= sorted[index.min(n) - 1]);
        }
    }
}
