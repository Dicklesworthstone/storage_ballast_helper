//! Value-of-Information scan scheduler: allocates scan budget to paths with highest
//! expected reclaimed-bytes-per-IO while maintaining safety and exploration guarantees.
//!
//! # Motivation
//!
//! Fixed-frequency scanning wastes IO under both pressure and calm: under pressure we
//! want to scan high-yield paths first, under calm we waste cycles scanning paths with
//! nothing to reclaim. VOI scheduling directs limited scan budget toward the most
//! promising paths.
//!
//! # Index (Q6)
//!
//! Each root is ranked by a hazard-driven index:
//!
//! ```text
//! I_i = R_i * (1 - exp(-lambda_i * dt_i)) - w_c * C_i
//! ```
//!
//! where `R_i` is the expected reclaim (EWMA of bytes reclaimed per scan),
//! `C_i` the visit cost (EWMA of IO per scan), `lambda_i` the EWMA of dirty
//! transitions per hour reported by the v2 event source (prior: once a day,
//! also the floor), and `dt_i` the hours since the last visit. Roots with a
//! pending dirty transition always go first; then the top of the index within
//! the budget. The hazard term is what keeps an idle root from being starved:
//! it climbs on its own as time passes, so no exploration quota is needed.
//!
//! # Fallback Guarantee
//!
//! If forecast accuracy degrades below a threshold across N consecutive windows, the
//! scheduler disables VOI prioritization and reverts to deterministic round-robin until
//! recalibrated.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::Instant;

pub use crate::core::config::VoiConfig;

// ──────────────────── configuration ────────────────────

// ──────────────────── per-path statistics ────────────────────

/// Tracked statistics for a single scan path.
#[derive(Debug, Clone)]
pub struct PathStats {
    /// Cumulative bytes reclaimed from this path across all scans.
    pub total_reclaimed_bytes: u64,
    /// Number of times this path has been scanned.
    pub scan_count: u32,
    /// Number of items deleted from this path across all scans.
    pub total_items_deleted: u32,
    /// Number of false-positive vetoes encountered during scanning.
    pub false_positive_count: u32,
    /// Last time this path was scanned.
    pub last_scanned: Option<Instant>,
    /// EWMA of bytes reclaimed per scan (smoothed).
    pub ewma_reclaim_per_scan: f64,
    /// EWMA of IO cost per scan (estimated disk reads).
    pub ewma_io_cost_per_scan: f64,
    /// Forecast: predicted reclaim for next scan.
    pub forecast_reclaim: f64,
    /// Forecast that was in effect before the most recent scan (for error computation).
    last_pre_scan_forecast: f64,
    /// Last actual reclaim (for forecast error tracking).
    pub last_actual_reclaim: u64,
    /// EWMA of dirty transitions per hour seen for this root (Q6 hazard
    /// rate `lambda_i`), from the v2 event source. Prior: once a day.
    pub dirty_rate_per_hour: f64,
    /// When the dirty rate was last observed.
    last_dirty_observation: Option<Instant>,
    /// A dirty transition was reported since the last scan: the root goes
    /// first in the next plan regardless of its index.
    pub dirty_pending: bool,
}

/// Prior hazard rate for a root nothing is known about: one dirty
/// transition per day.
pub const PRIOR_DIRTY_RATE_PER_HOUR: f64 = 1.0 / 24.0;

impl PathStats {
    fn new() -> Self {
        Self {
            total_reclaimed_bytes: 0,
            scan_count: 0,
            total_items_deleted: 0,
            false_positive_count: 0,
            last_scanned: None,
            ewma_reclaim_per_scan: 0.0,
            ewma_io_cost_per_scan: 1000.0, // default assumption: 1000 reads per scan
            forecast_reclaim: 0.0,
            last_pre_scan_forecast: 0.0,
            last_actual_reclaim: 0,
            dirty_rate_per_hour: PRIOR_DIRTY_RATE_PER_HOUR,
            last_dirty_observation: None,
            dirty_pending: false,
        }
    }

    /// Fold one pass's dirty observation into the hazard rate: a dirty pass
    /// counts as one transition over the time since the previous
    /// observation, a clean pass as zero.
    fn record_dirty(&mut self, dirty: bool, now: Instant, alpha: f64) {
        let hours = self.last_dirty_observation.map_or(1.0 / 60.0, |last| {
            (now.saturating_duration_since(last).as_secs_f64() / 3600.0).max(1.0 / 60.0)
        });
        let observed = if dirty { 1.0 / hours } else { 0.0 };
        self.dirty_rate_per_hour = ewma(alpha, self.dirty_rate_per_hour, observed);
        self.last_dirty_observation = Some(now);
        if dirty {
            self.dirty_pending = true;
        }
    }

    /// Q6 index: expected reclaim discounted by the chance the root changed
    /// since its last visit, minus the weighted visit cost.
    ///
    /// `I = R * (1 - exp(-lambda * dt)) - w_c * C`, with `lambda` floored at
    /// the daily prior so a quiet root is still revisited about once a day,
    /// and `dt` the hours since the last visit. A never-visited root's state
    /// is unknown, which is the maximal hazard: it ranks on its full prior
    /// reclaim until its first scan, so nothing is starved.
    fn hazard_index(&self, expected_reclaim: f64, io_cost_weight: f64, now: Instant) -> f64 {
        let hazard = self.last_scanned.map_or(1.0, |t| {
            let dt_hours = now.saturating_duration_since(t).as_secs_f64() / 3600.0;
            let lambda = self.dirty_rate_per_hour.max(PRIOR_DIRTY_RATE_PER_HOUR);
            1.0 - (-lambda * dt_hours).exp()
        });
        expected_reclaim.mul_add(hazard, -(io_cost_weight * self.ewma_io_cost_per_scan))
    }

    /// Update stats after a completed scan.
    fn record_scan(
        &mut self,
        reclaimed_bytes: u64,
        items_deleted: u32,
        false_positives: u32,
        io_cost_estimate: f64,
        now: Instant,
        alpha: f64,
    ) {
        self.total_reclaimed_bytes = self.total_reclaimed_bytes.saturating_add(reclaimed_bytes);
        self.total_items_deleted = self.total_items_deleted.saturating_add(items_deleted);
        self.false_positive_count = self.false_positive_count.saturating_add(false_positives);
        self.scan_count = self.scan_count.saturating_add(1);
        self.last_scanned = Some(now);
        self.last_actual_reclaim = reclaimed_bytes;
        self.dirty_pending = false;

        // Snapshot the pre-update forecast so forecast_error() compares the actual
        // result against the prediction that was made *before* seeing this observation.
        self.last_pre_scan_forecast = self.forecast_reclaim;

        let reclaim_f = reclaimed_bytes as f64;
        self.ewma_reclaim_per_scan = ewma(alpha, self.ewma_reclaim_per_scan, reclaim_f);
        self.ewma_io_cost_per_scan = ewma(alpha, self.ewma_io_cost_per_scan, io_cost_estimate);

        // Update forecast for next scan (simple: use EWMA as forecast).
        self.forecast_reclaim = self.ewma_reclaim_per_scan;
    }

    /// Compute forecast error (absolute percentage error) for the last scan.
    fn forecast_error(&self) -> Option<f64> {
        if self.scan_count < 2 {
            return None;
        }
        let actual = self.last_actual_reclaim as f64;
        let forecast = self.last_pre_scan_forecast;
        if !actual.is_finite() || !forecast.is_finite() {
            return None;
        }
        if actual.abs() < 1.0 && forecast.abs() < 1.0 {
            return Some(0.0); // both near zero
        }
        let denominator = actual.abs().max(forecast.abs()).max(1.0);
        Some((actual - forecast).abs() / denominator)
    }
}

// ──────────────────── scan plan output ────────────────────

/// A prioritized scan plan produced by the scheduler.
#[derive(Debug, Clone)]
pub struct ScanPlan {
    /// Ordered list of paths to scan (highest utility first).
    pub paths: Vec<ScanPlanEntry>,
    /// Whether the scheduler is in fallback (round-robin) mode.
    pub fallback_active: bool,
    /// Total budget allocated this interval.
    pub budget_used: usize,
    /// Total budget available.
    pub budget_total: usize,
}

/// A single entry in the scan plan.
#[derive(Debug, Clone)]
pub struct ScanPlanEntry {
    /// Path to scan.
    pub path: PathBuf,
    /// Computed utility score.
    pub utility: f64,
    /// Whether this was selected as an exploration pick.
    pub is_exploration: bool,
    /// Forecast reclaim bytes.
    pub forecast_reclaim_bytes: f64,
}

// ──────────────────── calibration state ────────────────────

/// Tracks forecast accuracy to trigger/recover from fallback mode.
#[derive(Debug, Clone)]
struct CalibrationState {
    /// Consecutive windows where mean forecast error exceeded threshold.
    consecutive_bad_windows: u32,
    /// Consecutive windows where mean forecast error was acceptable.
    consecutive_good_windows: u32,
    /// Whether we are in fallback mode.
    fallback_active: bool,
    /// History of window-level mean absolute percentage error.
    window_mapes: VecDeque<f64>,
}

impl CalibrationState {
    fn new() -> Self {
        Self {
            consecutive_bad_windows: 0,
            consecutive_good_windows: 0,
            fallback_active: false,
            window_mapes: VecDeque::new(),
        }
    }

    /// Record a window's mean forecast error and update fallback state.
    fn record_window(&mut self, mape: f64, config: &VoiConfig) {
        self.window_mapes.push_back(mape);
        // Keep last 50 windows for diagnostics.
        if self.window_mapes.len() > 50 {
            self.window_mapes.pop_front();
        }

        if mape > config.forecast_error_threshold {
            self.consecutive_bad_windows = self.consecutive_bad_windows.saturating_add(1);
            self.consecutive_good_windows = 0;
            if self.consecutive_bad_windows >= config.fallback_trigger_windows {
                self.fallback_active = true;
            }
        } else {
            self.consecutive_good_windows = self.consecutive_good_windows.saturating_add(1);
            self.consecutive_bad_windows = 0;
            if self.fallback_active
                && self.consecutive_good_windows >= config.recovery_trigger_windows
            {
                self.fallback_active = false;
            }
        }
    }
}

// ──────────────────── main scheduler ────────────────────

/// Value-of-Information scan scheduler.
///
/// Maintains per-path statistics and produces prioritized scan plans that maximize
/// expected reclaimed-bytes-per-IO within a fixed budget.
#[derive(Debug, Clone)]
pub struct VoiScheduler {
    config: VoiConfig,
    path_stats: HashMap<PathBuf, PathStats>,
    calibration: CalibrationState,
    /// Errors observed in the current window (for calibration).
    pending_errors: Vec<f64>,
    /// Round-robin cursor for exploration and fallback.
    rr_cursor: usize,
}

impl VoiScheduler {
    #[must_use]
    pub fn new(config: VoiConfig) -> Self {
        Self {
            config,
            path_stats: HashMap::new(),
            calibration: CalibrationState::new(),
            pending_errors: Vec::new(),
            rr_cursor: 0,
        }
    }

    /// Register a path for tracking. Idempotent.
    pub fn register_path(&mut self, path: PathBuf) {
        self.path_stats.entry(path).or_insert_with(PathStats::new);
    }

    /// Update configuration at runtime.
    pub fn update_config(&mut self, config: VoiConfig) {
        self.config = config;
    }

    /// Record the results of a completed scan for a path.
    pub fn record_scan_result(
        &mut self,
        path: &PathBuf,
        reclaimed_bytes: u64,
        items_deleted: u32,
        false_positives: u32,
        io_cost_estimate: f64,
        now: Instant,
    ) {
        if let Some(stats) = self.path_stats.get_mut(path) {
            stats.record_scan(
                reclaimed_bytes,
                items_deleted,
                false_positives,
                io_cost_estimate,
                now,
                self.config.ewma_alpha,
            );

            // Accumulate forecast error for this specific scan if valid.
            if stats.scan_count >= self.config.min_observations_for_forecast
                && let Some(error) = stats.forecast_error()
            {
                self.pending_errors.push(error);
            }
        }
    }

    /// Record whether a completed pass found `path` dirty (v2 event source),
    /// feeding the hazard rate and marking the root for the next plan.
    pub fn record_dirty(&mut self, path: &PathBuf, dirty: bool, now: Instant) {
        if let Some(stats) = self.path_stats.get_mut(path) {
            stats.record_dirty(dirty, now, self.config.ewma_alpha);
        }
    }

    /// Order `paths` by the hazard index (dirty roots first), for callers
    /// that already know which roots to scan but not in which order. Paths
    /// the scheduler has never seen keep their input order at the end.
    #[must_use]
    pub fn rank_paths(&self, paths: &[PathBuf], now: Instant) -> Vec<PathBuf> {
        let prior = self.unscanned_reclaim_prior();
        let mut ranked: Vec<(bool, f64, usize, &PathBuf)> = paths
            .iter()
            .enumerate()
            .map(|(position, path)| {
                let stats = self.path_stats.get(path);
                let dirty = stats.is_some_and(|s| s.dirty_pending);
                let index = stats.map_or(f64::NEG_INFINITY, |s| {
                    s.hazard_index(
                        Self::expected_reclaim(s, prior),
                        self.config.io_cost_weight,
                        now,
                    )
                });
                (dirty, index, position, path)
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.2.cmp(&b.2))
        });
        ranked
            .into_iter()
            .map(|(_, _, _, path)| path.clone())
            .collect()
    }

    /// Reclaim to assume for a root that was never scanned: the mean
    /// forecast of the scanned roots, at least one byte so the hazard term
    /// can matter.
    fn unscanned_reclaim_prior(&self) -> f64 {
        let scanned: Vec<f64> = self
            .path_stats
            .values()
            .filter(|s| s.scan_count > 0)
            .map(|s| s.forecast_reclaim)
            .collect();
        if scanned.is_empty() {
            return 1.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let mean = scanned.iter().sum::<f64>() / scanned.len() as f64;
        mean.max(1.0)
    }

    fn expected_reclaim(stats: &PathStats, prior: f64) -> f64 {
        if stats.scan_count == 0 {
            prior
        } else {
            stats.forecast_reclaim
        }
    }

    /// End the current scheduling window: compute forecast accuracy and update calibration.
    pub fn end_window(&mut self) {
        if self.pending_errors.is_empty() {
            return;
        }

        let mape = self.pending_errors.iter().sum::<f64>() / self.pending_errors.len() as f64;
        self.calibration.record_window(mape, &self.config);
        self.pending_errors.clear();
    }

    /// Whether the scheduler is currently in fallback (round-robin) mode.
    #[must_use]
    pub fn is_fallback_active(&self) -> bool {
        !self.config.enabled || self.calibration.fallback_active
    }

    /// Produce a prioritized scan plan for the current interval.
    #[must_use]
    pub fn schedule(&mut self, now: Instant) -> ScanPlan {
        let budget = self.config.scan_budget_per_interval;

        if self.path_stats.is_empty() || budget == 0 {
            return ScanPlan {
                paths: Vec::new(),
                fallback_active: self.is_fallback_active(),
                budget_used: 0,
                budget_total: budget,
            };
        }

        if self.is_fallback_active() {
            let paths: Vec<PathBuf> = self.path_stats.keys().cloned().collect();
            return self.schedule_round_robin(&paths, budget);
        }

        let paths: Vec<&PathBuf> = self.path_stats.keys().collect();
        self.schedule_voi(&paths, budget, now)
    }

    /// Deterministic round-robin fallback scheduler.
    fn schedule_round_robin(&mut self, paths: &[PathBuf], budget: usize) -> ScanPlan {
        let mut sorted_paths = paths.to_vec();
        sorted_paths.sort();

        let count = budget.min(sorted_paths.len());
        let mut entries = Vec::with_capacity(count);

        for i in 0..count {
            let idx = (self.rr_cursor + i) % sorted_paths.len();
            let path = &sorted_paths[idx];
            let forecast = self
                .path_stats
                .get(path)
                .map_or(0.0, |s| s.forecast_reclaim);
            entries.push(ScanPlanEntry {
                path: path.clone(),
                utility: 0.0,
                is_exploration: false,
                forecast_reclaim_bytes: forecast,
            });
        }

        self.rr_cursor = (self.rr_cursor + count) % sorted_paths.len().max(1);

        ScanPlan {
            paths: entries,
            fallback_active: true,
            budget_used: count,
            budget_total: budget,
        }
    }

    /// VOI-prioritized scheduler with exploration quota.
    /// Q6: rank every root by its hazard index (dirty roots first) and take
    /// the top of the list within the budget. The exploit/explore split is
    /// gone: the hazard term already grows with time since the last visit,
    /// so an unvisited or long-idle root climbs the list on its own.
    fn schedule_voi(&self, paths: &[&PathBuf], budget: usize, now: Instant) -> ScanPlan {
        let prior = self.unscanned_reclaim_prior();
        let mut scored: Vec<(bool, f64, &PathBuf)> = paths
            .iter()
            .map(|p| {
                let stats = self.path_stats.get(*p);
                let dirty = stats.is_some_and(|s| s.dirty_pending);
                let index = stats.map_or(0.0, |s| {
                    s.hazard_index(
                        Self::expected_reclaim(s, prior),
                        self.config.io_cost_weight,
                        now,
                    )
                });
                (dirty, index, *p)
            })
            .collect();

        // Dirty first, then by index, then by path for determinism.
        scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.2.cmp(b.2))
        });

        let selected: Vec<ScanPlanEntry> = scored
            .iter()
            .take(budget)
            .map(|(_, index, path)| {
                let stats = self.path_stats.get(*path);
                ScanPlanEntry {
                    path: (*path).clone(),
                    utility: *index,
                    is_exploration: stats.is_none_or(|s| s.scan_count == 0),
                    forecast_reclaim_bytes: stats.map_or(0.0, |s| s.forecast_reclaim),
                }
            })
            .collect();

        let used = selected.len();
        ScanPlan {
            paths: selected,
            fallback_active: false,
            budget_used: used,
            budget_total: budget,
        }
    }

    /// Get current statistics for a path (read-only).
    #[must_use]
    pub fn path_stats(&self, path: &PathBuf) -> Option<&PathStats> {
        self.path_stats.get(path)
    }

    /// Get calibration diagnostics.
    #[must_use]
    pub fn calibration_summary(&self) -> CalibrationSummary {
        CalibrationSummary {
            fallback_active: self.calibration.fallback_active,
            consecutive_bad_windows: self.calibration.consecutive_bad_windows,
            consecutive_good_windows: self.calibration.consecutive_good_windows,
            recent_mapes: self.calibration.window_mapes.iter().copied().collect(),
            total_paths_tracked: self.path_stats.len(),
        }
    }
}

/// Summary of calibration state for reporting.
#[derive(Debug, Clone)]
pub struct CalibrationSummary {
    pub fallback_active: bool,
    pub consecutive_bad_windows: u32,
    pub consecutive_good_windows: u32,
    pub recent_mapes: Vec<f64>,
    pub total_paths_tracked: usize,
}

// ──────────────────── helpers ────────────────────

#[inline]
fn ewma(alpha: f64, prev: f64, current: f64) -> f64 {
    (current - prev).mul_add(alpha, prev)
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn default_scheduler() -> VoiScheduler {
        VoiScheduler::new(VoiConfig::default())
    }

    fn scheduler_with_paths(paths: &[&str]) -> VoiScheduler {
        let mut s = default_scheduler();
        for p in paths {
            s.register_path(PathBuf::from(p));
        }
        s
    }

    #[test]
    fn empty_scheduler_produces_empty_plan() {
        let mut s = default_scheduler();
        let plan = s.schedule(Instant::now());
        assert!(plan.paths.is_empty());
        assert_eq!(plan.budget_used, 0);
    }

    #[test]
    fn registered_paths_appear_in_plan() {
        let mut s = scheduler_with_paths(&["/data/projects", "/tmp", "/var/tmp"]);
        let plan = s.schedule(Instant::now());
        assert!(!plan.paths.is_empty());
        assert!(plan.budget_used <= s.config.scan_budget_per_interval);
    }

    #[test]
    fn high_yield_paths_ranked_higher() {
        let mut s = scheduler_with_paths(&["/high", "/low"]);
        let now = Instant::now();

        // Record high reclaim for /high.
        for i in 0..5 {
            s.record_scan_result(
                &PathBuf::from("/high"),
                10_000_000,
                50,
                0,
                500.0,
                now + Duration::from_secs(i),
            );
        }
        // Record low reclaim for /low.
        for i in 0..5 {
            s.record_scan_result(
                &PathBuf::from("/low"),
                100,
                1,
                0,
                500.0,
                now + Duration::from_secs(i),
            );
        }

        let plan = s.schedule(now + Duration::from_secs(10));
        let exploitation_entries: Vec<_> =
            plan.paths.iter().filter(|e| !e.is_exploration).collect();
        if !exploitation_entries.is_empty() {
            assert_eq!(exploitation_entries[0].path, PathBuf::from("/high"));
        }
    }

    /// Q6: unvisited roots are not starved by a quota; the hazard term does
    /// the work. A root scanned a minute ago has almost no chance of having
    /// changed, so the never-visited roots (a day of prior hazard) outrank it.
    #[test]
    fn unvisited_roots_outrank_a_just_scanned_root_by_hazard() {
        let mut s = VoiScheduler::new(VoiConfig {
            scan_budget_per_interval: 4,
            ..Default::default()
        });
        for path in ["/a", "/b", "/c", "/d"] {
            s.register_path(PathBuf::from(path));
        }

        let now = Instant::now();
        // Only /a has any scan history, and it was just scanned.
        for i in 0..5 {
            s.record_scan_result(
                &PathBuf::from("/a"),
                5_000_000,
                10,
                0,
                200.0,
                now + Duration::from_secs(i),
            );
        }

        let plan = s.schedule(now + Duration::from_mins(1));
        assert_eq!(plan.budget_used, 4);
        assert_ne!(
            plan.paths[0].path,
            Path::new("/a"),
            "a root scanned a minute ago must not lead the plan"
        );
        let unvisited: Vec<_> = plan.paths.iter().filter(|e| e.is_exploration).collect();
        assert_eq!(
            unvisited.len(),
            3,
            "the three never-scanned roots are exploration picks"
        );
        assert!(unvisited.iter().all(|e| e.path != Path::new("/a")));

        // A day later the just-scanned root has regained most of its hazard:
        // its index is orders of magnitude above the just-scanned value.
        let minute_index = plan
            .paths
            .iter()
            .find(|e| e.path == Path::new("/a"))
            .map(|e| e.utility)
            .expect("/a is in the plan");
        let later = s.schedule(now + Duration::from_hours(24));
        let day_index = later
            .paths
            .iter()
            .find(|e| e.path == Path::new("/a"))
            .map(|e| e.utility)
            .expect("/a is in the plan");
        assert!(
            day_index > minute_index * 100.0,
            "index after a day {day_index} vs after a minute {minute_index}"
        );
    }

    /// Dirty roots (v2 events) go first regardless of index, and the flag
    /// clears once the root is scanned.
    #[test]
    fn dirty_roots_go_first_until_scanned() {
        let mut s = scheduler_with_paths(&["/big", "/small"]);
        let now = Instant::now();
        for i in 0..5 {
            s.record_scan_result(&PathBuf::from("/big"), 50_000_000, 10, 0, 500.0, now);
            s.record_scan_result(&PathBuf::from("/small"), 1_000, 1, 0, 500.0, now);
            let _ = i;
        }
        let later = now + Duration::from_hours(2);
        assert_eq!(s.schedule(later).paths[0].path, PathBuf::from("/big"));

        s.record_dirty(&PathBuf::from("/small"), true, later);
        assert_eq!(s.schedule(later).paths[0].path, PathBuf::from("/small"));
        assert_eq!(
            s.rank_paths(&[PathBuf::from("/big"), PathBuf::from("/small")], later)[0],
            PathBuf::from("/small")
        );

        s.record_scan_result(&PathBuf::from("/small"), 1_000, 1, 0, 500.0, later);
        assert!(
            !s.path_stats(&PathBuf::from("/small"))
                .unwrap()
                .dirty_pending
        );
        assert_eq!(
            s.schedule(later + Duration::from_secs(1)).paths[0].path,
            PathBuf::from("/big")
        );
    }

    #[test]
    fn fallback_triggers_after_consecutive_bad_windows() {
        let mut s = scheduler_with_paths(&["/data"]);
        let now = Instant::now();

        // Bootstrap: reach min_observations_for_forecast (3) so errors get tracked.
        for i in 0..3 {
            s.record_scan_result(
                &PathBuf::from("/data"),
                1_000_000,
                10,
                0,
                100.0,
                now + Duration::from_secs(i),
            );
        }
        // Flush bootstrap errors so we start clean.
        s.end_window();

        // Simulate 3 bad windows (default fallback_trigger_windows=3).
        // Each window: corrupt forecast → record scan with tiny actual → end_window.
        for i in 0..3 {
            if let Some(stats) = s.path_stats.get_mut(&PathBuf::from("/data")) {
                stats.forecast_reclaim = 100_000_000.0; // wildly wrong
            }
            s.record_scan_result(
                &PathBuf::from("/data"),
                1, // tiny actual → huge forecast error
                1,
                0,
                100.0,
                now + Duration::from_secs(10 + i),
            );
            s.end_window();
        }

        assert!(
            s.is_fallback_active(),
            "should be in fallback after 3 bad windows"
        );

        // Plan should now be round-robin.
        let plan = s.schedule(now + Duration::from_secs(100));
        assert!(plan.fallback_active);
    }

    #[test]
    fn fallback_recovers_after_good_windows() {
        let mut s = scheduler_with_paths(&["/data"]);
        let now = Instant::now();

        // Bootstrap: converge EWMA to a stable value before entering fallback.
        for i in 0..10 {
            s.record_scan_result(
                &PathBuf::from("/data"),
                1000,
                5,
                0,
                100.0,
                now + Duration::from_secs(i),
            );
        }
        // Flush bootstrap errors.
        s.end_window();

        // Force into fallback.
        s.calibration.fallback_active = true;
        s.calibration.consecutive_bad_windows = 5;
        assert!(s.is_fallback_active());

        // Simulate 5 good windows (default recovery_trigger_windows=5).
        // Each window: record a scan with value close to the converged EWMA → low error.
        for i in 0..5 {
            s.record_scan_result(
                &PathBuf::from("/data"),
                1000,
                5,
                0,
                100.0,
                now + Duration::from_secs(20 + i),
            );
            s.end_window();
        }

        assert!(
            !s.is_fallback_active(),
            "should have recovered from fallback after 5 good windows"
        );
    }

    #[test]
    fn disabled_scheduler_uses_round_robin() {
        let mut s = VoiScheduler::new(VoiConfig {
            enabled: false,
            ..Default::default()
        });
        s.register_path(PathBuf::from("/a"));
        s.register_path(PathBuf::from("/b"));

        let plan = s.schedule(Instant::now());
        assert!(
            plan.fallback_active,
            "disabled scheduler should use fallback"
        );
    }

    #[test]
    fn round_robin_advances_cursor() {
        let mut s = VoiScheduler::new(VoiConfig {
            enabled: false,
            scan_budget_per_interval: 1,
            ..Default::default()
        });
        s.register_path(PathBuf::from("/a"));
        s.register_path(PathBuf::from("/b"));
        s.register_path(PathBuf::from("/c"));

        let now = Instant::now();
        let plan1 = s.schedule(now);
        let plan2 = s.schedule(now);
        let plan3 = s.schedule(now);

        // Three successive calls with budget=1 should cycle through all paths.
        let selected: Vec<String> = [plan1, plan2, plan3]
            .iter()
            .flat_map(|p| p.paths.iter().map(|e| e.path.to_string_lossy().to_string()))
            .collect();
        assert_eq!(selected.len(), 3);
        // All should be unique (cycling through /a, /b, /c).
        let unique: std::collections::HashSet<_> = selected.iter().collect();
        assert_eq!(
            unique.len(),
            3,
            "round-robin should cycle through all paths"
        );
    }

    /// Q6 index properties: monotone in time since the last visit, the
    /// hazard rate floored at the daily prior (a quiet root is still worth a
    /// visit after a day), and a hot, rich root dominates a quiet, poor one.
    #[test]
    fn hazard_index_is_monotone_in_idle_time_and_dominated_by_hot_rich_roots() {
        let now = Instant::now();
        let mut quiet = PathStats::new();
        quiet.last_scanned = Some(now);
        quiet.forecast_reclaim = 1_000_000.0;
        quiet.scan_count = 3;
        quiet.dirty_rate_per_hour = 0.0; // never seen dirty: floored to the prior
        let cost_weight = 0.1;

        let at = |hours: f64| {
            quiet.hazard_index(
                quiet.forecast_reclaim,
                cost_weight,
                now + Duration::from_secs_f64(hours * 3600.0),
            )
        };
        assert!(at(0.0) < at(1.0));
        assert!(at(1.0) < at(6.0));
        assert!(at(6.0) < at(24.0));
        assert!(at(24.0) < at(48.0));
        // With the daily prior, a day of idleness recovers ~63% of the reclaim.
        let day = at(24.0);
        let expected = 1_000_000.0f64.mul_add(1.0 - (-1.0f64).exp(), -(cost_weight * 1000.0));
        assert!((day - expected).abs() < 1.0, "{day} vs {expected}");
        // Right after a visit the index is at most the (negative) cost term.
        assert!(at(0.0) <= 0.0);

        // A hot (dirty ten times an hour), rich root beats a quiet, poor one
        // at the same idle time.
        let mut hot = PathStats::new();
        hot.last_scanned = Some(now);
        hot.forecast_reclaim = 10_000_000.0;
        hot.scan_count = 3;
        hot.dirty_rate_per_hour = 10.0;
        let later = now + Duration::from_mins(30);
        assert!(
            hot.hazard_index(hot.forecast_reclaim, cost_weight, later)
                > quiet.hazard_index(quiet.forecast_reclaim, cost_weight, later)
        );

        // The dirty rate follows observations: a dirty pass every ten
        // minutes pushes the rate well above the prior, clean passes decay it.
        let mut observed = PathStats::new();
        let mut t = now;
        for _ in 0..12 {
            t += Duration::from_mins(10);
            observed.record_dirty(true, t, 0.3);
        }
        assert!(
            observed.dirty_rate_per_hour > 3.0,
            "{}",
            observed.dirty_rate_per_hour
        );
        for _ in 0..12 {
            t += Duration::from_mins(10);
            observed.record_dirty(false, t, 0.3);
        }
        assert!(
            observed.dirty_rate_per_hour < 0.2,
            "{}",
            observed.dirty_rate_per_hour
        );
    }

    #[test]
    fn budget_limits_plan_size() {
        let mut s = VoiScheduler::new(VoiConfig {
            scan_budget_per_interval: 2,
            ..Default::default()
        });
        for i in 0..10 {
            s.register_path(PathBuf::from(format!("/path/{i}")));
        }

        let plan = s.schedule(Instant::now());
        assert!(
            plan.budget_used <= 2,
            "plan should respect budget limit, got {}",
            plan.budget_used
        );
    }

    #[test]
    fn calibration_summary_reflects_state() {
        let s = default_scheduler();
        let summary = s.calibration_summary();
        assert!(!summary.fallback_active);
        assert_eq!(summary.consecutive_bad_windows, 0);
        assert_eq!(summary.recent_mapes.len(), 0);
    }

    #[test]
    fn record_scan_updates_stats() {
        let mut s = scheduler_with_paths(&["/data"]);
        let now = Instant::now();

        s.record_scan_result(&PathBuf::from("/data"), 5000, 3, 1, 200.0, now);

        let stats = s.path_stats(&PathBuf::from("/data")).unwrap();
        assert_eq!(stats.total_reclaimed_bytes, 5000);
        assert_eq!(stats.scan_count, 1);
        assert_eq!(stats.total_items_deleted, 3);
        assert_eq!(stats.false_positive_count, 1);
        assert!(stats.last_scanned.is_some());
    }

    #[test]
    fn ewma_converges_over_multiple_scans() {
        let mut s = scheduler_with_paths(&["/data"]);
        let now = Instant::now();

        // Record 10 scans with constant 1MB reclaim.
        for i in 0..10 {
            s.record_scan_result(
                &PathBuf::from("/data"),
                1_000_000,
                10,
                0,
                500.0,
                now + Duration::from_secs(i),
            );
        }

        let stats = s.path_stats(&PathBuf::from("/data")).unwrap();
        // EWMA should converge close to 1_000_000.
        assert!(
            (stats.ewma_reclaim_per_scan - 1_000_000.0).abs() < 100_000.0,
            "EWMA should converge near 1M, got {}",
            stats.ewma_reclaim_per_scan
        );
    }
}
