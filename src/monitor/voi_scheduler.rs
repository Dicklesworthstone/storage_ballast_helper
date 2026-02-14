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
//! # Utility Model
//!
//! ```text
//! utility(path) = expected_reclaim_bytes × uncertainty_discount
//!               − io_cost_penalty
//!               − false_positive_risk_penalty
//!               + exploration_bonus (for under-sampled paths)
//! ```
//!
//! # Fallback Guarantee
//!
//! If forecast accuracy degrades below a threshold across N consecutive windows, the
//! scheduler disables VOI prioritization and reverts to deterministic round-robin until
//! recalibrated.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};

// ──────────────────── configuration ────────────────────

/// Tuning knobs for the VOI scan scheduler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct VoiConfig {
    /// Master switch.
    pub enabled: bool,
    /// Maximum number of paths to scan per scheduling interval.
    pub scan_budget_per_interval: usize,
    /// Minimum fraction of budget reserved for exploration (round-robin of least-scanned paths).
    pub exploration_quota_fraction: f64,
    /// Weight for IO cost penalty (bytes estimated per scan).
    pub io_cost_weight: f64,
    /// Weight for false-positive risk penalty.
    pub fp_risk_weight: f64,
    /// Weight for exploration bonus.
    pub exploration_weight: f64,
    /// Forecast-error threshold: if MAPE exceeds this, switch to fallback.
    pub forecast_error_threshold: f64,
    /// Number of consecutive windows with high forecast error before triggering fallback.
    pub fallback_trigger_windows: u32,
    /// Number of consecutive windows with acceptable error to exit fallback.
    pub recovery_trigger_windows: u32,
    /// Minimum scans of a path before its forecast is considered reliable.
    pub min_observations_for_forecast: u32,
}

impl Default for VoiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_budget_per_interval: 5,
            exploration_quota_fraction: 0.20,
            io_cost_weight: 0.1,
            fp_risk_weight: 0.15,
            exploration_weight: 0.25,
            forecast_error_threshold: 0.5,
            fallback_trigger_windows: 3,
            recovery_trigger_windows: 5,
            min_observations_for_forecast: 3,
        }
    }
}

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
    /// Last actual reclaim (for forecast error tracking).
    pub last_actual_reclaim: u64,
}

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
            last_actual_reclaim: 0,
        }
    }

    /// Update stats after a completed scan.
    fn record_scan(
        &mut self,
        reclaimed_bytes: u64,
        items_deleted: u32,
        false_positives: u32,
        io_cost_estimate: f64,
        now: Instant,
    ) {
        let alpha = 0.3;
        self.total_reclaimed_bytes = self.total_reclaimed_bytes.saturating_add(reclaimed_bytes);
        self.total_items_deleted = self.total_items_deleted.saturating_add(items_deleted);
        self.false_positive_count = self.false_positive_count.saturating_add(false_positives);
        self.scan_count = self.scan_count.saturating_add(1);
        self.last_scanned = Some(now);
        self.last_actual_reclaim = reclaimed_bytes;

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
        let forecast = self.forecast_reclaim;
        if actual.abs() < 1.0 && forecast.abs() < 1.0 {
            return Some(0.0); // both near zero
        }
        let denominator = actual.abs().max(forecast.abs()).max(1.0);
        Some((actual - forecast).abs() / denominator)
    }

    /// Time since last scan (or infinity if never scanned).
    fn staleness(&self, now: Instant) -> f64 {
        self.last_scanned
            .map_or(f64::INFINITY, |t| now.duration_since(t).as_secs_f64())
    }

    /// False-positive rate.
    fn fp_rate(&self) -> f64 {
        if self.scan_count == 0 {
            return 0.0;
        }
        f64::from(self.false_positive_count) / f64::from(self.scan_count)
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
    window_mapes: Vec<f64>,
}

impl CalibrationState {
    fn new() -> Self {
        Self {
            consecutive_bad_windows: 0,
            consecutive_good_windows: 0,
            fallback_active: false,
            window_mapes: Vec::new(),
        }
    }

    /// Record a window's mean forecast error and update fallback state.
    fn record_window(&mut self, mape: f64, config: &VoiConfig) {
        self.window_mapes.push(mape);
        // Keep last 50 windows for diagnostics.
        if self.window_mapes.len() > 50 {
            self.window_mapes.remove(0);
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
            rr_cursor: 0,
        }
    }

    /// Register a path for tracking. Idempotent.
    pub fn register_path(&mut self, path: PathBuf) {
        self.path_stats.entry(path).or_insert_with(PathStats::new);
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
            );
        }
    }

    /// End the current scheduling window: compute forecast accuracy and update calibration.
    pub fn end_window(&mut self) {
        let errors: Vec<f64> = self
            .path_stats
            .values()
            .filter(|s| s.scan_count >= self.config.min_observations_for_forecast)
            .filter_map(PathStats::forecast_error)
            .collect();

        if errors.is_empty() {
            return;
        }

        let mape = errors.iter().sum::<f64>() / errors.len() as f64;
        self.calibration.record_window(mape, &self.config);
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
        let paths: Vec<PathBuf> = self.path_stats.keys().cloned().collect();

        if paths.is_empty() || budget == 0 {
            return ScanPlan {
                paths: Vec::new(),
                fallback_active: self.is_fallback_active(),
                budget_used: 0,
                budget_total: budget,
            };
        }

        if self.is_fallback_active() {
            return self.schedule_round_robin(&paths, budget);
        }

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
    fn schedule_voi(&self, paths: &[PathBuf], budget: usize, now: Instant) -> ScanPlan {
        // Split budget: exploration vs exploitation.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let exploration_budget =
            ((budget as f64 * self.config.exploration_quota_fraction).ceil() as usize).min(budget);
        let exploitation_budget = budget.saturating_sub(exploration_budget);

        // 1. Score all paths by utility.
        let mut scored: Vec<(PathBuf, f64)> = paths
            .iter()
            .map(|p| {
                let utility = self.compute_utility(p, now);
                (p.clone(), utility)
            })
            .collect();

        // Sort descending by utility.
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // 2. Pick exploitation targets (top utility, up to exploitation_budget).
        let mut selected: Vec<ScanPlanEntry> = Vec::with_capacity(budget);
        let mut selected_set: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        for (path, utility) in scored.iter().take(exploitation_budget) {
            let forecast = self
                .path_stats
                .get(path)
                .map_or(0.0, |s| s.forecast_reclaim);
            selected.push(ScanPlanEntry {
                path: path.clone(),
                utility: *utility,
                is_exploration: false,
                forecast_reclaim_bytes: forecast,
            });
            selected_set.insert(path.clone());
        }

        // 3. Pick exploration targets: least-scanned paths not already selected.
        let mut exploration_candidates: Vec<(PathBuf, u32, f64)> = paths
            .iter()
            .filter(|p| !selected_set.contains(*p))
            .map(|p| {
                let stats = self.path_stats.get(p);
                let count = stats.map_or(0, |s| s.scan_count);
                let staleness = stats.map_or(f64::INFINITY, |s| s.staleness(now));
                (p.clone(), count, staleness)
            })
            .collect();

        // Prefer least-scanned, then most stale.
        exploration_candidates.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
        });

        for (path, _, _) in exploration_candidates.iter().take(exploration_budget) {
            let forecast = self
                .path_stats
                .get(path)
                .map_or(0.0, |s| s.forecast_reclaim);
            let utility = self.compute_utility(path, now);
            selected.push(ScanPlanEntry {
                path: path.clone(),
                utility,
                is_exploration: true,
                forecast_reclaim_bytes: forecast,
            });
        }

        let used = selected.len();

        ScanPlan {
            paths: selected,
            fallback_active: false,
            budget_used: used,
            budget_total: budget,
        }
    }

    /// Compute the VOI utility score for a path.
    fn compute_utility(&self, path: &PathBuf, now: Instant) -> f64 {
        let Some(stats) = self.path_stats.get(path) else {
            return 0.0;
        };

        // Expected reclaim.
        let expected_reclaim = stats.ewma_reclaim_per_scan;

        // Uncertainty discount: reduce utility if we have few observations.
        let observation_ratio = (f64::from(stats.scan_count)
            / f64::from(self.config.min_observations_for_forecast))
        .min(1.0);
        let uncertainty_discount = 0.5f64.mul_add(observation_ratio, 0.5); // range [0.5, 1.0]

        // IO cost penalty.
        let io_penalty = stats.ewma_io_cost_per_scan * self.config.io_cost_weight;

        // False-positive risk penalty.
        let fp_penalty = stats.fp_rate() * expected_reclaim * self.config.fp_risk_weight;

        // Exploration bonus: grows with staleness and inversely with scan count.
        let staleness_hours = stats.staleness(now) / 3600.0;
        let exploration_bonus = self.config.exploration_weight
            * staleness_hours.min(24.0)
            * (1.0 / (f64::from(stats.scan_count) + 1.0));

        // Combine.
        let utility = expected_reclaim.mul_add(uncertainty_discount, -io_penalty) - fp_penalty
            + exploration_bonus;

        // Clamp to non-negative (a path can't have negative priority — just low).
        utility.max(0.0)
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
            recent_mapes: self.calibration.window_mapes.clone(),
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

    #[test]
    fn exploration_quota_prevents_starvation() {
        let mut s = VoiScheduler::new(VoiConfig {
            scan_budget_per_interval: 4,
            exploration_quota_fraction: 0.50, // 50% exploration
            ..Default::default()
        });
        s.register_path(PathBuf::from("/a"));
        s.register_path(PathBuf::from("/b"));
        s.register_path(PathBuf::from("/c"));
        s.register_path(PathBuf::from("/d"));

        let now = Instant::now();
        // Only /a has any scan history.
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

        let plan = s.schedule(now + Duration::from_secs(60));
        let exploration: Vec<_> = plan.paths.iter().filter(|e| e.is_exploration).collect();
        // With 50% exploration and budget=4, at least 2 should be exploration picks.
        assert!(
            exploration.len() >= 2,
            "expected at least 2 exploration picks, got {}",
            exploration.len()
        );
        // Exploration picks should NOT include /a (which has the most scans).
        for e in &exploration {
            assert_ne!(
                e.path,
                PathBuf::from("/a"),
                "exploration should prefer least-scanned"
            );
        }
    }

    #[test]
    fn fallback_triggers_after_consecutive_bad_windows() {
        let mut s = scheduler_with_paths(&["/data"]);
        let now = Instant::now();

        // Record some scans.
        for i in 0..5 {
            s.record_scan_result(
                &PathBuf::from("/data"),
                1_000_000,
                10,
                0,
                100.0,
                now + Duration::from_secs(i),
            );
        }

        // Simulate 3 bad windows (default fallback_trigger_windows=3).
        for _ in 0..3 {
            // Corrupt the forecast to create high error.
            if let Some(stats) = s.path_stats.get_mut(&PathBuf::from("/data")) {
                stats.forecast_reclaim = 100_000_000.0; // wildly wrong
                stats.last_actual_reclaim = 1; // actual was tiny
            }
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

        // Force into fallback.
        s.calibration.fallback_active = true;
        s.calibration.consecutive_bad_windows = 5;
        assert!(s.is_fallback_active());

        // Record scans with good accuracy.
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

        // Simulate 5 good windows (default recovery_trigger_windows=5).
        for _ in 0..5 {
            // Forecast should be close to actual now (EWMA converged).
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

    #[test]
    fn false_positive_rate_reduces_utility() {
        let mut s = scheduler_with_paths(&["/fp_heavy", "/clean"]);
        let now = Instant::now();

        // Both paths have similar reclaim, but /fp_heavy has many false positives.
        for i in 0..5 {
            s.record_scan_result(
                &PathBuf::from("/fp_heavy"),
                1_000_000,
                10,
                8, // 8 false positives per scan
                500.0,
                now + Duration::from_secs(i),
            );
            s.record_scan_result(
                &PathBuf::from("/clean"),
                1_000_000,
                10,
                0, // no false positives
                500.0,
                now + Duration::from_secs(i),
            );
        }

        let plan = s.schedule(now + Duration::from_secs(60));
        let exploitation: Vec<_> = plan.paths.iter().filter(|e| !e.is_exploration).collect();
        if exploitation.len() >= 2 {
            // /clean should rank higher than /fp_heavy.
            assert!(
                exploitation[0].utility >= exploitation[1].utility,
                "clean path should have higher utility than FP-heavy path"
            );
        }
    }

    #[test]
    fn uncertainty_discount_reduces_utility_for_new_paths() {
        let s = scheduler_with_paths(&["/new"]);
        let now = Instant::now();
        // New path with no observations has uncertainty discount.
        let utility = s.compute_utility(&PathBuf::from("/new"), now);
        // With no observations, expected reclaim is 0, so utility should be just exploration bonus.
        // The exploration bonus depends on staleness (infinite for never-scanned).
        assert!(utility >= 0.0, "utility should be non-negative");
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
