//! Scanner v2 filesystem event invalidation.
//!
//! The event layer is advisory: it marks roots/subtrees dirty and the scanner
//! reconciles those paths against current filesystem state before deletion.
//! Overflow, backend loss, and watch-budget gaps force conservative bounded
//! reconciliation rather than approving stale index state.

#![allow(missing_docs)]

#[cfg(any(target_os = "linux", test))]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(any(target_os = "linux", test))]
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", test))]
use std::time::SystemTime;
use std::time::{Duration, Instant};

use crate::core::config::{ScannerConfig, ScannerEventSourceMode};
use crate::scanner::index::ScannerCandidateIndex;
use crate::scanner::patterns::classify_opaque_tree;
use crate::scanner::walker::opaque_context_for_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventBackendKind {
    Fanotify,
    RecursiveInotify,
    ReconciliationOnly,
}

impl fmt::Display for EventBackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fanotify => f.write_str("fanotify"),
            Self::RecursiveInotify => f.write_str("recursive-inotify"),
            Self::ReconciliationOnly => f.write_str("reconciliation-only"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProbe {
    pub backend: EventBackendKind,
    pub available: bool,
    pub reason: String,
}

impl BackendProbe {
    #[cfg(target_os = "linux")]
    fn available(backend: EventBackendKind, reason: impl Into<String>) -> Self {
        Self {
            backend,
            available: true,
            reason: reason.into(),
        }
    }

    fn unavailable(backend: EventBackendKind, reason: impl Into<String>) -> Self {
        Self {
            backend,
            available: false,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSourceConfig {
    root_paths: Vec<PathBuf>,
    mode: ScannerEventSourceMode,
    watch_budget: usize,
}

impl EventSourceConfig {
    #[must_use]
    pub fn from_scanner_config(root_paths: &[PathBuf], scanner_config: &ScannerConfig) -> Self {
        let mut roots = root_paths.to_vec();
        roots.sort();
        roots.dedup();
        Self {
            root_paths: roots,
            mode: scanner_config.event_source,
            watch_budget: scanner_config.event_watch_budget,
        }
    }

    #[must_use]
    pub fn root_paths(&self) -> &[PathBuf] {
        &self.root_paths
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSourceCapability {
    pub selected_backend: EventBackendKind,
    pub complete: bool,
    pub watched_dirs: usize,
    /// Unwatched directories directly below a watched one; their subtrees
    /// are reconciled by scanning instead of by events.
    pub frontier_dirs: usize,
    pub dirty_roots: Vec<PathBuf>,
    pub reason: String,
    pub fanotify: BackendProbe,
    pub recursive_inotify: BackendProbe,
}

impl EventSourceCapability {
    fn from_plan(plan: &EventSourcePlan) -> Self {
        Self {
            selected_backend: plan.backend,
            complete: plan.complete,
            watched_dirs: plan.watched_dirs.len(),
            frontier_dirs: plan.frontier_dirs,
            dirty_roots: plan.dirty_roots.iter().cloned().collect(),
            reason: plan.reason.clone(),
            fanotify: fanotify_probe(),
            recursive_inotify: recursive_inotify_probe(plan.backend),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSourcePlan {
    pub backend: EventBackendKind,
    pub complete: bool,
    pub watched_dirs: Vec<PathBuf>,
    pub frontier_dirs: usize,
    pub dirty_roots: BTreeSet<PathBuf>,
    pub reason: String,
}

impl EventSourcePlan {
    #[must_use]
    pub fn for_config(config: &EventSourceConfig) -> Self {
        Self::with_rates(config, &EventRateTracker::default(), Instant::now())
    }

    /// Plan watches using observed per-directory event rates so a budget that
    /// cannot cover the tree lands on the hottest directories.
    #[must_use]
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    pub fn with_rates(config: &EventSourceConfig, rates: &EventRateTracker, now: Instant) -> Self {
        if config.mode == ScannerEventSourceMode::ReconciliationOnly {
            return Self::reconciliation_only(
                &config.root_paths,
                "scanner.event_source forces reconciliation-only",
            );
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::reconciliation_only(
                &config.root_paths,
                "safe kernel scanner event backend is unavailable on this platform",
            )
        }

        #[cfg(target_os = "linux")]
        {
            if config.watch_budget == 0 {
                return Self::reconciliation_only(
                    &config.root_paths,
                    "scanner.event_watch_budget is 0",
                );
            }
            Self::recursive_inotify(&config.root_paths, config.watch_budget, rates, now)
        }
    }

    fn reconciliation_only(root_paths: &[PathBuf], reason: impl Into<String>) -> Self {
        Self {
            backend: EventBackendKind::ReconciliationOnly,
            complete: false,
            watched_dirs: Vec::new(),
            frontier_dirs: 0,
            dirty_roots: root_paths.iter().cloned().collect(),
            reason: reason.into(),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn recursive_inotify(
        root_paths: &[PathBuf],
        watch_budget: usize,
        rates: &EventRateTracker,
        now: Instant,
    ) -> Self {
        let enumeration = enumerate_watch_candidates(root_paths, watch_budget, rates, now);
        let allocation = allocate_watches(&enumeration.candidates, watch_budget);

        let mut dirty_roots = enumeration.unreadable_roots.clone();
        dirty_roots.extend(allocation.unwatched_roots.iter().cloned());
        dirty_roots.extend(allocation.frontier.iter().cloned());
        // A directory whose children were never enumerated needs its subtree
        // reconciled, unless a dirty ancestor already covers it.
        for truncated in &enumeration.truncated {
            if !dirty_roots.iter().any(|dirty| truncated.starts_with(dirty)) {
                dirty_roots.insert(truncated.clone());
            }
        }

        let reason = if !enumeration.unreadable_roots.is_empty() {
            enumeration.reason
        } else if !allocation.unwatched_roots.is_empty() {
            "recursive inotify watch budget cannot cover the roots".to_string()
        } else if !allocation.frontier.is_empty() {
            format!(
                "recursive inotify watch budget exhausted: {} frontier directories rely on reconciliation",
                allocation.frontier.len()
            )
        } else if !enumeration.truncated.is_empty() {
            format!(
                "recursive inotify planning stopped enumerating after {} directories",
                enumeration.candidates.len()
            )
        } else {
            "recursive inotify plan covers all current directories".to_string()
        };

        Self {
            backend: if allocation.watched.is_empty() {
                EventBackendKind::ReconciliationOnly
            } else {
                EventBackendKind::RecursiveInotify
            },
            complete: dirty_roots.is_empty(),
            watched_dirs: allocation.watched,
            frontier_dirs: allocation.frontier.len(),
            dirty_roots,
            reason,
        }
    }
}

/// Directories enumerated per unit of watch budget before planning stops
/// descending. Subtrees below the enumeration cap rely on reconciliation.
const WATCH_PLAN_ENUMERATION_FACTOR: usize = 4;
/// Above this many unwatched frontier directories under one root, the root
/// itself is reconciled instead of thousands of tiny scan paths.
const MAX_FRONTIER_DIRS_PER_ROOT: usize = 256;
/// Time constant of the per-directory event-rate EWMA.
const EVENT_RATE_TAU: Duration = Duration::from_mins(10);
/// How often an incomplete plan is re-allocated by observed event rate.
const WATCH_REPLAN_INTERVAL: Duration = Duration::from_mins(15);
/// First overflow backoff window; doubles per consecutive overflow.
const OVERFLOW_BACKOFF_BASE: Duration = Duration::from_secs(30);
/// Cap on the overflow backoff window.
const OVERFLOW_BACKOFF_MAX: Duration = Duration::from_mins(30);
/// Time constant of the directory-mtime prior. A directory that has never
/// been watched cannot have an observed event rate, so a recent mtime stands
/// in for it: modified just now counts like one event just now.
const MTIME_PRIOR_TAU: Duration = Duration::from_hours(1);

/// Observed event rate for a directory, or the mtime prior when the
/// directory has been quiet or unwatched.
#[cfg(any(target_os = "linux", test))]
fn candidate_rate(
    rates: &EventRateTracker,
    path: &Path,
    now: Instant,
    metadata: &fs::Metadata,
    now_system: SystemTime,
) -> f64 {
    let observed = rates.rate(path, now);
    let prior = metadata
        .modified()
        .ok()
        .and_then(|modified| now_system.duration_since(modified).ok())
        .map_or(0.0, |age| {
            (-age.as_secs_f64() / MTIME_PRIOR_TAU.as_secs_f64()).exp()
                / EVENT_RATE_TAU.as_secs_f64()
        });
    observed.max(prior)
}

/// A directory the planner may spend a watch on.
#[derive(Debug, Clone, PartialEq)]
pub struct WatchCandidate {
    pub path: PathBuf,
    pub root: PathBuf,
    pub depth: usize,
    /// Observed event rate (events per second, EWMA); `0.0` when unknown.
    pub rate: f64,
}

/// Result of spending the watch budget over enumerated candidates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchAllocation {
    pub watched: Vec<PathBuf>,
    /// Unwatched directories whose parent is watched. Their subtrees rely on
    /// the reconciliation pass, so they become dirty scan paths.
    pub frontier: BTreeSet<PathBuf>,
    /// Roots that received no watch, or whose frontier exceeded the cap.
    pub unwatched_roots: BTreeSet<PathBuf>,
}

/// Spend `budget` watches: every root and depth-1 directory first (in path
/// order), then the remaining directories in decreasing observed event rate.
#[must_use]
pub fn allocate_watches(candidates: &[WatchCandidate], budget: usize) -> WatchAllocation {
    let mut mandatory: Vec<&WatchCandidate> = candidates.iter().filter(|c| c.depth <= 1).collect();
    mandatory.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.path.cmp(&b.path)));
    let mut optional: Vec<&WatchCandidate> = candidates.iter().filter(|c| c.depth > 1).collect();
    optional.sort_by(|a, b| {
        b.rate
            .total_cmp(&a.rate)
            .then_with(|| a.depth.cmp(&b.depth))
            .then_with(|| a.path.cmp(&b.path))
    });

    let mut watched_set = BTreeSet::new();
    let mut watched = Vec::new();
    for candidate in mandatory.into_iter().chain(optional) {
        if watched.len() >= budget {
            break;
        }
        if watched_set.insert(candidate.path.clone()) {
            watched.push(candidate.path.clone());
        }
    }

    let mut allocation = WatchAllocation {
        watched,
        ..WatchAllocation::default()
    };
    let mut frontier_per_root: BTreeMap<&Path, usize> = BTreeMap::new();
    for candidate in candidates {
        if watched_set.contains(&candidate.path) {
            continue;
        }
        if candidate.depth == 0 {
            allocation.unwatched_roots.insert(candidate.root.clone());
            continue;
        }
        let parent_watched = candidate
            .path
            .parent()
            .is_some_and(|parent| watched_set.contains(parent));
        if parent_watched && allocation.frontier.insert(candidate.path.clone()) {
            *frontier_per_root
                .entry(candidate.root.as_path())
                .or_default() += 1;
        }
    }
    for (root, count) in frontier_per_root {
        if count > MAX_FRONTIER_DIRS_PER_ROOT {
            allocation.frontier.retain(|path| !path.starts_with(root));
            allocation.unwatched_roots.insert(root.to_path_buf());
        }
    }
    allocation
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
struct WatchEnumeration {
    candidates: Vec<WatchCandidate>,
    /// Directories whose children were not listed because the enumeration
    /// cap was reached; their subtrees rely on reconciliation.
    truncated: BTreeSet<PathBuf>,
    unreadable_roots: BTreeSet<PathBuf>,
    reason: String,
}

/// Breadth-first directory enumeration bounded by the watch budget so that
/// planning never degenerates into a full tree walk.
#[cfg(any(target_os = "linux", test))]
fn enumerate_watch_candidates(
    root_paths: &[PathBuf],
    watch_budget: usize,
    rates: &EventRateTracker,
    now: Instant,
) -> WatchEnumeration {
    let cap = watch_budget
        .saturating_mul(WATCH_PLAN_ENUMERATION_FACTOR)
        .max(1);
    let now_system = SystemTime::now();
    let mut enumeration = WatchEnumeration::default();

    for root in root_paths {
        let metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(err) => {
                enumeration.unreadable_roots.insert(root.clone());
                enumeration.reason =
                    format!("root metadata unavailable for {}: {err}", root.display());
                continue;
            }
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            enumeration.unreadable_roots.insert(root.clone());
            enumeration.reason = format!("root is not a plain directory: {}", root.display());
            continue;
        }

        enumeration.candidates.push(WatchCandidate {
            path: root.clone(),
            root: root.clone(),
            depth: 0,
            rate: candidate_rate(rates, root, now, &metadata, now_system),
        });
        let mut queue = VecDeque::from([(root.clone(), 0usize)]);
        while let Some((dir, depth)) = queue.pop_front() {
            if enumeration.candidates.len() >= cap {
                enumeration.truncated.insert(dir);
                continue;
            }
            let Ok(entries) = sorted_child_paths(&dir) else {
                enumeration.truncated.insert(dir);
                continue;
            };
            for child in entries {
                let Ok(metadata) = fs::symlink_metadata(&child) else {
                    enumeration.truncated.insert(dir.clone());
                    continue;
                };
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    continue;
                }
                enumeration.candidates.push(WatchCandidate {
                    path: child.clone(),
                    root: root.clone(),
                    depth: depth + 1,
                    rate: candidate_rate(rates, &child, now, &metadata, now_system),
                });
                queue.push_back((child, depth + 1));
            }
        }
    }
    enumeration
}

/// Per-directory EWMA of the filesystem event rate, keyed by the watched
/// directory an event was delivered on. Bounded by the watch budget because
/// only watched directories ever receive events.
#[derive(Debug, Default)]
pub struct EventRateTracker {
    rates: BTreeMap<PathBuf, RateSample>,
    events_since_plan: u64,
}

#[derive(Debug, Clone, Copy)]
struct RateSample {
    value: f64,
    updated: Instant,
}

impl EventRateTracker {
    pub fn record(&mut self, dir: &Path, now: Instant) {
        let tau = EVENT_RATE_TAU.as_secs_f64();
        let sample = self.rates.entry(dir.to_path_buf()).or_insert(RateSample {
            value: 0.0,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(sample.updated).as_secs_f64();
        sample.value = (-elapsed / tau).exp().mul_add(sample.value, 1.0 / tau);
        sample.updated = now;
        self.events_since_plan = self.events_since_plan.saturating_add(1);
    }

    /// Smoothed events per second for `dir`, decayed to `now`.
    #[must_use]
    pub fn rate(&self, dir: &Path, now: Instant) -> f64 {
        self.rates.get(dir).map_or(0.0, |sample| {
            let elapsed = now.saturating_duration_since(sample.updated).as_secs_f64();
            sample.value * (-elapsed / EVENT_RATE_TAU.as_secs_f64()).exp()
        })
    }

    #[must_use]
    pub fn tracked_dirs(&self) -> usize {
        self.rates.len()
    }

    #[must_use]
    pub fn events_since_plan(&self) -> u64 {
        self.events_since_plan
    }

    /// Forget directories that are no longer watched and reset the
    /// since-plan counter after a replan.
    pub fn retain_watched(&mut self, watched: &[PathBuf]) {
        let keep: BTreeSet<&Path> = watched.iter().map(PathBuf::as_path).collect();
        self.rates.retain(|path, _| keep.contains(path.as_path()));
        self.events_since_plan = 0;
    }
}

/// Exponential backoff of overflow-driven reconciliation.
///
/// The first overflow reconciles immediately; overflows arriving inside the
/// backoff window are coalesced into one deferred reconciliation when the
/// window expires, and each consecutive overflow doubles the window up to
/// the cap.
#[derive(Debug, Default)]
pub struct OverflowBackoff {
    consecutive: u32,
    window: Duration,
    suppress_until: Option<Instant>,
    deferred: bool,
    total: u64,
    coalesced: u64,
}

/// What the event source should do about an overflow right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowDecision {
    /// Reconcile everything now; the window is the backoff that follows.
    Reconcile { window: Duration },
    /// Inside the backoff window: count it and reconcile when the window ends.
    Coalesced { remaining: Duration },
}

impl OverflowBackoff {
    pub fn record(&mut self, now: Instant) -> OverflowDecision {
        self.total = self.total.saturating_add(1);
        if let Some(until) = self.suppress_until
            && until > now
        {
            self.coalesced = self.coalesced.saturating_add(1);
            self.deferred = true;
            return OverflowDecision::Coalesced {
                remaining: until.saturating_duration_since(now),
            };
        }
        let quiet_for = self
            .suppress_until
            .map_or(Duration::MAX, |until| now.saturating_duration_since(until));
        if quiet_for >= self.window.saturating_mul(2) {
            self.consecutive = 0;
        }
        self.consecutive = self.consecutive.saturating_add(1);
        let shift = self.consecutive.saturating_sub(1).min(16);
        self.window = OVERFLOW_BACKOFF_BASE
            .saturating_mul(1u32 << shift)
            .min(OVERFLOW_BACKOFF_MAX);
        self.suppress_until = Some(now + self.window);
        self.deferred = false;
        OverflowDecision::Reconcile {
            window: self.window,
        }
    }

    /// Returns `true` once when a coalesced overflow's deferred
    /// reconciliation becomes due.
    pub fn take_deferred(&mut self, now: Instant) -> bool {
        if self.deferred && self.suppress_until.is_none_or(|until| until <= now) {
            self.deferred = false;
            return true;
        }
        false
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    #[must_use]
    pub fn coalesced(&self) -> u64 {
        self.coalesced
    }

    #[must_use]
    pub fn current_window(&self) -> Duration {
        self.window
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsEventKind {
    Create,
    Modify,
    Remove,
    Rename,
    Overflow,
    BackendRestart,
    PermissionLost,
    WatchBudgetExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEvent {
    pub kind: FsEventKind,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventInvalidation {
    dirty_roots: BTreeSet<PathBuf>,
    dirty_paths: BTreeSet<PathBuf>,
    generation_bump: bool,
    reasons: BTreeSet<String>,
}

impl EventInvalidation {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            dirty_roots: BTreeSet::new(),
            dirty_paths: BTreeSet::new(),
            generation_bump: false,
            reasons: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn dirty_roots(&self) -> &BTreeSet<PathBuf> {
        &self.dirty_roots
    }

    #[must_use]
    pub fn dirty_paths(&self) -> &BTreeSet<PathBuf> {
        &self.dirty_paths
    }

    #[must_use]
    pub fn requires_reconciliation(&self) -> bool {
        !self.dirty_roots.is_empty()
    }

    #[must_use]
    pub fn requires_index_generation_bump(&self) -> bool {
        self.generation_bump
    }

    #[must_use]
    pub fn reason_summary(&self) -> String {
        self.reasons.iter().cloned().collect::<Vec<_>>().join("; ")
    }

    pub fn apply_to_index(&self, index: &mut ScannerCandidateIndex) {
        if self.requires_index_generation_bump() {
            index.mark_event_overflow();
        }
    }

    /// Subtrees a plan cannot watch are reconciled once now and bump the
    /// index generation, because changes under them arrive without events.
    fn mark_plan_gaps(&mut self, plan: &EventSourcePlan) {
        if plan.complete {
            return;
        }
        self.dirty_roots.extend(plan.dirty_roots.iter().cloned());
        self.reasons.insert(plan.reason.clone());
        self.generation_bump = true;
    }

    fn mark_dirty_root(&mut self, root: PathBuf, reason: impl Into<String>) {
        self.dirty_roots.insert(root);
        self.reasons.insert(reason.into());
    }

    /// Record a changed path. The scan path it implies is resolved once per
    /// drain by [`Self::resolve_scan_roots`]; a path under no configured
    /// root reconciles everything.
    fn mark_dirty_path(&mut self, roots: &[PathBuf], path: &Path, reason: impl Into<String>) {
        let reason = reason.into();
        self.dirty_paths.insert(path.to_path_buf());
        if root_for_path(roots, path).is_some() {
            self.reasons.insert(reason);
        } else {
            self.mark_all_roots(roots, reason, true);
        }
    }

    /// Turn the dirty paths into scan paths: the project directory directly
    /// below the configured root that contains the change, so a Green or
    /// Yellow pass walks one project instead of the whole root. The root
    /// itself is used when the change sits at the root, when the project
    /// directory is itself an artifact (the walker evaluates a scan path's
    /// children, never the path), or when one root has more than
    /// [`MAX_EVENT_SCAN_PATHS_PER_ROOT`] distinct projects to reconcile.
    /// Scan paths under another dirty scan path are dropped.
    pub fn resolve_scan_roots(&mut self, roots: &[PathBuf]) {
        let mut per_root: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
        let mut memo: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
        for path in &self.dirty_paths {
            let Some(root) = root_for_path(roots, path) else {
                continue;
            };
            let scan_root = event_scan_root(&root, path, &mut memo);
            per_root.entry(root).or_default().insert(scan_root);
        }
        for (root, scan_roots) in per_root {
            if scan_roots.len() > MAX_EVENT_SCAN_PATHS_PER_ROOT || scan_roots.contains(&root) {
                self.dirty_roots.insert(root);
            } else {
                self.dirty_roots.extend(scan_roots);
            }
        }
        let covered: Vec<PathBuf> = self
            .dirty_roots
            .iter()
            .filter(|path| {
                self.dirty_roots
                    .iter()
                    .any(|other| other.as_path() != path.as_path() && path.starts_with(other))
            })
            .cloned()
            .collect();
        for path in covered {
            self.dirty_roots.remove(&path);
        }
    }

    fn mark_all_roots(
        &mut self,
        roots: &[PathBuf],
        reason: impl Into<String>,
        generation_bump: bool,
    ) {
        self.dirty_roots.extend(roots.iter().cloned());
        self.reasons.insert(reason.into());
        self.generation_bump |= generation_bump;
    }

    pub fn merge(&mut self, other: Self) {
        self.dirty_roots.extend(other.dirty_roots);
        self.dirty_paths.extend(other.dirty_paths);
        self.generation_bump |= other.generation_bump;
        self.reasons.extend(other.reasons);
    }
}

#[derive(Debug, Clone)]
pub struct DirtyRootTracker {
    roots: Vec<PathBuf>,
}

impl DirtyRootTracker {
    #[must_use]
    pub fn new(root_paths: &[PathBuf]) -> Self {
        let mut roots = root_paths.to_vec();
        roots.sort();
        roots.dedup();
        Self { roots }
    }

    #[must_use]
    pub fn apply_event(&self, event: FsEvent) -> EventInvalidation {
        let mut invalidation = EventInvalidation::empty();
        match event.kind {
            FsEventKind::Overflow | FsEventKind::BackendRestart | FsEventKind::PermissionLost => {
                invalidation.mark_all_roots(&self.roots, format!("{:?}", event.kind), true);
            }
            FsEventKind::WatchBudgetExceeded => {
                // The new directory sits directly below a watched one: it is a
                // frontier subtree, reconciled by scanning it, not the root.
                if let Some(path) = event.path {
                    invalidation.mark_dirty_root(path, format!("{:?}", event.kind));
                } else {
                    invalidation.mark_all_roots(&self.roots, format!("{:?}", event.kind), true);
                }
            }
            FsEventKind::Create
            | FsEventKind::Modify
            | FsEventKind::Remove
            | FsEventKind::Rename => {
                if let Some(path) = event.path {
                    invalidation.mark_dirty_path(&self.roots, &path, format!("{:?}", event.kind));
                } else {
                    invalidation.mark_all_roots(&self.roots, format!("{:?}", event.kind), true);
                }
            }
        }
        invalidation
    }
}

/// Live counters of the event source for telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventSourceStats {
    pub overflows: u64,
    pub coalesced_overflows: u64,
    pub backoff_secs: u64,
    pub replans: u64,
    pub watched_dirs: usize,
    pub frontier_dirs: usize,
    pub rate_tracked_dirs: usize,
}

#[derive(Debug)]
pub struct ScannerEventSource {
    config: EventSourceConfig,
    capability: EventSourceCapability,
    #[cfg(target_os = "linux")]
    tracker: DirtyRootTracker,
    backend: EventSourceBackend,
    pending: EventInvalidation,
    rates: EventRateTracker,
    backoff: OverflowBackoff,
    planned_at: Instant,
    replans: u64,
}

impl ScannerEventSource {
    #[must_use]
    pub fn start(config: EventSourceConfig) -> Self {
        Self::start_at(config, Instant::now())
    }

    #[must_use]
    pub fn start_at(config: EventSourceConfig, now: Instant) -> Self {
        #[cfg(target_os = "linux")]
        let tracker = DirtyRootTracker::new(config.root_paths());
        let rates = EventRateTracker::default();
        let plan = EventSourcePlan::with_rates(&config, &rates, now);
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut capability = EventSourceCapability::from_plan(&plan);
        let mut pending = EventInvalidation::empty();
        pending.mark_plan_gaps(&plan);

        let backend = match plan.backend {
            EventBackendKind::RecursiveInotify => {
                #[cfg(target_os = "linux")]
                {
                    match LinuxInotifyBackend::start(&plan.watched_dirs, config.watch_budget) {
                        Ok(backend) => EventSourceBackend::RecursiveInotify(backend),
                        Err(err) => {
                            capability.selected_backend = EventBackendKind::ReconciliationOnly;
                            capability.complete = false;
                            capability.reason = format!("recursive inotify unavailable: {err}");
                            pending.mark_all_roots(
                                config.root_paths(),
                                capability.reason.clone(),
                                true,
                            );
                            EventSourceBackend::ReconciliationOnly
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    EventSourceBackend::ReconciliationOnly
                }
            }
            EventBackendKind::Fanotify | EventBackendKind::ReconciliationOnly => {
                EventSourceBackend::ReconciliationOnly
            }
        };

        Self {
            config,
            capability,
            #[cfg(target_os = "linux")]
            tracker,
            backend,
            pending,
            rates,
            backoff: OverflowBackoff::default(),
            planned_at: now,
            replans: 0,
        }
    }

    #[must_use]
    pub fn matches_config(&self, config: &EventSourceConfig) -> bool {
        &self.config == config
    }

    #[must_use]
    pub fn capability(&self) -> &EventSourceCapability {
        &self.capability
    }

    #[must_use]
    pub fn stats(&self) -> EventSourceStats {
        EventSourceStats {
            overflows: self.backoff.total(),
            coalesced_overflows: self.backoff.coalesced(),
            backoff_secs: self.backoff.current_window().as_secs(),
            replans: self.replans,
            watched_dirs: self.capability.watched_dirs,
            frontier_dirs: self.capability.frontier_dirs,
            rate_tracked_dirs: self.rates.tracked_dirs(),
        }
    }

    pub fn drain(&mut self) -> EventInvalidation {
        self.drain_at(Instant::now())
    }

    pub fn drain_at(&mut self, now: Instant) -> EventInvalidation {
        let mut invalidation = std::mem::replace(&mut self.pending, EventInvalidation::empty());
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            EventSourceBackend::RecursiveInotify(backend) => {
                invalidation.merge(backend.drain(
                    &self.tracker,
                    &self.config,
                    &mut self.rates,
                    &mut self.backoff,
                    now,
                ));
            }
            EventSourceBackend::ReconciliationOnly => {}
        }
        if self.backoff.take_deferred(now) {
            invalidation.mark_all_roots(
                self.config.root_paths(),
                "Overflow (deferred by backoff)",
                true,
            );
        }
        if self.should_replan(now) {
            invalidation.merge(self.replan(now));
        }
        invalidation.resolve_scan_roots(self.config.root_paths());
        invalidation
    }

    /// Overflows the backend reported so far, including coalesced ones.
    #[must_use]
    pub fn overflow_backoff(&self) -> &OverflowBackoff {
        &self.backoff
    }

    /// Feed an overflow observed outside the backend (tests and the
    /// reconciliation-only backend share the same backoff policy).
    pub fn note_overflow(&mut self, now: Instant) -> EventInvalidation {
        match self.backoff.record(now) {
            OverflowDecision::Reconcile { .. } => {
                let mut invalidation = EventInvalidation::empty();
                invalidation.mark_all_roots(self.config.root_paths(), "Overflow", true);
                invalidation
            }
            OverflowDecision::Coalesced { .. } => EventInvalidation::empty(),
        }
    }

    fn should_replan(&self, now: Instant) -> bool {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = now;
            false
        }
        #[cfg(target_os = "linux")]
        {
            matches!(self.backend, EventSourceBackend::RecursiveInotify(_))
                && !self.capability.complete
                && now.saturating_duration_since(self.planned_at) >= WATCH_REPLAN_INTERVAL
                && self.rates.events_since_plan() > 0
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn replan(&mut self, _now: Instant) -> EventInvalidation {
        EventInvalidation::empty()
    }

    /// Re-spend the watch budget by observed event rate. The new backend is
    /// started before the old one is dropped, so no events are lost; the new
    /// frontier is reconciled once.
    #[cfg(target_os = "linux")]
    fn replan(&mut self, now: Instant) -> EventInvalidation {
        let plan = EventSourcePlan::with_rates(&self.config, &self.rates, now);
        let mut invalidation = EventInvalidation::empty();
        self.planned_at = now;
        self.replans = self.replans.saturating_add(1);

        let current: BTreeSet<&Path> = match &self.backend {
            EventSourceBackend::RecursiveInotify(backend) => backend.watched_dirs().collect(),
            EventSourceBackend::ReconciliationOnly => BTreeSet::new(),
        };
        let planned: BTreeSet<&Path> = plan.watched_dirs.iter().map(PathBuf::as_path).collect();
        if plan.backend != EventBackendKind::RecursiveInotify {
            self.backend = EventSourceBackend::ReconciliationOnly;
            self.capability = EventSourceCapability::from_plan(&plan);
            invalidation.mark_all_roots(self.config.root_paths(), plan.reason, true);
            return invalidation;
        }
        if current != planned {
            match LinuxInotifyBackend::start(&plan.watched_dirs, self.config.watch_budget) {
                Ok(backend) => self.backend = EventSourceBackend::RecursiveInotify(backend),
                Err(err) => {
                    invalidation.mark_all_roots(
                        self.config.root_paths(),
                        format!("recursive inotify replan failed: {err}"),
                        true,
                    );
                    return invalidation;
                }
            }
        }
        self.rates.retain_watched(&plan.watched_dirs);
        for path in &plan.dirty_roots {
            invalidation.mark_dirty_root(path.clone(), plan.reason.clone());
        }
        self.capability = EventSourceCapability::from_plan(&plan);
        invalidation
    }
}

#[derive(Debug)]
enum EventSourceBackend {
    #[cfg(target_os = "linux")]
    RecursiveInotify(LinuxInotifyBackend),
    ReconciliationOnly,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxInotifyBackend {
    inotify: inotify::Inotify,
    watch_paths: BTreeMap<inotify::WatchDescriptor, PathBuf>,
    buffer: Vec<u8>,
    max_watches: usize,
}

#[cfg(target_os = "linux")]
impl LinuxInotifyBackend {
    fn start(paths: &[PathBuf], max_watches: usize) -> std::io::Result<Self> {
        let inotify = inotify::Inotify::init()?;
        let mut backend = Self {
            inotify,
            watch_paths: BTreeMap::new(),
            buffer: vec![0; 64 * 1024],
            max_watches,
        };
        for path in paths {
            backend.add_watch(path)?;
        }
        Ok(backend)
    }

    fn watched_dirs(&self) -> impl Iterator<Item = &Path> {
        self.watch_paths.values().map(PathBuf::as_path)
    }

    fn drain(
        &mut self,
        tracker: &DirtyRootTracker,
        config: &EventSourceConfig,
        rates: &mut EventRateTracker,
        backoff: &mut OverflowBackoff,
        now: Instant,
    ) -> EventInvalidation {
        use std::io::ErrorKind;

        let mut invalidation = EventInvalidation::empty();
        loop {
            let events = match self.read_available_events() {
                Ok(events) => events,
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => {
                    invalidation.mark_all_roots(
                        config.root_paths(),
                        format!("recursive inotify read failed: {err}"),
                        true,
                    );
                    break;
                }
            };
            if events.is_empty() {
                break;
            }
            for event in events {
                invalidation.merge(self.handle_event(tracker, config, rates, backoff, now, &event));
            }
        }
        invalidation
    }

    fn read_available_events(&mut self) -> std::io::Result<Vec<LinuxInotifyEvent>> {
        let events = self.inotify.read_events(&mut self.buffer)?;
        Ok(events
            .map(|event| LinuxInotifyEvent {
                watch: event.wd,
                mask: event.mask,
                name: event.name.map(PathBuf::from),
            })
            .collect())
    }

    fn handle_event(
        &mut self,
        tracker: &DirtyRootTracker,
        config: &EventSourceConfig,
        rates: &mut EventRateTracker,
        backoff: &mut OverflowBackoff,
        now: Instant,
        event: &LinuxInotifyEvent,
    ) -> EventInvalidation {
        use inotify::EventMask;

        if event.mask.contains(EventMask::Q_OVERFLOW) {
            return match backoff.record(now) {
                OverflowDecision::Reconcile { .. } => tracker.apply_event(FsEvent {
                    kind: FsEventKind::Overflow,
                    path: None,
                }),
                OverflowDecision::Coalesced { .. } => EventInvalidation::empty(),
            };
        }

        if let Some(base) = self.watch_paths.get(&event.watch) {
            rates.record(base, now);
        }
        let path = self.path_for_event(event);
        let mut invalidation = if event.mask.intersects(
            EventMask::IGNORED | EventMask::UNMOUNT | EventMask::DELETE_SELF | EventMask::MOVE_SELF,
        ) {
            tracker.apply_event(FsEvent {
                kind: FsEventKind::PermissionLost,
                path: path.clone(),
            })
        } else {
            tracker.apply_event(FsEvent {
                kind: event_kind_from_inotify_mask(event.mask),
                path: path.clone(),
            })
        };

        if event.mask.contains(EventMask::ISDIR)
            && event
                .mask
                .intersects(EventMask::CREATE | EventMask::MOVED_TO)
            && let Some(path) = path
        {
            if self.watch_paths.len() >= self.max_watches {
                invalidation.merge(tracker.apply_event(FsEvent {
                    kind: FsEventKind::WatchBudgetExceeded,
                    path: Some(path),
                }));
            } else if let Err(err) = self.add_watch(&path) {
                invalidation.mark_dirty_path(
                    config.root_paths(),
                    &path,
                    format!("recursive inotify add-watch failed: {err}"),
                );
                invalidation.generation_bump = true;
            }
        }

        invalidation
    }

    fn path_for_event(&self, event: &LinuxInotifyEvent) -> Option<PathBuf> {
        let base = self.watch_paths.get(&event.watch)?;
        Some(
            event
                .name
                .as_ref()
                .map_or_else(|| base.clone(), |name| base.join(name)),
        )
    }

    fn add_watch(&mut self, path: &Path) -> std::io::Result<()> {
        let watch = self.inotify.watches().add(path, inotify_watch_mask())?;
        self.watch_paths.insert(watch, path.to_path_buf());
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxInotifyEvent {
    watch: inotify::WatchDescriptor,
    mask: inotify::EventMask,
    name: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn inotify_watch_mask() -> inotify::WatchMask {
    use inotify::WatchMask;
    WatchMask::ATTRIB
        | WatchMask::CLOSE_WRITE
        | WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::DELETE_SELF
        | WatchMask::DONT_FOLLOW
        | WatchMask::EXCL_UNLINK
        | WatchMask::MODIFY
        | WatchMask::MOVE
        | WatchMask::MOVE_SELF
        | WatchMask::ONLYDIR
}

#[cfg(target_os = "linux")]
fn event_kind_from_inotify_mask(mask: inotify::EventMask) -> FsEventKind {
    use inotify::EventMask;
    if mask.intersects(EventMask::DELETE | EventMask::DELETE_SELF) {
        FsEventKind::Remove
    } else if mask.intersects(EventMask::MOVED_FROM | EventMask::MOVED_TO | EventMask::MOVE_SELF) {
        FsEventKind::Rename
    } else if mask.contains(EventMask::CREATE) {
        FsEventKind::Create
    } else {
        FsEventKind::Modify
    }
}

#[cfg(any(target_os = "linux", test))]
fn sorted_child_paths(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(path)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

/// Distinct project scan paths one root may carry per drain before the
/// whole root is reconciled instead.
const MAX_EVENT_SCAN_PATHS_PER_ROOT: usize = 64;

/// The scan path for a change at `path` under `root`: the depth-1 directory
/// containing it, unless the change is at depth ≤ 1 or that directory is an
/// opaque artifact tree itself, in which case the root. `memo` caches the
/// classification per depth-1 directory for one drain.
fn event_scan_root(root: &Path, path: &Path, memo: &mut BTreeMap<PathBuf, PathBuf>) -> PathBuf {
    let Ok(relative) = path.strip_prefix(root) else {
        return root.to_path_buf();
    };
    let mut components = relative.components();
    let Some(first) = components.next() else {
        return root.to_path_buf();
    };
    if components.next().is_none() {
        return root.to_path_buf();
    }
    let project = root.join(first.as_os_str());
    memo.entry(project.clone())
        .or_insert_with(|| {
            let is_artifact =
                classify_opaque_tree(&project, opaque_context_for_path(&project)).is_some();
            if is_artifact {
                root.to_path_buf()
            } else {
                project.clone()
            }
        })
        .clone()
}

fn root_for_path(roots: &[PathBuf], path: &Path) -> Option<PathBuf> {
    roots
        .iter()
        .find(|root| path == root.as_path() || path.starts_with(root))
        .cloned()
}

fn fanotify_probe() -> BackendProbe {
    BackendProbe::unavailable(
        EventBackendKind::Fanotify,
        "deferred: no safe fanotify backend is wired into the unsafe-forbidden crate",
    )
}

fn recursive_inotify_probe(selected_backend: EventBackendKind) -> BackendProbe {
    #[cfg(target_os = "linux")]
    {
        if selected_backend == EventBackendKind::RecursiveInotify {
            BackendProbe::available(
                EventBackendKind::RecursiveInotify,
                "safe inotify crate selected with recursive watch planning",
            )
        } else {
            BackendProbe::unavailable(
                EventBackendKind::RecursiveInotify,
                "recursive inotify was not selected",
            )
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = selected_backend;
        BackendProbe::unavailable(EventBackendKind::RecursiveInotify, "inotify is Linux-only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn event_config(root_paths: &[PathBuf], watch_budget: usize) -> EventSourceConfig {
        let scanner_config = ScannerConfig {
            event_watch_budget: watch_budget,
            ..Default::default()
        };
        EventSourceConfig::from_scanner_config(root_paths, &scanner_config)
    }

    #[test]
    fn recursive_plan_covers_nested_directories_within_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("a")).unwrap();
        fs::create_dir(root.join("a").join("b")).unwrap();

        let plan = EventSourcePlan::recursive_inotify(
            std::slice::from_ref(&root),
            8,
            &EventRateTracker::default(),
            Instant::now(),
        );

        assert!(plan.complete);
        assert_eq!(plan.backend, EventBackendKind::RecursiveInotify);
        assert!(plan.watched_dirs.contains(&root));
        assert!(plan.watched_dirs.contains(&root.join("a")));
        assert!(plan.watched_dirs.contains(&root.join("a").join("b")));
        assert!(plan.dirty_roots.is_empty());
        assert_eq!(plan.frontier_dirs, 0);
    }

    #[test]
    fn watch_budget_exhaustion_marks_the_frontier_dirty_not_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("a")).unwrap();
        fs::create_dir(root.join("a").join("b")).unwrap();
        fs::create_dir(root.join("c")).unwrap();

        // Budget 1: only the root is watched; `a` and `c` are the frontier.
        let plan = EventSourcePlan::recursive_inotify(
            std::slice::from_ref(&root),
            1,
            &EventRateTracker::default(),
            Instant::now(),
        );

        assert!(!plan.complete);
        assert_eq!(plan.backend, EventBackendKind::RecursiveInotify);
        assert_eq!(plan.watched_dirs, vec![root.clone()]);
        assert_eq!(plan.frontier_dirs, 2);
        assert!(!plan.dirty_roots.contains(&root));
        assert!(plan.dirty_roots.contains(&root.join("a")));
        assert!(plan.dirty_roots.contains(&root.join("c")));
        assert!(!plan.dirty_roots.contains(&root.join("a").join("b")));

        // Budget 3: root and both depth-1 dirs are mandatory; `a/b` is frontier.
        let plan = EventSourcePlan::recursive_inotify(
            std::slice::from_ref(&root),
            3,
            &EventRateTracker::default(),
            Instant::now(),
        );
        assert_eq!(plan.watched_dirs.len(), 3);
        assert_eq!(
            plan.dirty_roots.iter().cloned().collect::<Vec<_>>(),
            vec![root.join("a").join("b")]
        );
    }

    #[test]
    fn hot_directories_win_the_remaining_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let cold = root.join("a").join("cold");
        let hot = root.join("b").join("hot");
        fs::create_dir_all(&cold).unwrap();
        fs::create_dir_all(&hot).unwrap();

        let now = Instant::now();
        let mut rates = EventRateTracker::default();
        for _ in 0..50 {
            rates.record(&hot, now);
        }
        rates.record(&cold, now);
        assert!(rates.rate(&hot, now) > rates.rate(&cold, now));

        // Budget 4 = root + a + b + one depth-2 directory: the hot one.
        let plan = EventSourcePlan::recursive_inotify(std::slice::from_ref(&root), 4, &rates, now);

        assert!(plan.watched_dirs.contains(&hot));
        assert!(!plan.watched_dirs.contains(&cold));
        assert_eq!(
            plan.dirty_roots.iter().cloned().collect::<Vec<_>>(),
            vec![cold.clone()]
        );

        // Rates decay: after several time constants the two are equal again.
        let later = now + EVENT_RATE_TAU * 40;
        assert!(rates.rate(&hot, later) < 1e-9);
    }

    #[test]
    fn overflow_backoff_reconciles_first_then_coalesces_and_doubles() {
        let mut backoff = OverflowBackoff::default();
        let t0 = Instant::now();

        assert_eq!(
            backoff.record(t0),
            OverflowDecision::Reconcile {
                window: OVERFLOW_BACKOFF_BASE
            }
        );
        // Inside the window: coalesced, counted, deferred.
        assert!(matches!(
            backoff.record(t0 + Duration::from_secs(5)),
            OverflowDecision::Coalesced { .. }
        ));
        assert_eq!(backoff.total(), 2);
        assert_eq!(backoff.coalesced(), 1);
        assert!(!backoff.take_deferred(t0 + Duration::from_secs(6)));
        assert!(backoff.take_deferred(t0 + OVERFLOW_BACKOFF_BASE));
        assert!(!backoff.take_deferred(t0 + OVERFLOW_BACKOFF_BASE));

        // The next overflow right after the window doubles it.
        let t1 = t0 + OVERFLOW_BACKOFF_BASE + Duration::from_secs(1);
        assert_eq!(
            backoff.record(t1),
            OverflowDecision::Reconcile {
                window: OVERFLOW_BACKOFF_BASE * 2
            }
        );
        let t2 = t1 + OVERFLOW_BACKOFF_BASE * 2 + Duration::from_secs(1);
        assert_eq!(
            backoff.record(t2),
            OverflowDecision::Reconcile {
                window: OVERFLOW_BACKOFF_BASE * 4
            }
        );
        // Windows are capped.
        let mut t = t2;
        for _ in 0..20 {
            t += backoff.current_window() + Duration::from_secs(1);
            backoff.record(t);
        }
        assert_eq!(backoff.current_window(), OVERFLOW_BACKOFF_MAX);

        // A long quiet period resets the streak to the base window.
        let quiet = t + OVERFLOW_BACKOFF_MAX * 3;
        assert_eq!(
            backoff.record(quiet),
            OverflowDecision::Reconcile {
                window: OVERFLOW_BACKOFF_BASE
            }
        );
    }

    #[test]
    fn event_source_overflow_bumps_generation_then_backs_off() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let scanner_config = ScannerConfig {
            event_source: ScannerEventSourceMode::ReconciliationOnly,
            ..Default::default()
        };
        let config =
            EventSourceConfig::from_scanner_config(std::slice::from_ref(&root), &scanner_config);
        let t0 = Instant::now();
        let mut source = ScannerEventSource::start_at(config, t0);
        let _startup = source.drain_at(t0);

        let first = source.note_overflow(t0 + Duration::from_secs(1));
        assert!(first.requires_index_generation_bump());
        assert!(first.dirty_roots().contains(&root));

        let second = source.note_overflow(t0 + Duration::from_secs(2));
        assert!(!second.requires_reconciliation());
        assert!(!second.requires_index_generation_bump());
        assert_eq!(source.stats().overflows, 2);
        assert_eq!(source.stats().coalesced_overflows, 1);
        assert_eq!(source.stats().backoff_secs, OVERFLOW_BACKOFF_BASE.as_secs());

        // Still inside the window: nothing is reconciled yet.
        let quiet = source.drain_at(t0 + Duration::from_secs(10));
        assert!(!quiet.requires_reconciliation());
        // When the window ends the coalesced overflow reconciles once.
        let due = source.drain_at(t0 + Duration::from_secs(1) + OVERFLOW_BACKOFF_BASE);
        assert!(due.requires_index_generation_bump());
        assert!(due.dirty_roots().contains(&root));
        assert!(due.reason_summary().contains("deferred"));
        let after = source.drain_at(t0 + Duration::from_secs(2) + OVERFLOW_BACKOFF_BASE);
        assert!(!after.requires_reconciliation());
    }

    fn candidate(path: &str, root: &str, depth: usize, rate: f64) -> WatchCandidate {
        WatchCandidate {
            path: PathBuf::from(path),
            root: PathBuf::from(root),
            depth,
            rate,
        }
    }

    #[test]
    fn allocation_caps_the_frontier_per_root() {
        let mut candidates = vec![candidate("/r", "/r", 0, 0.0)];
        for i in 0..=MAX_FRONTIER_DIRS_PER_ROOT {
            candidates.push(candidate(&format!("/r/d{i}"), "/r", 1, 0.0));
        }
        let allocation = allocate_watches(&candidates, 1);
        assert_eq!(allocation.watched, vec![PathBuf::from("/r")]);
        assert!(allocation.frontier.is_empty());
        assert!(allocation.unwatched_roots.contains(Path::new("/r")));

        // Zero budget: the root itself is unwatched.
        let allocation = allocate_watches(&candidates, 0);
        assert!(allocation.watched.is_empty());
        assert!(allocation.unwatched_roots.contains(Path::new("/r")));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Never exceeds the budget; every root and depth-1 directory is
        /// watched whenever the budget can hold them; every unwatched
        /// directory is covered by exactly one frontier entry or an
        /// unwatched root above it.
        #[test]
        fn allocation_respects_budget_and_mandatory_set(
            shape in proptest::collection::vec((0usize..4, 0usize..3), 1..40),
            roots in 1usize..3,
            budget in 0usize..48,
        ) {
            // Build a synthetic tree: each shape entry adds a directory under a
            // pseudo-random existing parent.
            let mut candidates: Vec<WatchCandidate> = Vec::new();
            for r in 0..roots {
                candidates.push(candidate(&format!("/root{r}"), &format!("/root{r}"), 0, 0.0));
            }
            for (i, (parent_pick, rate_pick)) in shape.iter().enumerate() {
                let parent = candidates[(i * 7 + parent_pick) % candidates.len()].clone();
                let path = parent.path.join(format!("d{i}"));
                let rate = f64::from(u8::try_from(*rate_pick).unwrap_or(0));
                candidates.push(WatchCandidate {
                    path,
                    root: parent.root.clone(),
                    depth: parent.depth + 1,
                    rate,
                });
            }

            let allocation = allocate_watches(&candidates, budget);
            let watched: BTreeSet<&Path> = allocation.watched.iter().map(PathBuf::as_path).collect();

            proptest::prop_assert!(allocation.watched.len() <= budget);
            proptest::prop_assert_eq!(watched.len(), allocation.watched.len(), "no duplicate watches");

            let mandatory: Vec<&WatchCandidate> = candidates.iter().filter(|c| c.depth <= 1).collect();
            if mandatory.len() <= budget {
                for c in &mandatory {
                    proptest::prop_assert!(watched.contains(c.path.as_path()), "mandatory {:?} unwatched", c.path);
                }
            } else {
                // Roots come first even when depth-1 cannot fit.
                let watched_roots = candidates.iter().filter(|c| c.depth == 0 && watched.contains(c.path.as_path())).count();
                proptest::prop_assert_eq!(watched_roots, roots.min(budget));
            }

            // A depth-2+ directory is never watched while a mandatory one is not.
            let optional_watched = candidates.iter().any(|c| c.depth > 1 && watched.contains(c.path.as_path()));
            let mandatory_unwatched = mandatory.iter().any(|c| !watched.contains(c.path.as_path()));
            proptest::prop_assert!(!(optional_watched && mandatory_unwatched));

            // Coverage: every unwatched directory is under a frontier entry or an unwatched root.
            for c in &candidates {
                if watched.contains(c.path.as_path()) {
                    continue;
                }
                let covered = allocation.frontier.iter().any(|f| c.path.starts_with(f))
                    || allocation.unwatched_roots.iter().any(|r| c.path.starts_with(r));
                proptest::prop_assert!(covered, "{:?} is neither watched nor covered", c.path);
            }
            // Frontier entries sit directly below a watched directory.
            for f in &allocation.frontier {
                proptest::prop_assert!(!watched.contains(f.as_path()));
                proptest::prop_assert!(f.parent().is_some_and(|p| watched.contains(p)));
            }
        }
    }

    #[test]
    fn forced_reconciliation_marks_roots_dirty_and_bumps_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let scanner_config = ScannerConfig {
            event_source: ScannerEventSourceMode::ReconciliationOnly,
            ..Default::default()
        };
        let config =
            EventSourceConfig::from_scanner_config(std::slice::from_ref(&root), &scanner_config);

        let mut source = ScannerEventSource::start(config);
        let invalidation = source.drain();

        assert_eq!(
            source.capability().selected_backend,
            EventBackendKind::ReconciliationOnly
        );
        assert!(invalidation.dirty_roots().contains(&root));
        assert!(invalidation.requires_index_generation_bump());
    }

    #[test]
    fn overflow_forces_all_roots_dirty_and_bumps_generation() {
        let roots = vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")];
        let tracker = DirtyRootTracker::new(&roots);

        let invalidation = tracker.apply_event(FsEvent {
            kind: FsEventKind::Overflow,
            path: None,
        });

        assert_eq!(invalidation.dirty_roots().len(), 2);
        assert!(invalidation.requires_index_generation_bump());
    }

    #[derive(Debug, serde::Serialize)]
    struct EventFallbackValidationArtifact {
        schema_version: u32,
        scenario: &'static str,
        dirty_roots: Vec<String>,
        generation_before: u64,
        generation_after: u64,
        generation_bumped: bool,
        reason_summary: String,
    }

    #[test]
    fn event_overflow_validation_artifact_records_reconciliation_fallback() {
        let roots = vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")];
        let tracker = DirtyRootTracker::new(&roots);
        let mut index = ScannerCandidateIndex::new(crate::scanner::index::ScannerIndexContext {
            root_fingerprint: "root".to_string(),
            config_fingerprint: "config".to_string(),
        });
        let generation_before = index.event_generation();

        let invalidation = tracker.apply_event(FsEvent {
            kind: FsEventKind::Overflow,
            path: None,
        });
        invalidation.apply_to_index(&mut index);

        let mut dirty_roots = invalidation
            .dirty_roots()
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        dirty_roots.sort();
        let artifact = EventFallbackValidationArtifact {
            schema_version: 1,
            scenario: "event-overflow-reconciliation",
            dirty_roots,
            generation_before,
            generation_after: index.event_generation(),
            generation_bumped: invalidation.requires_index_generation_bump(),
            reason_summary: invalidation.reason_summary(),
        };
        let payload = serde_json::to_value(&artifact).unwrap();

        assert_eq!(payload["schema_version"].as_u64(), Some(1));
        assert_eq!(
            payload["scenario"].as_str(),
            Some("event-overflow-reconciliation")
        );
        assert_eq!(artifact.dirty_roots.len(), 2);
        assert_eq!(artifact.generation_before, 0);
        assert_eq!(artifact.generation_after, 1);
        assert!(artifact.generation_bumped);
        assert!(artifact.reason_summary.contains("Overflow"));
        eprintln!(
            "scanner_v2_event_fallback_validation_artifact={}",
            serde_json::to_string(&artifact).unwrap()
        );
    }

    /// bd-rc-master-ajg1.8.8: a path event resolves to the project directory
    /// below the configured root, so a Green pass walks one project. The
    /// root itself is the scan path when the change is at the root, when
    /// the depth-1 directory is an artifact tree (the walker evaluates a
    /// scan path's children, never the path), or when too many projects are
    /// dirty at once; nested scan paths collapse into their ancestor.
    #[test]
    fn path_events_resolve_to_project_scan_paths_without_generation_bump() {
        let root = PathBuf::from("/tmp/root");
        let roots = vec![root.clone()];
        let tracker = DirtyRootTracker::new(&roots);
        let event = |path: PathBuf| {
            tracker.apply_event(FsEvent {
                kind: FsEventKind::Modify,
                path: Some(path),
            })
        };

        // Deep change inside a project: the project is the scan path.
        let mut deep = event(root.join("proj").join("src").join("main.rs"));
        assert!(deep.dirty_roots().is_empty(), "unresolved: {deep:?}");
        assert!(!deep.requires_reconciliation());
        deep.resolve_scan_roots(&roots);
        assert_eq!(
            deep.dirty_roots().iter().cloned().collect::<Vec<_>>(),
            vec![root.join("proj")]
        );
        assert!(deep.requires_reconciliation());
        assert!(!deep.requires_index_generation_bump());

        // The depth-1 directory is a cargo target: only the root's walk can
        // evaluate it, so the root is the scan path.
        let mut artifact = event(root.join("target").join("debug"));
        artifact.resolve_scan_roots(&roots);
        assert_eq!(
            artifact.dirty_roots().iter().cloned().collect::<Vec<_>>(),
            vec![root.clone()]
        );

        // A change at depth 1 (a project created or removed) is the root's.
        let mut shallow = event(root.join("newproj"));
        shallow.resolve_scan_roots(&roots);
        assert_eq!(
            shallow.dirty_roots().iter().cloned().collect::<Vec<_>>(),
            vec![root.clone()]
        );

        // Many projects at once collapse into the root; a nested scan path
        // under an explicitly dirty ancestor is dropped.
        let mut many = EventInvalidation::empty();
        for i in 0..=MAX_EVENT_SCAN_PATHS_PER_ROOT {
            many.merge(event(root.join(format!("p{i}")).join("src").join("x")));
        }
        many.resolve_scan_roots(&roots);
        assert_eq!(
            many.dirty_roots().iter().cloned().collect::<Vec<_>>(),
            vec![root.clone()]
        );
        let mut nested = event(root.join("proj").join("src").join("x"));
        nested.mark_dirty_root(root.join("proj").join("src"), "frontier");
        nested.resolve_scan_roots(&roots);
        assert_eq!(
            nested.dirty_roots().iter().cloned().collect::<Vec<_>>(),
            vec![root.join("proj")]
        );

        // A path under no configured root reconciles everything.
        let mut foreign = event(PathBuf::from("/elsewhere/x"));
        foreign.resolve_scan_roots(&roots);
        assert!(foreign.dirty_roots().contains(&root));
        assert!(foreign.requires_index_generation_bump());
    }

    #[test]
    fn invalidation_generation_bump_applies_to_index() {
        let mut index = ScannerCandidateIndex::new(crate::scanner::index::ScannerIndexContext {
            root_fingerprint: "root".to_string(),
            config_fingerprint: "config".to_string(),
        });
        let tracker = DirtyRootTracker::new(&[PathBuf::from("/tmp/root")]);
        let invalidation = tracker.apply_event(FsEvent {
            kind: FsEventKind::BackendRestart,
            path: None,
        });

        invalidation.apply_to_index(&mut index);

        assert_eq!(index.event_generation(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_recursive_inotify_reports_nested_changes_when_enabled() {
        use std::thread;
        use std::time::{Duration, Instant};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let nested = root.join("nested");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&nested).unwrap();
        let mut source = ScannerEventSource::start(event_config(std::slice::from_ref(&root), 16));
        if source.capability().selected_backend != EventBackendKind::RecursiveInotify {
            return;
        }
        let _ = source.drain();

        let changed = nested.join("object.o");
        fs::write(&changed, b"object").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let invalidation = source.drain();
            if invalidation.dirty_paths().contains(&changed) {
                // The scan path is the project directory, not the root.
                assert!(invalidation.dirty_roots().contains(&nested));
                assert!(!invalidation.dirty_roots().contains(&root));
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("expected nested inotify event for {}", changed.display());
    }

    #[cfg(target_os = "linux")]
    fn set_dir_mtime(path: &Path, when: SystemTime) {
        fs::File::open(path).unwrap().set_modified(when).unwrap();
    }

    /// bd-rc-master-ajg1.8.4: an exhausted budget lands on the recently
    /// active subtree, a budget-exceeded directory becomes a frontier scan
    /// path instead of dirtying the whole root, and the periodic replan moves
    /// the watch to whichever subtree became hot since.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_replan_moves_watches_to_the_hot_frontier() {
        use std::thread;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let a = root.join("a");
        let x = a.join("x");
        let y = a.join("y");
        fs::create_dir_all(&x).unwrap();
        fs::create_dir_all(&y).unwrap();
        let old = SystemTime::now() - Duration::from_hours(6);
        set_dir_mtime(&x, old);

        // Budget 3 = root + a (mandatory) + the more recently modified of x/y.
        let t0 = Instant::now();
        let mut source =
            ScannerEventSource::start_at(event_config(std::slice::from_ref(&root), 3), t0);
        if source.capability().selected_backend != EventBackendKind::RecursiveInotify {
            return;
        }
        let startup = source.drain_at(t0);
        assert_eq!(source.capability().watched_dirs, 3);
        assert_eq!(source.capability().frontier_dirs, 1);
        assert!(startup.dirty_roots().contains(&x), "{startup:?}");
        assert!(!startup.dirty_roots().contains(&root), "{startup:?}");

        // A directory created under a watched one when the budget is spent is
        // reported as its own frontier scan path, without a generation bump.
        let z = a.join("z");
        fs::create_dir(&z).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_budget_exceeded = false;
        while Instant::now() < deadline {
            let invalidation = source.drain_at(t0 + Duration::from_secs(1));
            if invalidation
                .reason_summary()
                .contains("WatchBudgetExceeded")
            {
                // `z` is a scan path, or is covered by its project `a`, which
                // the Create event resolved to; the root is never dirtied.
                assert!(
                    invalidation.dirty_roots().iter().any(|d| z.starts_with(d)),
                    "{invalidation:?}"
                );
                assert!(
                    !invalidation.dirty_roots().contains(&root),
                    "{invalidation:?}"
                );
                assert!(!invalidation.requires_index_generation_bump());
                saw_budget_exceeded = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            saw_budget_exceeded,
            "no WatchBudgetExceeded for {}",
            z.display()
        );

        // Now x is the hot one: bump its mtime and let the
        // replan interval elapse. The replan needs at least one observed event
        // since the plan, which the directory creation above provided.
        // Touching y or z would hand them observed events on their own
        // watches, so only x is touched: its mtime is now the newest.
        set_dir_mtime(&x, SystemTime::now());
        let later = t0 + WATCH_REPLAN_INTERVAL + Duration::from_secs(1);
        let replanned = source.drain_at(later);
        assert_eq!(source.stats().replans, 1, "{:?}", source.stats());
        assert_eq!(source.capability().watched_dirs, 3);
        assert_eq!(source.capability().frontier_dirs, 2);
        // y and z are the new frontier; the mtime touch on x was itself an
        // event on `a`, whose project scan path covers them both.
        let covered = |path: &Path| replanned.dirty_roots().iter().any(|d| path.starts_with(d));
        assert!(covered(&y) && covered(&z), "{replanned:?}");
        assert!(!replanned.dirty_roots().contains(&x), "{replanned:?}");
        assert!(!replanned.dirty_roots().contains(&root), "{replanned:?}");
        assert!(!replanned.requires_index_generation_bump());

        // The new backend is live: a file inside x is reported.
        let changed = x.join("object.o");
        fs::write(&changed, b"object").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let invalidation = source.drain_at(later + Duration::from_secs(1));
            if invalidation.dirty_paths().contains(&changed) {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "expected inotify event for {} after replan",
            changed.display()
        );
    }

    /// bd-rc-master-ajg1.8.5: the capability report must say what the event
    /// source really is on this platform. Linux plans recursive inotify and
    /// reports fanotify as deferred; every other platform reconciles only,
    /// with every root dirty, and says why.
    #[test]
    fn capability_report_is_honest_about_the_platform() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let scanner_config = ScannerConfig {
            event_watch_budget: 16,
            ..Default::default()
        };
        let config =
            EventSourceConfig::from_scanner_config(std::slice::from_ref(&root), &scanner_config);
        let plan = EventSourcePlan::for_config(&config);
        let capability = EventSourceCapability::from_plan(&plan);

        assert!(!capability.fanotify.available, "{capability:?}");
        assert!(
            capability.fanotify.reason.contains("deferred"),
            "{}",
            capability.fanotify.reason
        );
        if cfg!(target_os = "linux") {
            assert_eq!(
                capability.selected_backend,
                EventBackendKind::RecursiveInotify
            );
            assert!(capability.recursive_inotify.available, "{capability:?}");
            assert!(capability.complete, "{capability:?}");
        } else {
            assert_eq!(
                capability.selected_backend,
                EventBackendKind::ReconciliationOnly
            );
            assert!(!capability.recursive_inotify.available, "{capability:?}");
            assert_eq!(capability.dirty_roots, vec![root]);
            assert!(
                capability.reason.contains("unavailable on this platform"),
                "{}",
                capability.reason
            );
        }
    }
}
