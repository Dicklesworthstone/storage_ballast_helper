//! Empty-pass pacing belongs to the work that was actually inspected.
//!
//! An empty pass on one mount says nothing about another mount, a dirty
//! subtree, or an inode-removal objective. CPU and duty-cycle limits remain
//! global; this ledger only remembers evidence that a particular scope had
//! no reclaimable work.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{
    ScanRequest, SharedExecutorConfig, confirm_scanner_dispatch, effective_empty_pass_cooldown,
    empty_pass_cooldown_active, note_empty_pass_level, pressure_escalated,
    record_dispatching_pass, record_empty_pass, rise_already_scanned_empty,
};
use crate::core::config::{ScannerConfig, ScoringConfig};
use crate::daemon::filesystem_reclaim::FilesystemReclaimScope;
use crate::daemon::predictive_reclaim::PredictiveScanAdmission;
use crate::monitor::pid::PressureLevel;
use crate::platform::cleanup_catalog::ExpandedCatalogRoot;

/// Event subtrees can change indefinitely; forgetting pacing is safe, whereas
/// retaining unbounded path histories would turn monitoring into a memory leak.
const MAX_SCOPES: usize = 256;

struct ScanScope {
    paths: Vec<PathBuf>,
    catalog_roots: Vec<ExpandedCatalogRoot>,
    filesystem: Option<Arc<FilesystemReclaimScope>>,
    ram: bool,
    inodes: bool,
    predictive_floor: Option<u64>,
}

impl ScanScope {
    fn new(request: &ScanRequest) -> Self {
        let mut paths = request.paths.clone();
        paths.sort();
        paths.dedup();
        let mut catalog_roots = request.catalog_roots.clone();
        catalog_roots.sort_by(|left, right| {
            left.path.cmp(&right.path).then(left.rule.cmp(right.rule))
        });
        catalog_roots.dedup();
        Self {
            paths,
            catalog_roots,
            filesystem: request.filesystem_reclaim.clone(),
            ram: request.ram_reclaim.is_some(),
            inodes: request.inode_reclaim.is_some(),
            predictive_floor: request
                .predictive_reclaim
                .as_ref()
                .map(|admission| admission.min_score().to_bits()),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.paths == other.paths
            && self.catalog_roots == other.catalog_roots
            && self.ram == other.ram
            && self.inodes == other.inodes
            && self.predictive_floor == other.predictive_floor
            && match (&self.filesystem, &other.filesystem) {
                (Some(left), Some(right)) => left.same_scan_scope(right),
                (None, None) => true,
                _ => false,
            }
    }
}

struct ScopedBackoff {
    scope: ScanScope,
    state: ScanBackoff,
    last_used: Instant,
}

#[derive(Default)]
pub(super) struct ScanBackoffs {
    policy: Option<(ScannerConfig, ScoringConfig)>,
    scopes: Vec<ScopedBackoff>,
}

impl ScanBackoffs {
    pub(super) fn reconfigure(&mut self, scanner: &ScannerConfig, scoring: &ScoringConfig) {
        if self.policy.as_ref().is_none_or(|(old_scanner, old_scoring)| {
            old_scanner != scanner || old_scoring != scoring
        }) {
            // A changed classifier, threshold or traversal policy can expose
            // candidates that the old policy held. Old emptiness is no proof.
            self.scopes.clear();
            self.policy = Some((scanner.clone(), scoring.clone()));
        }
    }

    pub(super) fn confirm_dispatches(&mut self, config: &SharedExecutorConfig, now: Instant) {
        for scoped in &mut self.scopes {
            scoped.state.confirm_dispatch(config, now);
        }
    }

    pub(super) fn for_request(&mut self, request: &ScanRequest, now: Instant) -> &mut ScanBackoff {
        let scope = ScanScope::new(request);
        if let Some(index) = self.scopes.iter().position(|entry| entry.scope.matches(&scope)) {
            self.scopes[index].last_used = now;
            return &mut self.scopes[index].state;
        }
        if self.scopes.len() >= MAX_SCOPES {
            let oldest = self
                .scopes
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used)
                .map_or(0, |(index, _)| index);
            self.scopes.remove(oldest);
        }
        self.scopes.push(ScopedBackoff {
            scope,
            state: ScanBackoff::default(),
            last_used: now,
        });
        &mut self.scopes.last_mut().expect("just inserted scope").state
    }
}

#[derive(Default)]
pub(super) struct ScanBackoff {
    last_empty_at: Option<Instant>,
    consecutive_empty: u32,
    inconclusive_empty: u32,
    pending_dispatch: Option<(u64, Option<PredictiveScanAdmission>)>,
    last_dispatch_empty: bool,
    pub(super) last_pass_level: Option<PressureLevel>,
    empty_level_peak: Option<(PressureLevel, Instant)>,
}

impl ScanBackoff {
    pub(super) fn record_empty(&mut self, timed_out: bool, level: PressureLevel, now: Instant) {
        record_empty_pass(
            &mut self.consecutive_empty,
            &mut self.inconclusive_empty,
            timed_out,
        );
        self.last_empty_at = Some(now);
        note_empty_pass_level(&mut self.empty_level_peak, level, now);
    }

    pub(super) fn record_dispatch(
        &mut self,
        reclaim_before: u64,
        prediction: Option<PredictiveScanAdmission>,
    ) {
        record_dispatching_pass(
            self.last_dispatch_empty,
            &mut self.consecutive_empty,
            &mut self.inconclusive_empty,
            &mut self.last_empty_at,
        );
        self.record_pending(reclaim_before, prediction);
    }

    pub(super) fn record_pending(
        &mut self,
        reclaim_before: u64,
        prediction: Option<PredictiveScanAdmission>,
    ) {
        self.pending_dispatch = Some((reclaim_before, prediction));
    }

    fn confirm_dispatch(&mut self, config: &SharedExecutorConfig, now: Instant) {
        let Some((reclaim_before, prediction)) = self.pending_dispatch.take() else {
            return;
        };
        let outcome = confirm_scanner_dispatch(reclaim_before, prediction.as_ref(), config, now);
        self.last_dispatch_empty = outcome == Some(false);
        if outcome == Some(true) {
            record_dispatching_pass(
                false,
                &mut self.consecutive_empty,
                &mut self.inconclusive_empty,
                &mut self.last_empty_at,
            );
        } else if outcome == Some(false) {
            record_empty_pass(
                &mut self.consecutive_empty,
                &mut self.inconclusive_empty,
                false,
            );
            self.last_empty_at = Some(now);
            if let Some(level) = self.last_pass_level {
                note_empty_pass_level(&mut self.empty_level_peak, level, now);
            }
            eprintln!(
                "[SBH-SCANNER] the last pass for this scope dispatched candidates but nothing was reclaimed (dry-run, observe, dampened or failed); pacing it as an empty pass (consecutive={})",
                self.consecutive_empty
            );
        }
        // A forecast withdrawn while queued establishes no empty result.
    }

    pub(super) fn reset_on_escalation(&mut self, request: &ScanRequest, now: Instant) {
        if pressure_escalated(self.last_pass_level, request)
            && self.last_empty_at.is_some()
            && !rise_already_scanned_empty(self.empty_level_peak, request.pressure_level, now)
        {
            eprintln!(
                "[SBH-SCANNER] pressure rose to {:?} for this scope; empty-pass backoff reset (was consecutive={})",
                request.pressure_level, self.consecutive_empty
            );
            self.last_empty_at = None;
            self.consecutive_empty = 0;
            self.inconclusive_empty = 0;
        }
    }

    pub(super) fn cooldown_active(
        &self,
        request: &ScanRequest,
        from_events: bool,
        interval_secs: u64,
        now: Instant,
    ) -> bool {
        if from_events {
            let base = Duration::from_secs(interval_secs.max(1));
            return self
                .last_empty_at
                .is_some_and(|last| now.saturating_duration_since(last) < base);
        }
        empty_pass_cooldown_active(
            self.last_empty_at,
            now,
            self.cooldown(interval_secs),
            request,
            self.consecutive_empty,
        )
    }

    pub(super) fn cooldown(&self, interval_secs: u64) -> Duration {
        effective_empty_pass_cooldown(interval_secs, self.consecutive_empty)
    }

    pub(super) fn consecutive_empty(&self) -> u32 {
        self.consecutive_empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::InodePressureConfig;
    use crate::daemon::inode_reclaim::InodeReclaimRequest;

    fn request(path: &str, level: PressureLevel) -> ScanRequest {
        let paths = vec![PathBuf::from(path)];
        ScanRequest {
            admitted_scanner: Arc::new(ScannerConfig {
                root_paths: paths.clone(),
                ..ScannerConfig::default()
            }),
            paths,
            filesystem_reclaim: None,
            predictive_reclaim: None,
            urgency: 0.9,
            pressure_level: level,
            free_pct: Some(9.0),
            max_delete_batch: 10,
            force_full_scan: false,
            scan_now: None,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
            ram_reclaim: None,
            inode_reclaim: None,
        }
    }

    fn exhaust(backoffs: &mut ScanBackoffs, request: &ScanRequest, now: Instant) {
        let state = backoffs.for_request(request, now);
        for _ in 0..super::super::TERMINAL_IDLE_EMPTY_PASSES {
            state.record_empty(false, request.pressure_level, now);
        }
        state.last_pass_level = Some(request.pressure_level);
    }

    #[test]
    fn barren_mount_cannot_delay_unvisited_peer_or_dirty_subtree() {
        for level in [PressureLevel::Orange, PressureLevel::Critical] {
            let now = Instant::now();
            let mut backoffs = ScanBackoffs::default();
            let empty = request("/empty", level);
            let peer = request("/peer", level);
            let subtree = request("/empty/changed", level);
            exhaust(&mut backoffs, &empty, now);
            assert!(backoffs.for_request(&empty, now).cooldown_active(&empty, false, 90, now));
            assert!(!backoffs.for_request(&peer, now).cooldown_active(&peer, false, 90, now));
            assert!(!backoffs.for_request(&subtree, now).cooldown_active(&subtree, true, 90, now));
            assert!(backoffs.for_request(&empty, now).cooldown_active(&empty, false, 90, now));
        }
    }

    #[test]
    fn root_reordering_preserves_backoff_but_new_roots_and_resources_do_not() {
        let now = Instant::now();
        let mut backoffs = ScanBackoffs::default();
        let mut original = request("/a", PressureLevel::Orange);
        original.paths.push(PathBuf::from("/b"));
        exhaust(&mut backoffs, &original, now);
        let mut reordered = original.clone();
        reordered.paths.reverse();
        reordered.paths.push(PathBuf::from("/a"));
        assert!(backoffs.for_request(&reordered, now).cooldown_active(&reordered, false, 90, now));

        let mut expanded = original.clone();
        expanded.paths.push(PathBuf::from("/c"));
        assert!(!backoffs.for_request(&expanded, now).cooldown_active(&expanded, false, 90, now));

        let mut inode = original.clone();
        inode.inode_reclaim = Some(InodeReclaimRequest::from_observed_roots(
            PathBuf::from("/a"),
            1,
            100,
            10,
            2,
            &InodePressureConfig::default(),
            &[],
        ));
        assert!(!backoffs.for_request(&inode, now).cooldown_active(&inode, false, 90, now));

        let mut catalog = original.clone();
        catalog.catalog_roots.push(ExpandedCatalogRoot {
            path: PathBuf::from("/a/cache"),
            rule: "fixture",
            confidence: crate::platform::cleanup_catalog::CleanupConfidence::Definite,
            min_age: Duration::ZERO,
        });
        assert!(!backoffs.for_request(&catalog, now).cooldown_active(&catalog, false, 90, now));
    }

    #[test]
    fn failed_dispatch_is_charged_to_its_original_scope() {
        let now = Instant::now();
        let mut backoffs = ScanBackoffs::default();
        let shared = SharedExecutorConfig::new(false, 10, 0.0, 60, 3600, false, 0);
        let original = request("/a", PressureLevel::Orange);
        let peer = request("/b", PressureLevel::Orange);
        let state = backoffs.for_request(&original, now);
        state.last_pass_level = Some(original.pressure_level);
        state.record_dispatch(shared.reclaim_events(), None);
        backoffs.confirm_dispatches(&shared, now);
        assert_eq!(backoffs.for_request(&original, now).consecutive_empty(), 1);
        assert!(!backoffs.for_request(&peer, now).cooldown_active(&peer, false, 90, now));

        backoffs.for_request(&original, now).record_dispatch(shared.reclaim_events(), None);
        backoffs.confirm_dispatches(&shared, now);
        assert_eq!(backoffs.for_request(&original, now).consecutive_empty(), 2);
        backoffs.for_request(&original, now).record_dispatch(shared.reclaim_events(), None);
        shared.note_reclaim();
        backoffs.confirm_dispatches(&shared, now);
        assert_eq!(backoffs.for_request(&original, now).consecutive_empty(), 0);
    }

    #[test]
    fn escalation_and_threshold_flapping_remain_scoped() {
        let now = Instant::now();
        let mut backoffs = ScanBackoffs::default();
        let orange = request("/a", PressureLevel::Orange);
        let red = request("/a", PressureLevel::Red);
        let peer = request("/b", PressureLevel::Orange);
        exhaust(&mut backoffs, &orange, now);
        exhaust(&mut backoffs, &peer, now);
        backoffs.for_request(&red, now).reset_on_escalation(&red, now);
        assert!(!backoffs.for_request(&red, now).cooldown_active(&red, false, 90, now));
        assert!(backoffs.for_request(&peer, now).cooldown_active(&peer, false, 90, now));

        exhaust(&mut backoffs, &red, now);
        let state = backoffs.for_request(&orange, now);
        state.record_empty(false, orange.pressure_level, now);
        state.last_pass_level = Some(orange.pressure_level);
        backoffs.for_request(&red, now).reset_on_escalation(&red, now);
        assert!(backoffs.for_request(&red, now).cooldown_active(&red, false, 90, now));
    }

    #[test]
    fn policy_change_withdraws_empty_evidence_and_dynamic_scopes_stay_bounded() {
        let now = Instant::now();
        let mut backoffs = ScanBackoffs::default();
        let scanner = ScannerConfig::default();
        let mut scoring = ScoringConfig::default();
        let original = request("/a", PressureLevel::Orange);
        backoffs.reconfigure(&scanner, &scoring);
        exhaust(&mut backoffs, &original, now);
        backoffs.reconfigure(&scanner, &scoring);
        assert!(backoffs.for_request(&original, now).cooldown_active(&original, false, 90, now));
        scoring.min_score += 0.01;
        backoffs.reconfigure(&scanner, &scoring);
        assert!(!backoffs.for_request(&original, now).cooldown_active(&original, false, 90, now));
        for i in 0..MAX_SCOPES + 10 {
            let dynamic = request(&format!("/changed/{i}"), PressureLevel::Orange);
            backoffs.for_request(&dynamic, now + Duration::from_secs(i as u64));
        }
        assert_eq!(backoffs.scopes.len(), MAX_SCOPES);
        assert!(!backoffs.for_request(&original, now).cooldown_active(&original, false, 90, now));
    }
}
