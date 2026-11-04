//! Bounded reclaim of already-authorized tmpfs artifacts when swap is short.
//!
//! Filesystem capacity is not physical backing capacity. A tmpfs can have
//! plenty of free blocks while its pages exhaust swap. This permission carries
//! that separate reason through the scanner queue, without inventing disk
//! counters, admitting new roots, or relaxing the artifact safety checks.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::monitor::ram_scratch::swap_reclaim_pressure;
use crate::platform::pal::Platform;
use crate::scanner::deletion::SkipReason;
use crate::scanner::scoring::{ArtifactCertainty, CandidacyScore, DecisionAction};
use crate::scanner::walker::{device_id, identity_for_path};

/// A single tmpfs relief pass and its shared, finite allocated-byte allowance.
///
/// Every batch from a pass shares the remaining allowance. Before each actual
/// unlink, the executor renews both the swap-pressure observation and the
/// filesystem evidence; queue age alone never extends authority. The existing
/// executor still owns leases, active references, source/protection checks,
/// identity validation, policy, dry-run, and confined removal.
#[derive(Debug, Clone)]
pub struct RamReclaimRequest {
    mount: PathBuf,
    device_id: u64,
    remaining: Arc<AtomicU64>,
}

impl RamReclaimRequest {
    /// Capture a bounded pass on one admitted tmpfs filesystem.
    ///
    /// The caller obtains `device_id` from the admitted mount and caps
    /// `target_bytes` by both occupied tmpfs blocks and the swap shortfall.
    #[must_use]
    pub fn new(mount: PathBuf, device_id: u64, target_bytes: u64) -> Self {
        Self {
            mount,
            device_id,
            remaining: Arc::new(AtomicU64::new(target_bytes)),
        }
    }

    /// The original pass's byte allowance that successful unlinks have not used.
    #[must_use]
    pub fn remaining_bytes(&self) -> u64 {
        self.remaining.load(Ordering::Acquire)
    }

    /// Whether an observed candidate belongs to this pass's narrower scope.
    /// This is only a queue filter; [`Self::authorize`] renews live evidence.
    #[must_use]
    pub fn accepts_candidate(&self, candidate: &CandidacyScore) -> bool {
        self.remaining_bytes() > 0
            && !candidate.vetoed
            && candidate.decision.action == DecisionAction::Delete
            && candidate.decision.certainty == ArtifactCertainty::Definite
            && !candidate.decision.category_suspended
            && candidate
                .identity
                .is_some_and(|identity| identity.device_id == self.device_id)
    }

    /// A no-follow device check for shallow discovery and requested roots.
    /// In particular, a nested disk mount cannot become a RAM relief surface
    /// even when the operator normally allows cross-device scanning.
    #[must_use]
    pub fn contains_path(&self, path: &Path) -> bool {
        path.symlink_metadata().is_ok_and(|metadata| {
            !metadata.file_type().is_symlink() && device_id(&metadata) == self.device_id
        })
    }

    /// Renew the mount and backing-pressure evidence without authorizing a
    /// candidate. Missing, inconsistent, recovered or non-tmpfs observations
    /// defer the pass without imposing a failure backoff on its artifacts.
    pub fn authorize_mount(&self, platform: &dyn Platform) -> Result<(), SkipReason> {
        if self.remaining_bytes() == 0 || !self.contains_path(&self.mount) {
            return Err(SkipReason::PolicyChanged);
        }
        let stats = platform
            .fs_stats(&self.mount)
            .map_err(|_| SkipReason::PolicyChanged)?;
        if stats.fs_type != "tmpfs"
            || stats.total_bytes == 0
            || stats.free_bytes > stats.total_bytes
            || stats.available_bytes > stats.free_bytes
            || stats.free_bytes == stats.total_bytes
            || stats.is_readonly
            || !platform.is_ram_backed(&self.mount).unwrap_or(false)
        {
            return Err(SkipReason::PolicyChanged);
        }
        let memory = platform
            .memory_info()
            .map_err(|_| SkipReason::PolicyChanged)?;
        if swap_reclaim_pressure(&memory).is_none() {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(())
    }

    /// Recheck backing pressure and the candidate's exact filesystem identity
    /// immediately before mutation. A recent scan is not substitute evidence.
    pub fn authorize(
        &self,
        candidate: &CandidacyScore,
        platform: &dyn Platform,
    ) -> Result<(), SkipReason> {
        if !self.accepts_candidate(candidate) {
            return Err(SkipReason::PolicyChanged);
        }
        self.authorize_mount(platform)?;
        if identity_for_path(&candidate.path, false).ok() != candidate.identity
            || !platform.is_ram_backed(&candidate.path).unwrap_or(false)
        {
            return Err(SkipReason::PolicyChanged);
        }
        let stats = platform
            .fs_stats(&candidate.path)
            .map_err(|_| SkipReason::PolicyChanged)?;
        if stats.fs_type != "tmpfs"
            || stats.is_readonly
            || stats.total_bytes == 0
            || stats.free_bytes > stats.total_bytes
            || stats.available_bytes > stats.free_bytes
        {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(())
    }

    /// Charge only a successful irreversible unlink, using the scanner's
    /// allocated-block estimate rather than apparent file length. Whole
    /// artifacts are indivisible; one may exceed the remaining allowance,
    /// which stops every later candidate and batch from this pass.
    pub fn record_unlinked(&self, candidate: &CandidacyScore) {
        let _ = self
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                Some(remaining.saturating_sub(candidate.size_bytes))
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::time::Duration;

    use crate::platform::pal::{FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths};
    use crate::scanner::deletion::{DeletionConfig, DeletionExecutor};
    use crate::scanner::patterns::ArtifactClassification;
    use crate::scanner::scoring::{DecisionOutcome, EvidenceLedger, ScoreFactors};

    fn candidate(path: PathBuf) -> CandidacyScore {
        fs::create_dir(&path).unwrap();
        fs::write(path.join("artifact"), vec![1_u8; 4096]).unwrap();
        CandidacyScore {
            identity: identity_for_path(&path, false).ok(),
            path,
            total_score: 0.9,
            factors: ScoreFactors {
                location: 1.0,
                name: 1.0,
                age: 1.0,
                size: 1.0,
                structure: 1.0,
                pressure_multiplier: 1.0,
            },
            vetoed: false,
            veto_reason: None,
            classification: ArtifactClassification::unknown(),
            size_bytes: 4096,
            age: Duration::from_hours(24),
            decision: DecisionOutcome {
                action: DecisionAction::Delete,
                posterior_abandoned: 0.99,
                expected_loss_keep: 1.0,
                expected_loss_delete: 0.01,
                calibration_score: 1.0,
                fallback_active: false,
                certainty: ArtifactCertainty::Definite,
                posterior_floor_applied: false,
                regret_calibration: 1.0,
                category_suspended: false,
            },
            ledger: EvidenceLedger {
                terms: Vec::new(),
                summary: "fixture".to_string(),
            },
        }
    }

    fn memory(swap_free_bytes: u64) -> MemoryInfo {
        MemoryInfo {
            total_bytes: 64_000,
            available_bytes: 32_000,
            swap_total_bytes: 10_000,
            swap_free_bytes,
        }
    }

    fn platform(root: &Path, memory: MemoryInfo, fs_type: &str) -> MockPlatform {
        let root = root.to_path_buf();
        MockPlatform::new(
            vec![MountPoint {
                path: root.clone(),
                device: "fixture".to_string(),
                fs_type: fs_type.to_string(),
                is_ram_backed: fs_type == "tmpfs",
            }],
            HashMap::from([(
                root.clone(),
                FsStats {
                    total_bytes: 100_000,
                    free_bytes: 29_000,
                    available_bytes: 29_000,
                    fs_type: fs_type.to_string(),
                    mount_point: root,
                    is_readonly: false,
                },
            )]),
            memory,
            PlatformPaths::default(),
        )
    }

    #[test]
    fn filesystem_green_does_not_hide_current_swap_exhaustion() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            4096,
        );
        let pal = platform(temp.path(), memory(1), "tmpfs");
        assert!((pal.fs_stats(temp.path()).unwrap().free_pct() - 29.0).abs() < f64::EPSILON);
        assert_eq!(request.authorize(&candidate, &pal), Ok(()));
    }

    #[test]
    fn fresh_recovery_missing_evidence_and_invalid_memory_revoke_queued_work() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            4096,
        );
        for observed in [
            memory(1000),
            memory(10_001),
            MemoryInfo {
                total_bytes: 0,
                ..memory(1)
            },
            MemoryInfo {
                available_bytes: 64_001,
                ..memory(1)
            },
            MemoryInfo {
                swap_total_bytes: 0,
                swap_free_bytes: 0,
                ..memory(1)
            },
        ] {
            let pal = platform(temp.path(), observed, "tmpfs");
            assert_eq!(
                request.authorize(&candidate, &pal),
                Err(SkipReason::PolicyChanged)
            );
        }
        let missing = MockPlatform::new(
            Vec::new(),
            HashMap::new(),
            memory(1),
            PlatformPaths::default(),
        );
        assert_eq!(
            request.authorize(&candidate, &missing),
            Err(SkipReason::PolicyChanged)
        );
        assert!(candidate.path.exists());
    }

    #[test]
    fn disk_candidates_unknown_identity_and_uncertain_artifacts_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let mut candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            4096,
        );
        let disk = platform(temp.path(), memory(1), "ext4");
        assert_eq!(
            request.authorize(&candidate, &disk),
            Err(SkipReason::PolicyChanged)
        );
        let identity = candidate.identity;
        candidate.identity = None;
        assert!(!request.accepts_candidate(&candidate));
        candidate.identity = identity;
        candidate.identity.as_mut().unwrap().device_id ^= 1;
        assert!(!request.accepts_candidate(&candidate));
        candidate.identity = identity;
        for certainty in [ArtifactCertainty::Unclear, ArtifactCertainty::Likely] {
            candidate.decision.certainty = certainty;
            assert!(!request.accepts_candidate(&candidate));
        }
    }

    #[test]
    fn successful_unlinks_share_one_saturating_allowance_across_batches() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            5000,
        );
        let next_batch = request.clone();
        request.record_unlinked(&candidate);
        assert_eq!(next_batch.remaining_bytes(), 904);
        next_batch.record_unlinked(&candidate);
        assert_eq!(request.remaining_bytes(), 0);
        assert_eq!(
            request.authorize(&candidate, &platform(temp.path(), memory(1), "tmpfs")),
            Err(SkipReason::PolicyChanged)
        );
        request.record_unlinked(&candidate);
        assert_eq!(next_batch.remaining_bytes(), 0);
    }

    #[test]
    fn executor_keeps_protected_artifacts_and_stops_later_batches_at_the_target() {
        let temp = tempfile::tempdir().unwrap();
        let protected = candidate(temp.path().join("protected"));
        fs::write(protected.path.join(".sbh-protect"), b"operator work").unwrap();
        let eligible = candidate(temp.path().join("eligible"));
        let later = candidate(temp.path().join("later"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            eligible.identity.unwrap().device_id,
            eligible.size_bytes,
        );
        let next_batch = request.clone();
        let pal = platform(temp.path(), memory(1), "tmpfs");
        let executor = DeletionExecutor::new(
            DeletionConfig {
                check_open_files: false,
                require_identity: true,
                ..DeletionConfig::default()
            },
            None,
        );
        let plan = executor.plan(vec![protected.clone(), eligible.clone()]);
        let report = executor.execute_with_hooks(
            &plan,
            None,
            Some(&|candidate| request.authorize(candidate, &pal)),
            Some(&|candidate, _| request.record_unlinked(candidate)),
        );
        assert_eq!(report.items_deleted, 1);
        assert!(protected.path.join("artifact").exists());
        assert!(!eligible.path.exists());
        assert_eq!(next_batch.remaining_bytes(), 0);

        let later_plan = executor.plan(vec![later.clone()]);
        let stopped = executor.execute_with_hooks(
            &later_plan,
            None,
            Some(&|candidate| next_batch.authorize(candidate, &pal)),
            Some(&|candidate, _| next_batch.record_unlinked(candidate)),
        );
        assert_eq!(stopped.items_deleted, 0);
        assert_eq!(stopped.skipped_by_reason.get("policy_changed"), Some(&1));
        assert!(stopped.backoff_candidates.is_empty());
        assert!(later.path.join("artifact").exists());
    }

    #[test]
    fn recovered_swap_stops_a_previously_authorized_executor_plan() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            candidate.size_bytes,
        );
        assert!(
            request
                .authorize(&candidate, &platform(temp.path(), memory(1), "tmpfs"))
                .is_ok()
        );
        let executor = DeletionExecutor::new(
            DeletionConfig {
                check_open_files: false,
                require_identity: true,
                ..DeletionConfig::default()
            },
            None,
        );
        let plan = executor.plan(vec![candidate.clone()]);
        let recovered = platform(temp.path(), memory(1000), "tmpfs");
        let report = executor.execute_with_hooks(
            &plan,
            None,
            Some(&|candidate| request.authorize(candidate, &recovered)),
            Some(&|candidate, _| request.record_unlinked(candidate)),
        );
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.skipped_by_reason.get("policy_changed"), Some(&1));
        assert!(report.backoff_candidates.is_empty());
        assert_eq!(request.remaining_bytes(), candidate.size_bytes);
        assert!(candidate.path.join("artifact").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replacement_and_symlink_do_not_inherit_the_observed_identity() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            4096,
        );
        let pal = platform(temp.path(), memory(1), "tmpfs");
        fs::rename(&candidate.path, temp.path().join("saved")).unwrap();
        fs::create_dir(&candidate.path).unwrap();
        assert_eq!(
            request.authorize(&candidate, &pal),
            Err(SkipReason::PolicyChanged)
        );
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(temp.path().join("saved"), &alias).unwrap();
        assert!(!request.contains_path(&alias));
        assert!(temp.path().join("saved/artifact").exists());
    }
}
