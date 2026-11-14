//! Bounded reclaim of existing artifacts on a filesystem short of inodes.
//!
//! Bytes and inodes are different resources. This permission never changes a
//! byte estimate, invents an inode yield, or admits a new cleanup root. Fresh
//! filesystem counters decide when enough inodes are available; a shared
//! successful-artifact allowance bounds every batch from the same scan pass.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::core::config::{InodePressureConfig, ScannerConfig};
use crate::monitor::fs_stats::ObservedDirectory;
use crate::platform::pal::Platform;
use crate::scanner::deletion::SkipReason;
use crate::scanner::quarantine::QuarantineRecord;
use crate::scanner::scoring::{ArtifactCertainty, CandidacyScore, DecisionAction};
use crate::scanner::walker::{FsEntryKind, FsIdentity, device_id, identity_for_path};

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmittedRoot {
    original: PathBuf,
    resolved: PathBuf,
    identity: FsIdentity,
}

/// One exact-device inode relief pass, shared by all of its queued batches.
#[derive(Debug, Clone)]
pub struct InodeReclaimRequest {
    mount: PathBuf,
    device_id: u64,
    total: u64,
    target_available: u64,
    remaining: Arc<AtomicUsize>,
    policy: InodePressureConfig,
    roots: Vec<AdmittedRoot>,
}

impl InodeReclaimRequest {
    /// Capture the sampled inode capacity, recovery goal and finite action cap.
    #[must_use]
    pub fn new(
        mount: PathBuf,
        device_id: u64,
        total: u64,
        target_available: u64,
        max_artifacts: usize,
        policy: &InodePressureConfig,
        roots: &[PathBuf],
    ) -> Self {
        let roots = roots
            .iter()
            .filter_map(|root| ObservedDirectory::collect(root))
            .collect::<Vec<_>>();
        Self::from_observed_roots(
            mount,
            device_id,
            total,
            target_available,
            max_artifacts,
            policy,
            &roots,
        )
    }

    /// Build pressure authority from already-completed directory observations.
    /// Unknown roots stay absent; this constructor never performs native I/O.
    pub(super) fn from_observed_roots(
        mount: PathBuf,
        device_id: u64,
        total: u64,
        target_available: u64,
        max_artifacts: usize,
        policy: &InodePressureConfig,
        roots: &[ObservedDirectory],
    ) -> Self {
        let roots = roots
            .iter()
            .filter(|root| root.identity.device_id == device_id)
            .map(|root| AdmittedRoot {
                original: root.original.clone(),
                resolved: root.resolved.clone(),
                identity: root.identity,
            })
            .collect();
        Self {
            mount,
            device_id,
            total,
            target_available,
            remaining: Arc::new(AtomicUsize::new(max_artifacts)),
            policy: policy.clone(),
            roots,
        }
    }

    /// Successful artifact removals still permitted by the original pass.
    #[must_use]
    pub fn remaining_artifacts(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }

    /// Continue a completed quarantine pass only for the same captured mount,
    /// device, roots and inode goal. This comparison performs no filesystem
    /// I/O, and the successor can tighten but never replenish its allowance.
    pub(super) fn share_remaining_allowance(&mut self, previous: &Self) {
        if self.mount == previous.mount
            && self.device_id == previous.device_id
            && self.total == previous.total
            && self.target_available == previous.target_available
            && self.policy == previous.policy
            && self.roots == previous.roots
        {
            previous
                .remaining
                .fetch_min(self.remaining_artifacts(), Ordering::AcqRel);
            self.remaining = Arc::clone(&previous.remaining);
        }
    }

    /// A queued pass cannot retain permission across an inode policy change.
    pub fn authorize_policy(&self, current: &InodePressureConfig) -> Result<(), SkipReason> {
        if !current.enabled || !current.is_valid() || *current != self.policy {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(())
    }

    /// Renew a configured root's original alias, canonical directory identity,
    /// and both spellings of every exclusion. A lexical prefix is insufficient:
    /// a child symlink may lead to an unrelated directory on the same device.
    pub fn authorize_scope(
        &self,
        path: &Path,
        scanner: &ScannerConfig,
    ) -> Result<PathBuf, SkipReason> {
        let resolved = std::fs::canonicalize(path).map_err(|_| SkipReason::PolicyChanged)?;
        let original = std::path::absolute(path).map_err(|_| SkipReason::PolicyChanged)?;
        if excluded(&original, &resolved, &scanner.excluded_paths) {
            return Err(SkipReason::PolicyChanged);
        }
        let admitted = self.roots.iter().any(|root| {
            scanner.root_paths.contains(&root.original)
                && resolved.starts_with(&root.resolved)
                && std::fs::canonicalize(&root.original).ok().as_ref() == Some(&root.resolved)
                && identity_for_path(&root.original, true).ok() == Some(root.identity)
                && std::path::absolute(&root.original).is_ok_and(|original| {
                    !excluded(&original, &root.resolved, &scanner.excluded_paths)
                })
        });
        if !admitted {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(resolved)
    }

    /// A cheap queue filter; mutation still requires current filesystem proof.
    /// A zero-byte estimate needs an observed directory: removing its own inode
    /// can relieve exhaustion without claiming any allocated-byte yield.
    #[must_use]
    pub fn accepts_candidate(&self, candidate: &CandidacyScore) -> bool {
        self.remaining_artifacts() > 0
            && (candidate.size_bytes > 0
                || candidate
                    .identity
                    .is_some_and(|identity| identity.kind == FsEntryKind::Directory))
            && !candidate.vetoed
            && candidate.decision.action == DecisionAction::Delete
            && candidate.decision.certainty == ArtifactCertainty::Definite
            && !candidate.decision.category_suspended
            && candidate
                .identity
                .is_some_and(|identity| identity.device_id == self.device_id)
    }

    /// Preserve definite-artifact and exact-device admission for held entries.
    /// Zero-byte relief still requires a matching observed directory, rather
    /// than inferring inode yield from a historical size estimate.
    #[must_use]
    pub fn accepts_quarantined(&self, record: &QuarantineRecord, category_suspended: bool) -> bool {
        self.remaining_artifacts() > 0
            && record.device_id == self.device_id
            && record.definite_category().is_some()
            && !category_suspended
            && (record.size_bytes > 0
                || identity_for_path(&record.quarantine_path, false).is_ok_and(|identity| {
                    identity.device_id == record.device_id
                        && identity.inode == record.inode
                        && identity.kind == FsEntryKind::Directory
                }))
    }

    /// Renew the absent original leaf's parent/root identity and exclusions.
    /// A store beneath an admitted root cannot override a revoked child path.
    pub fn authorize_quarantine_scope(
        &self,
        record: &QuarantineRecord,
        scanner: &ScannerConfig,
    ) -> Result<PathBuf, SkipReason> {
        let original =
            std::path::absolute(&record.original_path).map_err(|_| SkipReason::PolicyChanged)?;
        let parent = original.parent().ok_or(SkipReason::PolicyChanged)?;
        let name = original.file_name().ok_or(SkipReason::PolicyChanged)?;
        let resolved = self.authorize_scope(parent, scanner)?.join(name);
        if excluded(&original, &resolved, &scanner.excluded_paths) {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(resolved)
    }

    /// Nested mounts and symlink aliases cannot widen the sampled device.
    #[must_use]
    pub fn contains_path(&self, path: &Path) -> bool {
        path.symlink_metadata().is_ok_and(|metadata| {
            if metadata.file_type().is_symlink() {
                // Configured root aliases are supported, but a child symlink
                // is never a new traversal surface.
                self.roots.iter().any(|root| {
                    root.original == path
                        && std::fs::canonicalize(path).ok().as_ref() == Some(&root.resolved)
                        && identity_for_path(path, true).ok() == Some(root.identity)
                })
            } else {
                device_id(&metadata) == self.device_id
            }
        })
    }

    /// Renew the actual inode goal and mounted-device evidence. Finishing this
    /// pass revokes its permission without backing off any artifact. The byte
    /// cleanup reason `TargetFreeReached` intentionally has different retry
    /// semantics and must not be used for this resource-scoped deferral.
    pub fn authorize_mount(&self, platform: &dyn Platform) -> Result<(), SkipReason> {
        if self.remaining_artifacts() == 0 {
            return Err(SkipReason::PolicyChanged);
        }
        if !self.contains_path(&self.mount)
            || self.total == 0
            || self.target_available == 0
            || self.target_available > self.total
        {
            return Err(SkipReason::PolicyChanged);
        }
        let capacity = platform
            .fs_stats(&self.mount)
            .map_err(|_| SkipReason::PolicyChanged)?;
        if capacity.is_readonly || capacity.mount_point != self.mount {
            return Err(SkipReason::PolicyChanged);
        }
        self.authorize_capacity(platform, &self.mount)
    }

    fn authorize_capacity(&self, platform: &dyn Platform, path: &Path) -> Result<(), SkipReason> {
        let sample = platform
            .inode_stats(path)
            .ok()
            .flatten()
            .and_then(crate::platform::pal::InodeStats::validated)
            .ok_or(SkipReason::PolicyChanged)?;
        // A resize or changed mount needs a newly sampled request and goal.
        if sample.total != self.total {
            return Err(SkipReason::PolicyChanged);
        }
        if sample.available >= self.target_available {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(())
    }

    /// Refresh both the live resource shortage and the exact candidate before
    /// each mutation. The executor retains every other safety and policy rail.
    pub fn authorize(
        &self,
        candidate: &CandidacyScore,
        platform: &dyn Platform,
    ) -> Result<(), SkipReason> {
        self.authorize_mount(platform)?;
        if !self.accepts_candidate(candidate)
            || identity_for_path(&candidate.path, false).ok() != candidate.identity
        {
            return Err(SkipReason::PolicyChanged);
        }
        let capacity = platform
            .fs_stats(&candidate.path)
            .map_err(|_| SkipReason::PolicyChanged)?;
        if capacity.is_readonly || capacity.mount_point != self.mount {
            return Err(SkipReason::PolicyChanged);
        }
        self.authorize_capacity(platform, &candidate.path)
    }

    /// Charge one actual unlink, not the number of inodes supposedly freed.
    /// A later batch must still observe the current inode goal independently.
    pub fn record_unlinked(&self) {
        let _ = self
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                Some(remaining.saturating_sub(1))
            });
    }
}

fn excluded(original: &Path, resolved: &Path, exclusions: &[PathBuf]) -> bool {
    exclusions.iter().any(|exclusion| {
        let Ok(absolute) = std::path::absolute(exclusion) else {
            return true;
        };
        let canonical = std::fs::canonicalize(exclusion).ok();
        [Some(absolute.as_path()), canonical.as_deref()]
            .into_iter()
            .flatten()
            .any(|excluded| {
                original == excluded
                    || resolved == excluded
                    || (excluded.parent().is_some()
                        && (original.starts_with(excluded) || resolved.starts_with(excluded)))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    use crate::platform::pal::{
        FsStats, InodeStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths, ServiceManager,
    };
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

    fn platform(root: &Path, sample: Option<InodeStats>) -> MockPlatform {
        MockPlatform::new(
            vec![MountPoint {
                path: root.to_path_buf(),
                device: "fixture".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            }],
            HashMap::from([(
                root.to_path_buf(),
                FsStats {
                    total_bytes: 100_000,
                    free_bytes: 70_000,
                    available_bytes: 70_000,
                    fs_type: "ext4".to_string(),
                    mount_point: root.to_path_buf(),
                    is_readonly: false,
                },
            )]),
            MemoryInfo {
                total_bytes: 64_000,
                available_bytes: 32_000,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        )
        .with_inode_stats(
            sample
                .map(|sample| HashMap::from([(root.to_path_buf(), sample)]))
                .unwrap_or_default(),
        )
    }

    fn request(root: &Path, candidate: &CandidacyScore, allowance: usize) -> InodeReclaimRequest {
        InodeReclaimRequest::new(
            root.to_path_buf(),
            candidate.identity.unwrap().device_id,
            10_000,
            1_050,
            allowance,
            &InodePressureConfig::default(),
            &[root.to_path_buf()],
        )
    }

    #[test]
    fn inode_exhaustion_authorizes_existing_artifacts_with_healthy_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = request(temp.path(), &candidate, 2);
        let pal = platform(temp.path(), InodeStats::new(10_000, 0, 0));
        assert_eq!(request.authorize(&candidate, &pal), Ok(()));
        assert!((pal.fs_stats(temp.path()).unwrap().free_pct() - 70.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fresh_recovery_missing_invalid_and_changed_capacity_revoke_queued_work() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = request(temp.path(), &candidate, 2);
        let recovered = platform(temp.path(), InodeStats::new(10_000, 1_050, 1_050));
        assert_eq!(
            request.authorize(&candidate, &recovered),
            Err(SkipReason::PolicyChanged)
        );
        for sample in [
            None,
            InodeStats::new(20_000, 0, 0),
            Some(InodeStats {
                total: 0,
                free: 0,
                available: 0,
            }),
            Some(InodeStats {
                total: 10_000,
                free: 10_001,
                available: 0,
            }),
            Some(InodeStats {
                total: u64::MAX,
                free: 0,
                available: 0,
            }),
        ] {
            assert_eq!(
                request.authorize(&candidate, &platform(temp.path(), sample)),
                Err(SkipReason::PolicyChanged)
            );
        }
        assert!(candidate.path.exists());
    }

    #[test]
    fn zero_byte_directory_authority_requires_identity_and_live_inode_pressure() {
        let temp = tempfile::tempdir().unwrap();
        let mut candidate = candidate(temp.path().join("target"));
        candidate.size_bytes = 0;
        let request = request(temp.path(), &candidate, 2);
        let exhausted = platform(temp.path(), InodeStats::new(10_000, 0, 0));
        assert!(request.accepts_candidate(&candidate));
        assert_eq!(request.authorize(&candidate, &exhausted), Ok(()));
        assert!((exhausted.fs_stats(temp.path()).unwrap().free_pct() - 70.0).abs() < f64::EPSILON);
        for kind in [FsEntryKind::File, FsEntryKind::Symlink, FsEntryKind::Other] {
            let mut altered = candidate.clone();
            altered.identity.as_mut().unwrap().kind = kind;
            assert!(!request.accepts_candidate(&altered));
            assert_eq!(
                request.authorize(&altered, &exhausted),
                Err(SkipReason::PolicyChanged)
            );
        }
        let recovered = platform(temp.path(), InodeStats::new(10_000, 1_050, 1_050));
        assert_eq!(
            request.authorize(&candidate, &recovered),
            Err(SkipReason::PolicyChanged)
        );
        assert_eq!(candidate.size_bytes, 0);
        assert!(candidate.path.exists());
    }

    #[test]
    fn uncertain_vetoed_and_foreign_device_candidates_stay_protected() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = request(temp.path(), &candidate, 2);
        for size_bytes in [0, candidate.size_bytes] {
            for changed in 0..7 {
                let mut altered = candidate.clone();
                altered.size_bytes = size_bytes;
                match changed {
                    0 => altered.decision.certainty = ArtifactCertainty::Likely,
                    1 => altered.vetoed = true,
                    2 => altered.decision.category_suspended = true,
                    3 => altered.identity = None,
                    4 => altered.identity.as_mut().unwrap().device_id ^= 1,
                    5 => altered.decision.action = DecisionAction::Keep,
                    _ => altered.decision.action = DecisionAction::Review,
                }
                assert!(!request.accepts_candidate(&altered));
            }
        }
    }

    #[test]
    fn quarantined_inode_relief_requires_definite_evidence_and_real_zero_byte_directory() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = request(temp.path(), &candidate, 1);
        let store = crate::scanner::quarantine::QuarantineStore::under(temp.path());
        let mut record = store
            .quarantine(
                &candidate.path,
                "inode-admission",
                0,
                Duration::from_hours(24),
                Some(serde_json::json!({"category": "RustTarget", "certainty": "Definite"})),
            )
            .unwrap();
        assert!(request.accepts_quarantined(&record, false));
        assert!(!request.accepts_quarantined(&record, true));
        record.device_id ^= 1;
        assert!(!request.accepts_quarantined(&record, false));
        record.device_id ^= 1;
        for snapshot in [
            None,
            Some(serde_json::json!({"category": "RustTarget", "certainty": "Likely"})),
            Some(serde_json::json!({"category": "Unknown", "certainty": "Definite"})),
        ] {
            record.decision = snapshot;
            assert!(!request.accepts_quarantined(&record, false));
        }
        record.decision =
            Some(serde_json::json!({"category": "RustTarget", "certainty": "Definite"}));
        let original_inode = record.inode;
        record.inode ^= 1;
        assert!(!request.accepts_quarantined(&record, false));
        record.inode = original_inode;
        let file = temp.path().join("empty.o");
        fs::write(&file, b"").unwrap();
        let held_file = store
            .quarantine(
                &file,
                "zero-file",
                0,
                Duration::ZERO,
                record.decision.clone(),
            )
            .unwrap();
        assert!(!request.accepts_quarantined(&held_file, false));
        request.record_unlinked();
        assert!(!request.accepts_quarantined(&record, false));
        assert!(record.quarantine_path.exists());
        assert!(held_file.quarantine_path.exists());
        assert!(store.stuck_entries().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn quarantined_inode_scope_checks_absent_original_leaf_and_root_alias() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let alias = temp.path().join("alias");
        fs::create_dir_all(root.join("project")).unwrap();
        let resolved_root = fs::canonicalize(&root).unwrap();
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let candidate = candidate(alias.join("project/target"));
        let request = InodeReclaimRequest::new(
            root.clone(),
            candidate.identity.unwrap().device_id,
            10_000,
            1_050,
            1,
            &InodePressureConfig::default(),
            std::slice::from_ref(&alias),
        );
        let store = crate::scanner::quarantine::QuarantineStore::under(&root);
        let record = store
            .quarantine(
                &candidate.path,
                "inode-scope",
                candidate.size_bytes,
                Duration::ZERO,
                None,
            )
            .unwrap();
        let mut scanner = ScannerConfig {
            root_paths: vec![alias.clone()],
            excluded_paths: Vec::new(),
            ..ScannerConfig::default()
        };
        assert!(!record.original_path.exists());
        assert_eq!(
            request.authorize_quarantine_scope(&record, &scanner),
            Ok(resolved_root.join("project/target")),
        );
        for excluded in [
            alias.join("project/target"),
            resolved_root.join("project/target"),
        ] {
            scanner.excluded_paths = vec![excluded];
            assert_eq!(
                request.authorize_quarantine_scope(&record, &scanner),
                Err(SkipReason::PolicyChanged),
            );
        }
        scanner.excluded_paths.clear();
        let replacement = temp.path().join("replacement");
        fs::create_dir_all(replacement.join("project")).unwrap();
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        assert_eq!(
            request.authorize_quarantine_scope(&record, &scanner),
            Err(SkipReason::PolicyChanged),
        );
        assert!(record.quarantine_path.exists());
    }

    #[test]
    fn replaced_identity_cannot_reuse_inode_pressure_authority() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = request(temp.path(), &candidate, 2);
        fs::rename(&candidate.path, temp.path().join("saved")).unwrap();
        fs::create_dir(&candidate.path).unwrap();
        let pal = platform(temp.path(), InodeStats::new(10_000, 0, 0));
        assert_eq!(
            request.authorize(&candidate, &pal),
            Err(SkipReason::PolicyChanged)
        );
        assert!(temp.path().join("saved/artifact").exists());
    }

    #[test]
    fn disabling_or_changing_inode_policy_revokes_a_queued_pass() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = request(temp.path(), &candidate, 2);
        let mut config = InodePressureConfig::default();
        assert_eq!(request.authorize_policy(&config), Ok(()));
        config.enabled = false;
        assert_eq!(
            request.authorize_policy(&config),
            Err(SkipReason::PolicyChanged)
        );
        config.enabled = true;
        config.green_min_free_pct = 8.0;
        assert_eq!(
            request.authorize_policy(&config),
            Err(SkipReason::PolicyChanged)
        );
    }

    #[cfg(unix)]
    #[test]
    fn scope_rejects_child_escape_root_retarget_and_both_exclusion_spellings() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let own = candidate(root.join("target"));
        let foreign = candidate(outside.join("target"));
        symlink(&outside, root.join("escape")).unwrap();
        let request = request(&root, &own, 2);
        let mut scanner = ScannerConfig {
            root_paths: vec![root.clone()],
            excluded_paths: vec![],
            ..ScannerConfig::default()
        };
        assert_eq!(
            request.authorize_scope(&own.path, &scanner),
            Ok(own.path.clone())
        );
        assert_eq!(
            request.authorize_scope(&root.join("escape/target"), &scanner),
            Err(SkipReason::PolicyChanged)
        );
        scanner.excluded_paths = vec![own.path.clone()];
        assert_eq!(
            request.authorize_scope(&own.path, &scanner),
            Err(SkipReason::PolicyChanged)
        );

        let alias = temp.path().join("alias");
        symlink(&root, &alias).unwrap();
        let alias_request = InodeReclaimRequest::new(
            temp.path().to_path_buf(),
            own.identity.unwrap().device_id,
            10_000,
            1_050,
            2,
            &InodePressureConfig::default(),
            std::slice::from_ref(&alias),
        );
        scanner.root_paths = vec![alias.clone()];
        scanner.excluded_paths = vec![own.path.clone()];
        assert_eq!(
            alias_request.authorize_scope(&alias.join("target"), &scanner),
            Err(SkipReason::PolicyChanged)
        );
        scanner.excluded_paths = vec![alias.join("target")];
        assert_eq!(
            alias_request.authorize_scope(&own.path, &scanner),
            Err(SkipReason::PolicyChanged)
        );
        scanner.excluded_paths.clear();
        assert!(
            alias_request
                .authorize_scope(&alias.join("target"), &scanner)
                .is_ok()
        );
        fs::rename(&alias, temp.path().join("saved-alias")).unwrap();
        symlink(&outside, &alias).unwrap();
        assert_eq!(
            alias_request.authorize_scope(&foreign.path, &scanner),
            Err(SkipReason::PolicyChanged)
        );
        assert!(foreign.path.exists());
    }

    #[test]
    fn zero_byte_unlinks_spend_one_shared_pass_allowance_without_inode_estimates() {
        let temp = tempfile::tempdir().unwrap();
        let mut first = candidate(temp.path().join("first-target"));
        let mut second = candidate(temp.path().join("second-target"));
        first.size_bytes = 0;
        second.size_bytes = 0;
        let request = request(temp.path(), &first, 1);
        let queued_batch = request.clone();
        let pal = platform(temp.path(), InodeStats::new(10_000, 0, 0));
        let executor = DeletionExecutor::new(
            DeletionConfig {
                min_score: 0.0,
                check_open_files: false,
                require_identity: true,
                ..DeletionConfig::default()
            },
            None,
        );
        let plan = executor.plan(vec![first.clone()]);
        assert_eq!(plan.total_reclaimable_bytes, 0);
        let report = executor.execute_with_hooks(
            &plan,
            None,
            Some(&|candidate| request.authorize(candidate, &pal)),
            Some(&|_, _| request.record_unlinked()),
        );
        assert_eq!(report.items_deleted, 1);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(queued_batch.remaining_artifacts(), 0);
        let later_plan = executor.plan(vec![second.clone()]);
        let later_report = executor.execute_with_hooks(
            &later_plan,
            None,
            Some(&|candidate| queued_batch.authorize(candidate, &pal)),
            Some(&|_, _| queued_batch.record_unlinked()),
        );
        assert_eq!(later_report.items_deleted, 0);
        assert_eq!(later_report.items_failed, 0);
        assert_eq!(
            later_report.skipped_by_reason.get("policy_changed"),
            Some(&1)
        );
        assert!(later_report.backoff_candidates.is_empty());
        assert!(!first.path.exists());
        assert!(second.path.exists());
        assert_eq!(
            queued_batch.authorize_mount(&pal),
            Err(SkipReason::PolicyChanged)
        );
    }

    struct ChangingInodes {
        base: MockPlatform,
        available: AtomicU64,
    }

    impl Platform for ChangingInodes {
        fn fs_stats(&self, path: &Path) -> crate::core::errors::Result<FsStats> {
            self.base.fs_stats(path)
        }
        fn inode_stats(&self, _path: &Path) -> crate::core::errors::Result<Option<InodeStats>> {
            let available = self.available.load(Ordering::Acquire);
            Ok(InodeStats::new(10_000, available, available))
        }
        fn mount_points(&self) -> crate::core::errors::Result<Vec<MountPoint>> {
            self.base.mount_points()
        }
        fn is_ram_backed(&self, path: &Path) -> crate::core::errors::Result<bool> {
            self.base.is_ram_backed(path)
        }
        fn default_paths(&self) -> PlatformPaths {
            self.base.default_paths()
        }
        fn memory_info(&self) -> crate::core::errors::Result<MemoryInfo> {
            self.base.memory_info()
        }
        fn service_manager(&self) -> Box<dyn ServiceManager> {
            self.base.service_manager()
        }
    }

    #[test]
    fn real_unlink_stops_next_candidate_when_fresh_inode_goal_recovers() {
        let temp = tempfile::tempdir().unwrap();
        let first = candidate(temp.path().join("first-target"));
        let second = candidate(temp.path().join("second-target"));
        let request = request(temp.path(), &first, 10);
        let pal = ChangingInodes {
            base: platform(temp.path(), None),
            available: AtomicU64::new(0),
        };
        let executor = DeletionExecutor::new(
            DeletionConfig {
                min_score: 0.0,
                check_open_files: false,
                require_identity: true,
                ..DeletionConfig::default()
            },
            None,
        );
        let plan = executor.plan(vec![first.clone(), second.clone()]);
        let report = executor.execute_with_hooks(
            &plan,
            None,
            Some(&|candidate| request.authorize(candidate, &pal)),
            Some(&|_, _| {
                request.record_unlinked();
                pal.available.store(1_050, Ordering::Release);
            }),
        );
        assert_eq!(report.items_deleted, 1);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.skipped_by_reason.get("policy_changed"), Some(&1));
        assert!(report.backoff_candidates.is_empty());
        assert_eq!(request.remaining_artifacts(), 9);
        assert_eq!(
            usize::from(first.path.exists()) + usize::from(second.path.exists()),
            1
        );
    }
}
