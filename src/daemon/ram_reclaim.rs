//! Bounded reclaim of already-authorized tmpfs artifacts when swap is short.
//!
//! Filesystem capacity is not physical backing capacity. A tmpfs can have
//! plenty of free blocks while its pages exhaust swap. This permission carries
//! that separate reason through the scanner queue, without inventing disk
//! counters, admitting new roots, or relaxing the artifact safety checks.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::core::config::ScannerConfig;
use crate::monitor::fs_stats::ObservedDirectory;
use crate::monitor::ram_scratch::swap_reclaim_pressure;
use crate::platform::pal::Platform;
use crate::scanner::deletion::SkipReason;
use crate::scanner::quarantine::QuarantineRecord;
use crate::scanner::scoring::{ArtifactCertainty, CandidacyScore, DecisionAction};
use crate::scanner::walker::{FsIdentity, device_id, identity_for_path};

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmittedRoot {
    original: PathBuf,
    resolved: PathBuf,
    identity: FsIdentity,
}

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
    roots: Vec<AdmittedRoot>,
}

impl RamReclaimRequest {
    /// Capture a bounded pass on one admitted tmpfs filesystem.
    ///
    /// The caller obtains `device_id` from the admitted mount and caps
    /// `target_bytes` by both occupied tmpfs blocks and the swap shortfall.
    /// Resolve existing configured roots now so a later root or alias change
    /// cannot extend this pass's scope.
    #[must_use]
    pub fn new(mount: PathBuf, device_id: u64, target_bytes: u64, roots: &[PathBuf]) -> Self {
        let roots = roots
            .iter()
            .filter_map(|root| ObservedDirectory::collect(root))
            .collect::<Vec<_>>();
        Self::from_observed_roots(mount, device_id, target_bytes, &roots)
    }

    /// Build pressure authority from already-completed directory observations.
    /// Unknown roots stay absent; this constructor never performs native I/O.
    pub(super) fn from_observed_roots(
        mount: PathBuf,
        device_id: u64,
        target_bytes: u64,
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
            remaining: Arc::new(AtomicU64::new(target_bytes)),
            roots,
        }
    }

    /// The original pass's byte allowance that successful unlinks have not used.
    #[must_use]
    pub fn remaining_bytes(&self) -> u64 {
        self.remaining.load(Ordering::Acquire)
    }

    /// Continue a completed quarantine pass only when this fresh observation
    /// captured the same mount, device and root identities. Compare retained
    /// evidence without filesystem I/O on the monitor thread, and preserve the
    /// newer pass's tighter allowance if the backing shortfall has decreased.
    pub(super) fn share_remaining_allowance(&mut self, previous: &Self) {
        if self.mount == previous.mount
            && self.device_id == previous.device_id
            && self.roots == previous.roots
        {
            previous
                .remaining
                .fetch_min(self.remaining_bytes(), Ordering::AcqRel);
            self.remaining = Arc::clone(&previous.remaining);
        }
    }

    /// Renew the admitted root's original alias, canonical directory identity,
    /// and exclusions in both spellings. A same-device parent symlink can move
    /// an unchanged artifact outside the root without changing its identity.
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

    /// Whether an observed candidate belongs to this pass's narrower scope.
    /// This is only a queue filter; the executor renews [`Self::authorize_scope`]
    /// and [`Self::authorize`] at the mutation boundary.
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

    /// A held artifact must retain this resource pass's narrower admission.
    /// The caller supplies the current category suspension and still renews
    /// original scope and backing pressure at the purge boundary.
    #[must_use]
    pub fn accepts_quarantined(&self, record: &QuarantineRecord, category_suspended: bool) -> bool {
        self.remaining_bytes() > 0
            && record.size_bytes > 0
            && record.device_id == self.device_id
            && record.definite_category().is_some()
            && !category_suspended
    }

    /// Renew the original artifact's scope even though its leaf was renamed.
    /// Checking only the store would miss a newly excluded original subtree.
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

    /// A device check for shallow discovery and requested roots. Only a
    /// still-valid configured root alias may itself be a symlink. A nested
    /// disk mount cannot become a RAM relief surface even when the operator
    /// normally allows cross-device scanning.
    #[must_use]
    pub fn contains_path(&self, path: &Path) -> bool {
        path.symlink_metadata().is_ok_and(|metadata| {
            if metadata.file_type().is_symlink() {
                // A configured root alias retains its original scope only
                // while its target and directory identity remain unchanged.
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
        if stats.mount_point != self.mount
            || stats.fs_type != "tmpfs"
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
        if stats.mount_point != self.mount
            || stats.fs_type != "tmpfs"
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
        self.record_unlinked_bytes(candidate.size_bytes);
    }

    /// Charge completed quarantine removals against the same pass allowance.
    /// Rename-only and partially purged entries have not completed reclamation
    /// and must not be credited here.
    pub fn record_unlinked_bytes(&self, bytes: u64) {
        let _ = self
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                Some(remaining.saturating_sub(bytes))
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
            &[temp.path().to_path_buf()],
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
            &[temp.path().to_path_buf()],
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
            &[temp.path().to_path_buf()],
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
    fn quarantined_ram_relief_requires_definite_unsuspended_same_device_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            candidate.size_bytes,
            &[temp.path().to_path_buf()],
        );
        let store = crate::scanner::quarantine::QuarantineStore::under(temp.path());
        let mut record = store
            .quarantine(
                &candidate.path,
                "ram-admission",
                candidate.size_bytes,
                Duration::from_hours(24),
                Some(serde_json::json!({"category": "GoCache", "certainty": "Definite"})),
            )
            .unwrap();
        assert!(request.accepts_quarantined(&record, false));
        assert!(!request.accepts_quarantined(&record, true));
        record.size_bytes = 0;
        assert!(!request.accepts_quarantined(&record, false));
        record.size_bytes = candidate.size_bytes;
        record.device_id ^= 1;
        assert!(!request.accepts_quarantined(&record, false));
        record.device_id ^= 1;
        for snapshot in [
            None,
            Some(serde_json::json!({"category": "GoCache"})),
            Some(serde_json::json!({"category": "GoCache", "certainty": "Likely"})),
            Some(serde_json::json!({"category": "GoCache", "certainty": "Unclear"})),
            Some(serde_json::json!({"category": "GoCache", "certainty": "definite"})),
            Some(serde_json::json!({"category": "Unknown", "certainty": "Definite"})),
            Some(serde_json::json!({"category": "unknown-category", "certainty": "Definite"})),
            Some(serde_json::json!({"category": 1, "certainty": "Definite"})),
        ] {
            record.decision = snapshot;
            assert!(!request.accepts_quarantined(&record, false));
        }
        record.decision = Some(serde_json::json!({"category": "GoCache", "certainty": "Definite"}));
        request.record_unlinked_bytes(record.size_bytes);
        assert!(!request.accepts_quarantined(&record, false));
        assert!(record.quarantine_path.exists());
        assert!(store.stuck_entries().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn quarantined_ram_scope_checks_absent_original_leaf_and_root_alias() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let alias = temp.path().join("alias");
        fs::create_dir_all(root.join("project")).unwrap();
        let resolved_root = fs::canonicalize(&root).unwrap();
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let candidate = candidate(alias.join("project/target"));
        let request = RamReclaimRequest::new(
            root.clone(),
            candidate.identity.unwrap().device_id,
            candidate.size_bytes,
            std::slice::from_ref(&alias),
        );
        let store = crate::scanner::quarantine::QuarantineStore::under(&root);
        let record = store
            .quarantine(
                &candidate.path,
                "ram-scope",
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
    fn matching_device_cannot_authorize_a_different_tmpfs_mount() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let nested = root.join("nested");
        fs::create_dir(&nested).unwrap();
        let artifact = candidate(nested.join("target"));
        let request = RamReclaimRequest::new(
            root.clone(),
            artifact.identity.unwrap().device_id,
            artifact.size_bytes,
            std::slice::from_ref(&root),
        );
        let base = platform(&root, memory(1), "tmpfs");
        assert_eq!(request.authorize(&artifact, &base), Ok(()));
        assert!(request.contains_path(&artifact.path));
        let root_stats = base.fs_stats(&root).unwrap();
        let nested_stats = FsStats {
            mount_point: nested.clone(),
            ..root_stats.clone()
        };
        let mismatched = MockPlatform::new(
            base.mount_points().unwrap(),
            HashMap::from([(root.clone(), nested_stats.clone())]),
            memory(1),
            PlatformPaths::default(),
        );
        assert_eq!(
            request.authorize_mount(&mismatched),
            Err(SkipReason::PolicyChanged)
        );

        // Bind aliases share the real device; their mount points still differ.
        let mut mounts = base.mount_points().unwrap();
        mounts.push(MountPoint {
            path: nested.clone(),
            device: "fixture-alias".to_string(),
            fs_type: "tmpfs".to_string(),
            is_ram_backed: true,
        });
        let aliased = MockPlatform::new(
            mounts,
            HashMap::from([(root, root_stats), (nested, nested_stats)]),
            memory(1),
            PlatformPaths::default(),
        );
        assert_eq!(request.authorize_mount(&aliased), Ok(()));
        assert_eq!(
            request.authorize(&artifact, &aliased),
            Err(SkipReason::PolicyChanged)
        );
        assert!(artifact.path.join("artifact").exists());
        assert_eq!(request.remaining_bytes(), artifact.size_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn stable_root_alias_honors_both_exclusion_spellings_and_allows_real_reclaim() {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().canonicalize().unwrap();
        let root = mount.join("actual");
        fs::create_dir(&root).unwrap();
        let artifact = candidate(root.join("target"));
        let alias = mount.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let mut through_alias = artifact.clone();
        through_alias.path = alias.join("target");
        let mut scanner = ScannerConfig {
            root_paths: vec![alias.clone()],
            excluded_paths: Vec::new(),
            ..ScannerConfig::default()
        };
        let request = RamReclaimRequest::new(
            mount.clone(),
            artifact.identity.unwrap().device_id,
            artifact.size_bytes,
            &scanner.root_paths,
        );
        assert!(request.contains_path(&alias));
        assert_eq!(
            request.authorize_scope(&through_alias.path, &scanner),
            Ok(artifact.path.clone())
        );
        for exclusion in [&artifact.path, &through_alias.path, &root, &alias] {
            scanner.excluded_paths = vec![exclusion.clone()];
            for path in [&artifact.path, &through_alias.path] {
                assert_eq!(
                    request.authorize_scope(path, &scanner),
                    Err(SkipReason::PolicyChanged)
                );
            }
        }
        scanner.excluded_paths.clear();
        let child_alias = root.join("child-alias");
        std::os::unix::fs::symlink(&artifact.path, &child_alias).unwrap();
        assert!(!request.contains_path(&child_alias));

        let executor = DeletionExecutor::new(
            DeletionConfig {
                check_open_files: false,
                require_identity: true,
                ..DeletionConfig::default()
            },
            None,
        );
        let pal = platform(&mount, memory(1), "tmpfs");
        let plan = executor.plan(vec![through_alias]);
        assert_eq!(plan.candidates.len(), 1);
        let report = executor.execute_with_hooks(
            &plan,
            None,
            Some(&|candidate| {
                request.authorize_scope(&candidate.path, &scanner)?;
                request.authorize(candidate, &pal)?;
                request
                    .authorize_scope(&candidate.path, &scanner)
                    .map(|_| ())
            }),
            Some(&|candidate, _| request.record_unlinked(candidate)),
        );
        assert_eq!(report.items_deleted, 1);
        assert_eq!(report.items_failed, 0);
        assert!(!artifact.path.exists());
        assert_eq!(request.remaining_bytes(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn root_replacement_and_alias_retarget_revoke_an_unchanged_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().canonicalize().unwrap();
        let root = mount.join("allowed");
        fs::create_dir(&root).unwrap();
        let artifact = candidate(root.join("target"));
        let root_identity = identity_for_path(&root, true).unwrap();
        let alias = mount.join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let scanner = ScannerConfig {
            root_paths: vec![root.clone()],
            excluded_paths: Vec::new(),
            ..ScannerConfig::default()
        };
        let alias_scanner = ScannerConfig {
            root_paths: vec![alias.clone()],
            ..scanner.clone()
        };
        let request = RamReclaimRequest::new(
            mount.clone(),
            root_identity.device_id,
            artifact.size_bytes,
            &scanner.root_paths,
        );
        let alias_request = RamReclaimRequest::new(
            mount.clone(),
            root_identity.device_id,
            artifact.size_bytes,
            &alias_scanner.root_paths,
        );
        assert!(request.authorize_scope(&artifact.path, &scanner).is_ok());
        assert!(alias_request.contains_path(&alias));

        // An unchanged canonical spelling and leaf inode are insufficient
        // when the admitted directory itself has been replaced.
        let saved_root = mount.join("saved-root");
        fs::rename(&root, &saved_root).unwrap();
        fs::create_dir(&root).unwrap();
        fs::rename(saved_root.join("target"), &artifact.path).unwrap();
        assert_eq!(
            identity_for_path(&artifact.path, false).ok(),
            artifact.identity
        );
        assert_eq!(artifact.path.canonicalize().unwrap(), artifact.path);
        assert_eq!(
            request.authorize_scope(&artifact.path, &scanner),
            Err(SkipReason::PolicyChanged)
        );
        assert!(!alias_request.contains_path(&alias));

        // Restore the original root and artifact identities behind a new
        // alias target: the admitted canonical location must still match.
        fs::rename(&artifact.path, saved_root.join("target")).unwrap();
        fs::rename(&alias, mount.join("saved-alias")).unwrap();
        std::os::unix::fs::symlink(&saved_root, &alias).unwrap();
        assert_eq!(identity_for_path(&alias, true).ok(), Some(root_identity));
        assert_eq!(
            identity_for_path(&alias.join("target"), false).ok(),
            artifact.identity
        );
        assert!(!alias_request.contains_path(&alias));
        assert_eq!(
            alias_request.authorize_scope(&alias.join("target"), &alias_scanner),
            Err(SkipReason::PolicyChanged)
        );
        assert!(saved_root.join("target/artifact").exists());
        assert_eq!(request.remaining_bytes(), artifact.size_bytes);
        assert_eq!(alias_request.remaining_bytes(), artifact.size_bytes);
    }

    #[test]
    fn successful_unlinks_share_one_saturating_allowance_across_batches() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = candidate(temp.path().join("target"));
        let request = RamReclaimRequest::new(
            temp.path().to_path_buf(),
            candidate.identity.unwrap().device_id,
            5000,
            &[temp.path().to_path_buf()],
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
            &[temp.path().to_path_buf()],
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
            &[temp.path().to_path_buf()],
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
            &[temp.path().to_path_buf()],
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
