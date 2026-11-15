//! Exact-filesystem authority for automatic cleanup.
//!
//! A pressured mount may authorize traversal through a configured ancestor,
//! but only artifacts on that mount may use its pressure or forecast. The
//! immutable admission crosses scanner queues and is renewed before mutation.
//! It holds observations, never directory descriptors that could block eject.

use std::path::{Component, Path, PathBuf};

use crate::core::config::ScannerConfig;
use crate::monitor::fs_stats::{FsStatsSample, ObservedDirectory, kernel_mount_id_for_path};
use crate::platform::pal::{FsStats, MountPoint, Platform};
use crate::scanner::deletion::SkipReason;
use crate::scanner::scoring::CandidacyScore;
use crate::scanner::walker::{FsEntryKind, identity_for_path};

#[derive(Debug, Clone)]
struct AdmittedRoot {
    selected: ObservedDirectory,
    configured: Option<ObservedDirectory>,
    lookup: PathBuf,
    owner: MountPoint,
}

/// A pressure observation and the already-authorized directories it may use.
/// Resource-specific permissions remain separate and intersect this scope.
#[derive(Debug, Clone)]
pub struct FilesystemReclaimScope {
    owner: MountPoint,
    mount_directory: ObservedDirectory,
    mount_lookup: PathBuf,
    roots: Vec<AdmittedRoot>,
    cross_devices: bool,
    follow_symlinks: bool,
    catalog: bool,
}

impl FilesystemReclaimScope {
    /// Capture completed native observations without filesystem work on the
    /// monitor. Missing roots grant no authority; an absent mount denies the
    /// pass. `paths` remains the selected scope even when `roots` also contains
    /// observations of configured ancestors needed to verify child selections.
    pub(crate) fn from_observed_roots(
        mount: &FsStatsSample,
        paths: &[PathBuf],
        roots: &[FsStatsSample],
        scanner: &ScannerConfig,
        catalog: bool,
    ) -> Option<Self> {
        let mount_directory = verified_mount_directory(mount)?.clone();
        let owner = mount.mount_owner();
        if catalog && !scanner.catalog_roots_on_pressured_device {
            return None;
        }
        let mut admitted = Vec::new();
        for path in paths {
            let Some(sample) = observed_path(roots, path) else {
                continue;
            };
            let Some(selected) = sample.query_directory() else {
                continue;
            };
            let Some(lookup) = sample.resolved_query() else {
                continue;
            };
            let configured = if catalog {
                None
            } else {
                let Some(configured) = scanner.root_paths.iter().find_map(|root| {
                    let configured = observed_path(roots, root)?.query_directory()?;
                    (selected.original.starts_with(&configured.original)
                        && selected.resolved.starts_with(&configured.resolved)
                        && (scanner.cross_devices || same_native_mount(selected, configured)))
                    .then(|| configured.clone())
                }) else {
                    continue;
                };
                Some(configured)
            };
            let on_mount = sample.mount_owner() == owner
                && sample.mount_directory() == Some(&mount_directory)
                && same_native_mount(selected, &mount_directory);
            // Cross-device scanning is traversal permission only. A root on
            // a peer filesystem cannot contribute candidates; only a real
            // ancestor can lead the walker to the observed nested mount.
            let leads_to_mount = !catalog
                && scanner.cross_devices
                && mount.resolved_mount() != lookup
                && mount.resolved_mount().starts_with(lookup);
            if !on_mount && !leads_to_mount {
                continue;
            }
            if admitted
                .iter()
                .any(|root: &AdmittedRoot| root.selected.original == selected.original)
            {
                continue;
            }
            admitted.push(AdmittedRoot {
                selected: selected.clone(),
                configured,
                lookup: lookup.to_path_buf(),
                owner: sample.mount_owner(),
            });
        }
        (!admitted.is_empty()).then_some(Self {
            owner,
            mount_directory,
            mount_lookup: mount.resolved_mount().to_path_buf(),
            roots: admitted,
            cross_devices: scanner.cross_devices,
            follow_symlinks: scanner.follow_symlinks,
            catalog,
        })
    }

    /// The native mount whose observation admitted this cleanup.
    #[must_use]
    pub fn mount(&self) -> &Path {
        &self.owner.path
    }

    /// Pure monitor-side selection; never resolve a path on the control loop.
    #[must_use]
    pub fn admitted_paths(&self) -> Vec<PathBuf> {
        self.roots
            .iter()
            .map(|root| root.selected.original.clone())
            .collect()
    }

    /// Start an ancestor-root scan at the admitted nested mount, preserving
    /// its configured alias. This pure narrowing avoids spending the pass's
    /// budget on unrelated filesystems before reaching the reclaim surface.
    #[must_use]
    pub fn scan_paths(&self) -> Vec<PathBuf> {
        self.roots
            .iter()
            .map(|root| {
                self.mount_lookup.strip_prefix(&root.lookup).map_or_else(
                    |_| root.selected.original.clone(),
                    |relative| root.selected.original.join(relative),
                )
            })
            .collect()
    }

    /// Permit scanner discovery on the target mount or along a captured
    /// ancestor leading to it. Candidate admission below is always narrower.
    #[must_use]
    pub fn contains_path(&self, path: &Path) -> bool {
        let Ok(resolved) = std::fs::canonicalize(path) else {
            return false;
        };
        self.roots.iter().any(|root| {
            if !within_selection(root, path, &resolved)
                || !root_binding_current(root, self.follow_symlinks)
                || !traversal_allowed(&root.selected.original, path, self.follow_symlinks)
            {
                return false;
            }
            let Some(lookup) = candidate_lookup(root, &resolved) else {
                return false;
            };
            (lookup.starts_with(&self.mount_lookup) && self.path_on_mount(&resolved))
                || (self.cross_devices
                    && lookup != self.mount_lookup
                    && self.mount_lookup.starts_with(lookup))
        })
    }

    /// Queue filter for index replay, pre-scan, recursive scan and dispatch.
    /// Native mount IDs are required on Linux, including same-device binds.
    /// This never substitutes for renewing aliases and policy at mutation.
    #[must_use]
    pub fn accepts_candidate(&self, candidate: &CandidacyScore) -> bool {
        let Some(identity) = candidate.identity else {
            return false;
        };
        if !matches!(identity.kind, FsEntryKind::File | FsEntryKind::Directory)
            || identity.device_id != self.mount_directory.identity.device_id
            || identity_for_path(&candidate.path, false).ok() != Some(identity)
        {
            return false;
        }
        let Ok(resolved) = std::fs::canonicalize(&candidate.path) else {
            return false;
        };
        self.path_on_mount(&resolved)
            && self.roots.iter().any(|root| {
                within_selection(root, &candidate.path, &resolved)
                    && root_binding_current(root, self.follow_symlinks)
                    && candidate_lookup(root, &resolved)
                        .is_some_and(|path| path.starts_with(&self.mount_lookup))
                    && traversal_allowed(
                        &root.selected.original,
                        &candidate.path,
                        self.follow_symlinks,
                    )
            })
    }

    /// Renew the observed mount incarnation and coherent writable capacity.
    /// Missing or replaced evidence defers work without artifact failure debt.
    pub fn authorize_mount(&self, platform: &dyn Platform) -> Result<(), SkipReason> {
        if !self.mount_binding_current(platform) {
            return Err(SkipReason::PolicyChanged);
        }
        let stats = platform
            .observe_fs_stats(&self.owner.path)
            .map_err(|_| SkipReason::PolicyChanged)?;
        if !valid_stats(&stats, &self.owner) || !self.mount_binding_current(platform) {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(())
    }

    /// Revalidate both spellings, configured ancestor, candidate identity and
    /// exact native mount at the irreversible mutation boundary. The caller
    /// applies the existing protection/source/lease/content checks as well.
    pub fn authorize_candidate(
        &self,
        candidate: &CandidacyScore,
        scanner: &ScannerConfig,
        platform: &dyn Platform,
    ) -> Result<PathBuf, SkipReason> {
        self.authorize_mount(platform)?;
        if !self.accepts_candidate(candidate)
            || self.cross_devices != scanner.cross_devices
            || self.follow_symlinks != scanner.follow_symlinks
            || (self.catalog && !scanner.catalog_roots_on_pressured_device)
        {
            return Err(SkipReason::PolicyChanged);
        }
        let resolved = candidate
            .path
            .canonicalize()
            .map_err(|_| SkipReason::PolicyChanged)?;
        let root = self
            .roots
            .iter()
            .find(|root| {
                within_selection(root, &candidate.path, &resolved)
                    && Self::root_current(root, scanner, platform)
            })
            .ok_or(SkipReason::PolicyChanged)?;
        if excluded(&candidate.path, &resolved, &scanner.excluded_paths) {
            return Err(SkipReason::PolicyChanged);
        }
        let owner = platform
            .mount_identity(&candidate.path)
            .map_err(|_| SkipReason::PolicyChanged)?;
        let stats = platform
            .observe_fs_stats(&candidate.path)
            .map_err(|_| SkipReason::PolicyChanged)?;
        if owner != self.owner
            || !valid_stats(&stats, &self.owner)
            || !platform
                .observe_mount_lookup_path(&candidate.path)
                .is_ok_and(|path| path.starts_with(&self.mount_lookup))
            || !self.mount_binding_current(platform)
            || !Self::root_current(root, scanner, platform)
            || !self.accepts_candidate(candidate)
            || candidate.path.canonicalize().ok().as_ref() != Some(&resolved)
            || platform.mount_identity(&candidate.path).ok().as_ref() != Some(&self.owner)
        {
            return Err(SkipReason::PolicyChanged);
        }
        Ok(resolved)
    }

    fn mount_binding_current(&self, platform: &dyn Platform) -> bool {
        ObservedDirectory::collect(&self.owner.path).as_ref() == Some(&self.mount_directory)
            && platform.mount_identity(&self.owner.path).ok().as_ref() == Some(&self.owner)
            && platform
                .observe_mount_lookup_path(&self.owner.path)
                .ok()
                .as_ref()
                == Some(&self.mount_lookup)
    }

    fn root_current(root: &AdmittedRoot, scanner: &ScannerConfig, platform: &dyn Platform) -> bool {
        if !root_binding_current(root, scanner.follow_symlinks)
            || excluded(
                &root.selected.original,
                &root.selected.resolved,
                &scanner.excluded_paths,
            )
            || platform
                .mount_identity(&root.selected.original)
                .ok()
                .as_ref()
                != Some(&root.owner)
            || platform
                .observe_mount_lookup_path(&root.selected.original)
                .ok()
                .as_ref()
                != Some(&root.lookup)
        {
            return false;
        }
        root.configured.as_ref().is_none_or(|configured| {
            scanner.root_paths.contains(&configured.original)
                && !excluded(
                    &configured.original,
                    &configured.resolved,
                    &scanner.excluded_paths,
                )
                && traversal_allowed(
                    &configured.original,
                    &root.selected.original,
                    scanner.follow_symlinks,
                )
        })
    }

    fn path_on_mount(&self, resolved: &Path) -> bool {
        identity_for_path(resolved, false)
            .is_ok_and(|identity| identity.device_id == self.mount_directory.identity.device_id)
            && kernel_mount_id_for_path(resolved).is_ok_and(|mount_id| {
                mount_id == self.mount_directory.kernel_mount_id
                    && (!cfg!(target_os = "linux") || mount_id.is_some())
            })
    }
}

fn valid_stats(stats: &FsStats, owner: &MountPoint) -> bool {
    if stats.mount_point != owner.path {
        return false;
    }
    stats.fs_type == owner.fs_type
        && stats.total_bytes > 0
        && stats.free_bytes <= stats.total_bytes
        && stats.available_bytes <= stats.free_bytes
        && !stats.is_readonly
}

fn verified_mount_directory(sample: &FsStatsSample) -> Option<&ObservedDirectory> {
    let directory = sample.mount_directory()?;
    let owner = sample.mount_owner();
    (directory.original == owner.path
        && directory.identity.kind == FsEntryKind::Directory
        && (!cfg!(target_os = "linux") || directory.kernel_mount_id.is_some())
        && valid_stats(&sample.stats, &owner))
    .then_some(directory)
}

fn observed_path<'a>(samples: &'a [FsStatsSample], path: &Path) -> Option<&'a FsStatsSample> {
    samples.iter().find(|sample| {
        let Some(directory) = sample.query_directory() else {
            return false;
        };
        directory.original == path
            && directory.original.is_absolute()
            && verified_mount_directory(sample)
                .is_some_and(|mount| same_native_mount(directory, mount))
    })
}

fn same_native_mount(left: &ObservedDirectory, right: &ObservedDirectory) -> bool {
    left.identity.device_id == right.identity.device_id
        && left.kernel_mount_id == right.kernel_mount_id
        && (!cfg!(target_os = "linux") || left.kernel_mount_id.is_some())
}

fn within_selection(root: &AdmittedRoot, path: &Path, resolved: &Path) -> bool {
    path.starts_with(&root.selected.original) && resolved.starts_with(&root.selected.resolved)
}

fn candidate_lookup(root: &AdmittedRoot, resolved: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let _ = root;
        // A firmlink crossed below `/` changes namespace without changing
        // the candidate's canonical spelling. Appending its suffix to the
        // parent lookup would misattribute Data-volume paths such as /tmp.
        crate::platform::macos::sys::resolve_firmlinked_path(resolved).ok()
    }
    #[cfg(not(target_os = "macos"))]
    {
        resolved
            .strip_prefix(&root.selected.resolved)
            .ok()
            .map(|relative| root.lookup.join(relative))
    }
}

fn root_binding_current(root: &AdmittedRoot, follow_symlinks: bool) -> bool {
    ObservedDirectory::collect(&root.selected.original).as_ref() == Some(&root.selected)
        && root.configured.as_ref().is_none_or(|configured| {
            *configured == root.selected
                || (ObservedDirectory::collect(&configured.original).as_ref() == Some(configured)
                    && traversal_allowed(
                        &configured.original,
                        &root.selected.original,
                        follow_symlinks,
                    ))
        })
}

fn traversal_allowed(root: &Path, path: &Path, follow_symlinks: bool) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return false;
        }
        current.push(component);
        if !follow_symlinks
            && !std::fs::symlink_metadata(&current)
                .is_ok_and(|metadata| !metadata.file_type().is_symlink())
        {
            return false;
        }
    }
    true
}

fn excluded(original: &Path, resolved: &Path, exclusions: &[PathBuf]) -> bool {
    exclusions.iter().any(|exclusion| {
        let Ok(absolute) = std::path::absolute(exclusion) else {
            return true;
        };
        let canonical = exclusion.canonicalize().ok();
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
    use std::sync::Arc;
    use std::time::Duration;

    use crate::monitor::fs_stats::FsStatsCollector;
    use crate::platform::pal::{MemoryInfo, MockPlatform, PlatformPaths};
    use crate::scanner::patterns::ArtifactClassification;
    use crate::scanner::scoring::{
        ArtifactCertainty, DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors,
    };

    fn candidate(path: &Path) -> CandidacyScore {
        fs::create_dir(path).unwrap();
        fs::write(path.join("artifact"), [1_u8; 4096]).unwrap();
        CandidacyScore {
            identity: identity_for_path(path, false).ok(),
            path: path.to_path_buf(),
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
                summary: "filesystem scope fixture".to_string(),
            },
        }
    }

    fn platform(root: &Path, device: &str, readonly: bool) -> Arc<dyn Platform> {
        Arc::new(MockPlatform::new(
            vec![MountPoint {
                path: root.to_path_buf(),
                device: device.to_string(),
                fs_type: "fixture".to_string(),
                is_ram_backed: false,
            }],
            HashMap::from([(
                root.to_path_buf(),
                FsStats {
                    total_bytes: 100_000,
                    free_bytes: 10_000,
                    available_bytes: 9_000,
                    fs_type: "fixture".to_string(),
                    mount_point: root.to_path_buf(),
                    is_readonly: readonly,
                },
            )]),
            MemoryInfo {
                total_bytes: 100_000,
                available_bytes: 90_000,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        ))
    }

    fn scanner(roots: &[PathBuf]) -> ScannerConfig {
        ScannerConfig {
            root_paths: roots.to_vec(),
            excluded_paths: Vec::new(),
            ..ScannerConfig::default()
        }
    }

    fn capture(
        platform: Arc<dyn Platform>,
        mount: &Path,
        paths: &[PathBuf],
        scanner: &ScannerConfig,
        catalog: bool,
    ) -> FilesystemReclaimScope {
        let collector = FsStatsCollector::new(platform, Duration::ZERO);
        let mounted = collector.collect_admission_sample(mount).unwrap();
        let samples = paths
            .iter()
            .chain(scanner.root_paths.iter())
            .map(|path| collector.collect_admission_sample(path).unwrap())
            .collect::<Vec<_>>();
        FilesystemReclaimScope::from_observed_roots(&mounted, paths, &samples, scanner, catalog)
            .unwrap()
    }

    #[test]
    fn unchanged_native_scope_admits_its_candidate_and_rejects_missing_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scratch");
        fs::create_dir(&root).unwrap();
        let paths = vec![root.clone()];
        let scanner = scanner(&paths);
        let platform = platform(temp.path(), "original", false);
        let scope = capture(Arc::clone(&platform), temp.path(), &paths, &scanner, false);
        let mut item = candidate(&root.join("target"));
        assert_eq!(scope.admitted_paths(), paths);
        assert!(scope.contains_path(&root));
        assert!(scope.accepts_candidate(&item));
        assert_eq!(
            scope.authorize_candidate(&item, &scanner, platform.as_ref()),
            Ok(item.path.canonicalize().unwrap())
        );
        item.identity = None;
        assert!(!scope.accepts_candidate(&item));
    }

    #[test]
    fn selected_child_does_not_widen_to_its_configured_ancestor() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("selected");
        fs::create_dir(&selected).unwrap();
        let scanner = scanner(&[temp.path().to_path_buf()]);
        let platform = platform(temp.path(), "original", false);
        let scope = capture(
            Arc::clone(&platform),
            temp.path(),
            std::slice::from_ref(&selected),
            &scanner,
            false,
        );
        let inside = candidate(&selected.join("target"));
        let sibling = candidate(&temp.path().join("sibling-target"));
        assert_eq!(scope.admitted_paths(), vec![selected]);
        assert!(scope.accepts_candidate(&inside));
        assert!(!scope.contains_path(temp.path()));
        assert!(!scope.accepts_candidate(&sibling));
        assert!(
            scope
                .authorize_candidate(&inside, &scanner, platform.as_ref())
                .is_ok()
        );
    }

    #[test]
    fn selected_child_alias_obeys_the_configured_traversal_policy() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let alias = temp.path().join("selected-alias");
        fs::create_dir(&original).unwrap();
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        let artifact = candidate(&alias.join("target"));
        let platform = platform(temp.path(), "original", false);
        for follow_symlinks in [false, true] {
            let scanner = ScannerConfig {
                follow_symlinks,
                ..scanner(&[temp.path().to_path_buf()])
            };
            let scope = capture(
                Arc::clone(&platform),
                temp.path(),
                std::slice::from_ref(&alias),
                &scanner,
                false,
            );
            assert_eq!(scope.contains_path(&alias), follow_symlinks);
            assert_eq!(scope.accepts_candidate(&artifact), follow_symlinks);
            assert_eq!(
                scope
                    .authorize_candidate(&artifact, &scanner, platform.as_ref())
                    .is_ok(),
                follow_symlinks,
            );
        }
    }

    #[test]
    fn replaced_selected_root_cannot_borrow_an_unchanged_leaf_identity() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("selected");
        fs::create_dir(&selected).unwrap();
        let scanner = scanner(&[temp.path().to_path_buf()]);
        let platform = platform(temp.path(), "original", false);
        let scope = capture(
            Arc::clone(&platform),
            temp.path(),
            std::slice::from_ref(&selected),
            &scanner,
            false,
        );
        let item = candidate(&selected.join("target"));
        let previous = temp.path().join("previous");
        fs::rename(&selected, &previous).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::rename(previous.join("target"), &item.path).unwrap();
        assert_eq!(identity_for_path(&item.path, false).ok(), item.identity);
        assert!(!scope.contains_path(&selected));
        assert!(!scope.accepts_candidate(&item));
        assert_eq!(
            scope.authorize_candidate(&item, &scanner, platform.as_ref()),
            Err(SkipReason::PolicyChanged)
        );
    }

    #[test]
    fn configured_ancestor_replacement_revokes_an_unchanged_selected_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let selected = root.join("selected");
        fs::create_dir_all(&selected).unwrap();
        let scanner = scanner(std::slice::from_ref(&root));
        let platform = platform(temp.path(), "original", false);
        let scope = capture(
            Arc::clone(&platform),
            temp.path(),
            std::slice::from_ref(&selected),
            &scanner,
            false,
        );
        let item = candidate(&selected.join("target"));
        let previous = temp.path().join("previous-root");
        fs::rename(&root, &previous).unwrap();
        fs::create_dir(&root).unwrap();
        fs::rename(previous.join("selected"), &selected).unwrap();
        assert_eq!(identity_for_path(&item.path, false).ok(), item.identity);
        assert!(!scope.accepts_candidate(&item));
        assert_eq!(
            scope.authorize_candidate(&item, &scanner, platform.as_ref()),
            Err(SkipReason::PolicyChanged)
        );
    }

    #[test]
    fn configured_alias_is_accepted_then_revoked_when_retargeted() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let alias = temp.path().join("alias");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        symlink(&first, &alias).unwrap();
        let scanner = scanner(std::slice::from_ref(&alias));
        let platform = platform(temp.path(), "original", false);
        let scope = capture(
            Arc::clone(&platform),
            temp.path(),
            std::slice::from_ref(&alias),
            &scanner,
            false,
        );
        let item = candidate(&alias.join("target"));
        assert!(
            scope
                .authorize_candidate(&item, &scanner, platform.as_ref())
                .is_ok()
        );
        fs::rename(&alias, temp.path().join("old-alias")).unwrap();
        symlink(&second, &alias).unwrap();
        fs::rename(first.join("target"), second.join("target")).unwrap();
        assert_eq!(identity_for_path(&item.path, false).ok(), item.identity);
        assert!(!scope.contains_path(&alias));
        assert!(!scope.accepts_candidate(&item));
    }

    #[test]
    fn nested_symlink_cannot_escape_even_when_following_is_enabled() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let mut scanner = scanner(std::slice::from_ref(&root));
        scanner.follow_symlinks = true;
        let platform = platform(temp.path(), "original", false);
        let scope = capture(
            platform,
            temp.path(),
            std::slice::from_ref(&root),
            &scanner,
            false,
        );
        let mut item = candidate(&outside.join("target"));
        symlink(&outside, root.join("escape")).unwrap();
        item.path = root.join("escape/target");
        assert!(!scope.contains_path(&item.path));
        assert!(!scope.accepts_candidate(&item));
    }

    #[test]
    fn changed_owner_readonly_or_removed_policy_cannot_authorize_queued_work() {
        let temp = tempfile::tempdir().unwrap();
        let paths = vec![temp.path().to_path_buf()];
        let mut scanner = scanner(&paths);
        let original = platform(temp.path(), "original", false);
        let scope = capture(Arc::clone(&original), temp.path(), &paths, &scanner, false);
        let item = candidate(&temp.path().join("target"));
        for current in [
            platform(temp.path(), "replacement-device", false),
            platform(temp.path(), "original", true),
        ] {
            assert_eq!(
                scope.authorize_mount(current.as_ref()),
                Err(SkipReason::PolicyChanged)
            );
            assert_eq!(
                scope.authorize_candidate(&item, &scanner, current.as_ref()),
                Err(SkipReason::PolicyChanged)
            );
        }
        scanner.root_paths.clear();
        assert_eq!(
            scope.authorize_candidate(&item, &scanner, original.as_ref()),
            Err(SkipReason::PolicyChanged)
        );
    }

    #[test]
    fn catalog_root_keeps_its_exact_selection_and_current_opt_in() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("cache");
        fs::create_dir(&selected).unwrap();
        let mut scanner = scanner(&[]);
        scanner.catalog_roots_on_pressured_device = true;
        let platform = platform(temp.path(), "original", false);
        let scope = capture(
            Arc::clone(&platform),
            temp.path(),
            std::slice::from_ref(&selected),
            &scanner,
            true,
        );
        let item = candidate(&selected.join("target"));
        assert!(
            scope
                .authorize_candidate(&item, &scanner, platform.as_ref())
                .is_ok()
        );
        let sibling = candidate(&temp.path().join("unrelated-target"));
        assert!(!scope.accepts_candidate(&sibling));
        scanner.catalog_roots_on_pressured_device = false;
        assert_eq!(
            scope.authorize_candidate(&item, &scanner, platform.as_ref()),
            Err(SkipReason::PolicyChanged)
        );
    }

    #[test]
    fn missing_mount_or_selected_directory_evidence_grants_no_authority() {
        let temp = tempfile::tempdir().unwrap();
        let paths = vec![temp.path().to_path_buf()];
        let scanner = scanner(&paths);
        let collector =
            FsStatsCollector::new(platform(temp.path(), "original", false), Duration::ZERO);
        let counters_only = collector.collect_sample(temp.path()).unwrap();
        let observed = collector.collect_admission_sample(temp.path()).unwrap();
        assert!(
            FilesystemReclaimScope::from_observed_roots(
                &counters_only,
                &paths,
                std::slice::from_ref(&observed),
                &scanner,
                false,
            )
            .is_none()
        );
        assert!(
            FilesystemReclaimScope::from_observed_roots(&observed, &paths, &[], &scanner, false,)
                .is_none()
        );
    }

    #[test]
    fn nested_owner_scan_keeps_alias_and_rejects_same_device_parent_candidates() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let nested = parent.join("nested-mount");
        let alias = temp.path().join("alias");
        fs::create_dir_all(&nested).unwrap();
        symlink(&parent, &alias).unwrap();
        let mounts = [temp.path().to_path_buf(), nested.clone()];
        let platform: Arc<dyn Platform> = Arc::new(MockPlatform::new(
            mounts
                .iter()
                .map(|mount| MountPoint {
                    path: mount.clone(),
                    device: "same-device-fixture".to_string(),
                    fs_type: "fixture".to_string(),
                    is_ram_backed: false,
                })
                .collect(),
            mounts
                .iter()
                .map(|mount| {
                    (
                        mount.clone(),
                        FsStats {
                            total_bytes: 100_000,
                            free_bytes: 10_000,
                            available_bytes: 9_000,
                            fs_type: "fixture".to_string(),
                            mount_point: mount.clone(),
                            is_readonly: false,
                        },
                    )
                })
                .collect(),
            MemoryInfo {
                total_bytes: 100_000,
                available_bytes: 90_000,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            PlatformPaths::default(),
        ));
        let mut scanner = scanner(std::slice::from_ref(&alias));
        scanner.cross_devices = true;
        let scope = capture(
            platform,
            &nested,
            std::slice::from_ref(&alias),
            &scanner,
            false,
        );
        assert_eq!(scope.admitted_paths(), vec![alias.clone()]);
        assert_eq!(scope.scan_paths(), vec![alias.join("nested-mount")]);
        assert!(scope.contains_path(&alias));
        let parent_item = candidate(&alias.join("parent-target"));
        let nested_item = candidate(&alias.join("nested-mount/target"));
        assert_eq!(
            parent_item.identity.unwrap().device_id,
            nested_item.identity.unwrap().device_id
        );
        assert!(!scope.contains_path(&parent_item.path));
        assert!(!scope.accepts_candidate(&parent_item));
        assert!(scope.accepts_candidate(&nested_item));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_device_and_inode_do_not_replace_a_missing_or_changed_kernel_mount_id() {
        let temp = tempfile::tempdir().unwrap();
        let paths = vec![temp.path().to_path_buf()];
        let scanner = scanner(&paths);
        let platform = platform(temp.path(), "original", false);
        let original = capture(Arc::clone(&platform), temp.path(), &paths, &scanner, false);
        let item = candidate(&temp.path().join("target"));
        let old_id = original.mount_directory.kernel_mount_id.unwrap();
        for changed in [None, Some(old_id.wrapping_add(1))] {
            let mut scope = original.clone();
            scope.mount_directory.kernel_mount_id = changed;
            assert_eq!(
                scope.mount_directory.identity,
                original.mount_directory.identity
            );
            assert!(!scope.contains_path(temp.path()));
            assert!(!scope.accepts_candidate(&item));
            assert_eq!(
                scope.authorize_mount(platform.as_ref()),
                Err(SkipReason::PolicyChanged)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cross_device_parent_traversal_never_authorizes_candidates_from_the_parent() {
        let Ok(temp) = tempfile::TempDir::new_in("/dev/shm") else {
            eprintln!("SKIP: a writable /dev/shm is required for native cross-mount scope proof");
            return;
        };
        let platform: Arc<dyn Platform> = Arc::new(crate::platform::current());
        let mount = platform.mount_identity(temp.path()).unwrap().path;
        let paths = vec![PathBuf::from("/")];
        let mut scanner = scanner(&paths);
        scanner.cross_devices = true;
        let scope = capture(Arc::clone(&platform), &mount, &paths, &scanner, false);
        let item = candidate(&temp.path().join("target"));
        assert!(scope.contains_path(Path::new("/")));
        assert!(scope.contains_path(temp.path()));
        assert!(scope.accepts_candidate(&item));
        assert!(
            scope
                .authorize_candidate(&item, &scanner, platform.as_ref())
                .is_ok()
        );
        let peer = tempfile::tempdir().unwrap();
        let peer_item = candidate(&peer.path().join("target"));
        if peer_item.identity.unwrap().device_id != item.identity.unwrap().device_id {
            assert!(!scope.contains_path(peer.path()));
            assert!(!scope.accepts_candidate(&peer_item));
        }
        scanner.cross_devices = false;
        let collector = FsStatsCollector::new(platform, Duration::ZERO);
        let mounted = collector.collect_admission_sample(&mount).unwrap();
        let parent = collector.collect_admission_sample(Path::new("/")).unwrap();
        assert!(
            FilesystemReclaimScope::from_observed_roots(
                &mounted,
                &paths,
                &[parent],
                &scanner,
                false,
            )
            .is_none()
        );
    }
}
