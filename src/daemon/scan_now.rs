//! Revocable scope and bounded scheduling for explicit live-daemon scans.
//!
//! An operator request may narrow configured traversal authority, never add
//! it. The configured spelling is retained so a queued request cannot bypass
//! a changed root alias. The same evidence reaches the executor.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::core::config::ScannerConfig;
use crate::daemon::loop_main::{
    ScanRequest, behavior_allows_delete_dispatch, behavior_delete_batch_limit, min_certainty_for,
    scanner_mutation_scope_matches,
};
use crate::daemon::policy::{BehaviorDispatchTable, BehaviorMode};
use crate::daemon::target_tier::is_excluded;
use crate::monitor::pid::{
    PidConfig, PidPressureController, PressureLevel, PressureReading, PressureResponse,
};
use crate::platform::pal::Platform;
use crate::platform::types::MemoryPressureLevel;
use crate::scanner::protection::ProtectionRegistry;
use crate::scanner::scoring::{ArtifactCertainty, CandidacyScore};
use crate::scanner::walker::{FsIdentity, entry_metadata};

#[derive(Debug, Clone)]
struct ScanPath {
    requested: PathBuf,
    root: PathBuf,
    resolved_root: PathBuf,
    root_identity: FsIdentity,
    path: PathBuf,
    resolved_path: PathBuf,
    path_identity: FsIdentity,
}

/// Permission captured for one explicit scan, renewed before traversal and
/// before every candidate mutation. `force` affects scheduling only.
#[derive(Debug, Clone)]
pub struct ScanNowScope {
    paths: Vec<ScanPath>,
    scanner: ScannerConfig,
    force: bool,
    mount: Option<PathBuf>,
    dispatch: Option<(Arc<RwLock<ScanNowPolicy>>, u64)>,
}

impl ScanNowScope {
    /// Validate the complete request. Empty paths select configured roots.
    pub(crate) fn capture(
        requested: &[PathBuf],
        force: bool,
        scanner: &ScannerConfig,
    ) -> Result<Self, String> {
        let requested = if requested.is_empty() {
            &scanner.root_paths
        } else {
            requested
        };
        if requested.is_empty() {
            return Err("scan-now: no scanner roots are configured".to_string());
        }
        let mut paths = Vec::new();
        for requested in requested {
            let requested = absolute_path(requested)?;
            let resolved_path = requested.canonicalize().map_err(|error| {
                format!("scan-now: cannot resolve {}: {error}", requested.display())
            })?;
            let path_identity = directory_identity(&requested)?;
            let mut authorized = None;
            for root in &scanner.root_paths {
                let Ok(resolved_root) = root.canonicalize() else {
                    continue;
                };
                let Ok(relative) = resolved_path.strip_prefix(&resolved_root) else {
                    continue;
                };
                let Ok(root_identity) = directory_identity(root) else {
                    continue;
                };
                // Reconstruct through the configured alias instead of
                // silently replacing it with a canonical pathname.
                let path = root.join(relative);
                let candidate = ScanPath {
                    requested: requested.clone(),
                    root: root.clone(),
                    resolved_root,
                    root_identity,
                    path,
                    resolved_path: resolved_path.clone(),
                    path_identity,
                };
                if candidate.authorized(scanner) {
                    authorized = Some(candidate);
                    break;
                }
            }
            let Some(path) = authorized else {
                return Err(format!(
                    "scan-now: {} is not an allowed directory within the current configured scanner roots",
                    requested.display()
                ));
            };
            paths.push(path);
        }
        Ok(Self {
            paths,
            scanner: scanner.clone(),
            force,
            mount: None,
            dispatch: None,
        })
    }

    /// One partition per observed mount keeps a healthy selection from
    /// borrowing the pressure or delete batch limit of a pressured neighbor.
    pub(crate) fn partition(
        self,
        mut mount_for: impl FnMut(&Path) -> Option<PathBuf>,
    ) -> Result<Vec<Self>, String> {
        let mut by_mount: BTreeMap<PathBuf, Vec<ScanPath>> = BTreeMap::new();
        for path in self.paths {
            let mount = mount_for(&path.path).ok_or_else(|| {
                format!(
                    "scan-now: cannot establish the filesystem for {}",
                    path.path.display()
                )
            })?;
            // Deduplicate only within a mount. An explicitly selected nested
            // filesystem must survive even when its ancestor was selected.
            let paths = by_mount.entry(mount).or_default();
            if paths
                .iter()
                .any(|prior| path.resolved_path.starts_with(&prior.resolved_path))
            {
                continue;
            }
            paths.retain(|prior| !prior.resolved_path.starts_with(&path.resolved_path));
            paths.push(path);
        }
        Ok(by_mount
            .into_iter()
            .map(|(mount, paths)| Self {
                paths,
                scanner: self.scanner.clone(),
                force: self.force,
                mount: Some(mount),
                dispatch: None,
            })
            .collect())
    }

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.paths.iter().map(|path| path.path.clone()).collect()
    }

    pub(crate) fn force(&self) -> bool {
        self.force
    }

    pub(crate) fn authorized(&self, scanner: &ScannerConfig) -> bool {
        self.configuration_current(scanner)
            && self.paths.iter().all(|path| path.authorized(scanner))
    }

    fn configuration_current(&self, scanner: &ScannerConfig) -> bool {
        self.dispatch
            .as_ref()
            .is_none_or(|(policy, epoch)| policy.read().epoch == *epoch)
            && scanner_mutation_scope_matches(&self.scanner, scanner, false)
    }

    pub(crate) fn contains_path(&self, candidate: &Path) -> bool {
        self.paths
            .iter()
            .any(|path| candidate.starts_with(&path.path))
    }

    pub(crate) fn accepts_candidate(&self, candidate: &CandidacyScore) -> bool {
        candidate.identity.is_some_and(|identity| {
            self.paths.iter().any(|path| {
                candidate.path.starts_with(&path.path)
                    && identity.device_id == path.path_identity.device_id
            })
        })
    }

    fn mode(&self, level: PressureLevel) -> Option<BehaviorMode> {
        let (policy, epoch) = self.dispatch.as_ref()?;
        let policy = policy.read();
        (policy.epoch == *epoch).then(|| policy.table.mode_for(policy.memory, level))
    }

    pub(crate) fn certainty_floor(&self, level: PressureLevel) -> ArtifactCertainty {
        self.mode(level)
            .map_or(ArtifactCertainty::Definite, |mode| {
                min_certainty_for(mode.cleanup_action)
            })
    }

    /// Renew actual byte pressure and the local behavior cell at mutation.
    /// A different selected mount's pressure and resource-only pressure are
    /// never permission to delete this candidate.
    pub(crate) fn permits_mutation(
        &self,
        candidate: &CandidacyScore,
        scanner: &ScannerConfig,
        platform: &dyn Platform,
        planned_pressure: PressureLevel,
    ) -> bool {
        if !self.accepts_candidate(candidate)
            || !self.authorizes_candidate(&candidate.path, scanner)
        {
            return false;
        }
        let Some((shared_policy, epoch)) = &self.dispatch else {
            return false;
        };
        let policy = shared_policy.read().clone();
        if policy.epoch != *epoch {
            return false;
        }
        let Ok(stats) = platform.fs_stats(&candidate.path) else {
            return false;
        };
        if stats.is_readonly
            || stats.total_bytes == 0
            || stats.free_bytes > stats.total_bytes
            || stats.available_bytes > stats.free_bytes
            || self.mount.as_ref() != Some(&stats.mount_point)
        {
            return false;
        }
        let response = PidPressureController::new(&policy.pressure, Duration::ZERO).update(
            PressureReading {
                free_bytes: stats.available_bytes,
                total_bytes: stats.total_bytes,
                mount: stats.mount_point,
            },
            None,
            Instant::now(),
        );
        let mode = policy.table.mode_for(policy.memory, response.level);
        response.level >= planned_pressure
            && behavior_allows_delete_dispatch(mode)
            && candidate.decision.certainty >= min_certainty_for(mode.cleanup_action)
            && *shared_policy.read() == policy
    }

    pub(crate) fn authorizes_candidate(&self, candidate: &Path, scanner: &ScannerConfig) -> bool {
        if !self.configuration_current(scanner) {
            return false;
        }
        let Ok(resolved) = candidate.canonicalize() else {
            return false;
        };
        let Ok(metadata) = fs::symlink_metadata(candidate) else {
            return false;
        };
        let identity = entry_metadata(&metadata).identity();
        self.paths.iter().any(|path| {
            candidate.starts_with(&path.path)
                && resolved.starts_with(&path.resolved_path)
                && identity.device_id == path.path_identity.device_id
                && path.authorized(scanner)
        }) && paths_allowed(&[candidate, &resolved], scanner)
    }
}

impl ScanPath {
    fn authorized(&self, scanner: &ScannerConfig) -> bool {
        scanner.root_paths.contains(&self.root)
            && (scanner.follow_symlinks
                || self.requested == self.path
                || self.requested == self.resolved_path)
            && self
                .root
                .canonicalize()
                .is_ok_and(|path| path == self.resolved_root)
            && self
                .path
                .canonicalize()
                .is_ok_and(|path| path == self.resolved_path)
            && self
                .requested
                .canonicalize()
                .is_ok_and(|path| path == self.resolved_path)
            && directory_identity(&self.root).is_ok_and(|identity| identity == self.root_identity)
            && directory_identity(&self.path).is_ok_and(|identity| identity == self.path_identity)
            && traversal_allowed(&self.root, &self.path, self.root_identity, scanner)
            && paths_allowed(
                &[
                    &self.root,
                    &self.resolved_root,
                    &self.requested,
                    &self.path,
                    &self.resolved_path,
                ],
                scanner,
            )
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(format!(
            "scan-now: {} must be an absolute path without '..' components",
            path.display()
        ));
    }
    Ok(path
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect())
}

fn directory_identity(path: &Path) -> Result<FsIdentity, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("scan-now: cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("scan-now: {} is not a directory", path.display()));
    }
    Ok(entry_metadata(&metadata).identity())
}

fn traversal_allowed(
    root: &Path,
    path: &Path,
    identity: FsIdentity,
    scanner: &ScannerConfig,
) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return false;
        };
        if !scanner.follow_symlinks && metadata.is_symlink() {
            return false;
        }
        let Ok(current_identity) = directory_identity(&current) else {
            return false;
        };
        if !scanner.cross_devices && current_identity.device_id != identity.device_id {
            return false;
        }
    }
    true
}

fn paths_allowed(paths: &[&Path], scanner: &ScannerConfig) -> bool {
    let Ok(mut protection) = ProtectionRegistry::new(Some(&scanner.protected_paths)) else {
        return false;
    };
    paths.iter().all(|path| {
        !is_excluded(path, &scanner.excluded_paths)
            && protection.discover_ancestor_markers(path).is_ok()
            && !protection.is_protected(path)
    })
}

#[derive(Debug)]
struct PendingScan {
    scope: Arc<ScanNowScope>,
    response: Option<PressureResponse>,
    retry_after: Instant,
}

#[derive(Debug, Clone, PartialEq)]
struct ScanNowPolicy {
    epoch: u64,
    table: BehaviorDispatchTable,
    memory: MemoryPressureLevel,
    pressure: PidConfig,
}

impl Default for ScanNowPolicy {
    fn default() -> Self {
        Self {
            epoch: 0,
            table: BehaviorDispatchTable::default(),
            memory: MemoryPressureLevel::Unknown,
            pressure: PidConfig::from(&crate::core::config::PressureConfig::default()),
        }
    }
}

/// Operator requests have their own bounded queue. Routine pressure work may
/// replace stale channel entries, but cannot evict accepted operator work.
#[derive(Debug, Default)]
pub(crate) struct ScanNowQueue {
    pending: VecDeque<PendingScan>,
    claimed: usize,
    policy: Arc<RwLock<ScanNowPolicy>>,
    pressure_epoch: u64,
}

impl ScanNowQueue {
    pub(crate) fn enqueue(
        &mut self,
        scopes: Vec<ScanNowScope>,
        capacity: usize,
    ) -> Result<(), String> {
        if scopes.len() > capacity.saturating_sub(self.pending.len() + self.claimed) {
            return Err(
                "the operator scan queue is full; retry after a pending scan completes".to_string(),
            );
        }
        let epoch = self.policy.read().epoch;
        self.pending.extend(scopes.into_iter().map(|mut scope| {
            scope.dispatch = Some((Arc::clone(&self.policy), epoch));
            PendingScan {
                scope: Arc::new(scope),
                response: None,
                retry_after: Instant::now(),
            }
        }));
        Ok(())
    }

    pub(crate) fn update_policy(
        &self,
        table: BehaviorDispatchTable,
        memory: MemoryPressureLevel,
        pressure: PidConfig,
    ) {
        let mut policy = self.policy.write();
        policy.table = table;
        policy.memory = memory;
        policy.pressure = pressure;
    }

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.pending
            .iter()
            .flat_map(|pending| pending.scope.paths())
            .collect()
    }

    pub(crate) fn revoke(&mut self) -> usize {
        let count = self.pending.len() + self.claimed;
        let mut policy = self.policy.write();
        policy.epoch = policy.epoch.wrapping_add(1);
        drop(policy);
        self.pending.clear();
        count
    }

    /// Pending requests wait for a new pressure sample without probing their
    /// paths. A failed monitor tick must not block in scope revalidation on
    /// the same unavailable filesystem it has just failed to observe.
    pub(crate) fn withdraw_pressure(&mut self) {
        self.pressure_epoch = self.pressure_epoch.wrapping_add(1);
        for pending in &mut self.pending {
            pending.response = None;
        }
    }

    /// Only actual byte-pressure observations can authorize an operator pass.
    /// Missing samples wait; swap/inode promotion is never inherited here.
    pub(crate) fn refresh(
        &mut self,
        scanner: &ScannerConfig,
        responses: &[PressureResponse],
        mut mount_for: impl FnMut(&Path) -> Option<PathBuf>,
    ) -> usize {
        let before = self.pending.len();
        self.pending.retain_mut(|pending| {
            if !pending.scope.authorized(scanner) {
                return false;
            }
            pending.response = pending.scope.mount.as_ref().and_then(|mount| {
                if !pending
                    .scope
                    .paths
                    .iter()
                    .all(|path| mount_for(&path.path).as_ref() == Some(mount))
                {
                    return None;
                }
                responses
                    .iter()
                    .find(|response| &response.causing_mount == mount)
                    .cloned()
                    .map(|mut response| {
                        response.max_delete_batch =
                            pending.scope.mode(response.level).map_or(0, |mode| {
                                behavior_delete_batch_limit(mode, response.max_delete_batch)
                            });
                        response
                    })
            });
            true
        });
        before - self.pending.len()
    }
}

/// A claimed request keeps its queue reservation through pacing and unwinding.
/// Deferral returns it; every other exit releases it.
pub(crate) struct ScanNowClaim {
    queue: Arc<Mutex<ScanNowQueue>>,
    pending: Option<PendingScan>,
    defer_for: Option<Duration>,
    pressure_epoch: u64,
}

impl ScanNowClaim {
    pub(crate) fn take(queue: &Arc<Mutex<ScanNowQueue>>, now: Instant) -> Option<Self> {
        let (pending, pressure_epoch) = {
            let mut queue = queue.lock();
            let ready =
                |pending: &&PendingScan| pending.response.is_some() && pending.retry_after <= now;
            let index = queue
                .pending
                .iter()
                .enumerate()
                .filter(|(_, pending)| ready(pending))
                .max_by_key(|(index, pending)| (pending.scope.force, std::cmp::Reverse(*index)))
                .map(|(index, _)| index)?;
            let pending = queue.pending.remove(index)?;
            queue.claimed += 1;
            let pressure_epoch = queue.pressure_epoch;
            drop(queue);
            (pending, pressure_epoch)
        };
        Some(Self {
            queue: Arc::clone(queue),
            pending: Some(pending),
            defer_for: None,
            pressure_epoch,
        })
    }

    pub(crate) fn request(&self) -> ScanRequest {
        let pending = self.pending.as_ref().expect("claimed scan has scope");
        let response = pending
            .response
            .as_ref()
            .expect("only observed scans are claimed");
        ScanRequest {
            paths: pending.scope.paths(),
            urgency: response.urgency,
            pressure_level: response.level,
            free_pct: Some(response.free_pct),
            max_delete_batch: response.max_delete_batch,
            force_full_scan: true,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
            ram_reclaim: None,
            inode_reclaim: None,
            scan_now: Some(Arc::clone(&pending.scope)),
        }
    }

    pub(crate) fn defer(&mut self, delay: Duration) {
        self.defer_for = Some(delay);
    }
}

impl Drop for ScanNowClaim {
    fn drop(&mut self) {
        let mut queue = self.queue.lock();
        queue.claimed = queue.claimed.saturating_sub(1);
        if let (Some(mut pending), Some(delay)) = (self.pending.take(), self.defer_for) {
            if self.pressure_epoch != queue.pressure_epoch {
                // A paced claim must not restore the observation invalidated
                // while it was outside the queue, even after sampling recovers.
                pending.response = None;
            }
            pending.retry_after = Instant::now() + delay;
            queue.pending.push_back(pending);
        }
    }
}

#[cfg(test)]
mod tests;
