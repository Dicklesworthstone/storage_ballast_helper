//! Ephemeral, process-bound protection for active build targets.
//!
//! A lease is deliberately not a permanent `.sbh-protect` marker. The caller
//! takes an exclusive lock in the target's parent *before* the target exists,
//! creates the target, and carries the lock file descriptor across `exec`.
//! The kernel releases the lock when the leased process tree exits or crashes.
//! Deletion preflight derives the same sidecar name from every candidate and
//! ancestor, so it can close both the scan/register race and the scan/delete
//! race without trusting process names or open-file heuristics.

#![allow(clippy::module_name_repetitions)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use nix::fcntl::{FcntlArg, FdFlag, Flock, FlockArg, fcntl};
#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::sys::statvfs::statvfs;
#[cfg(unix)]
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::errors::{Result, SbhError};

/// Stable wire contract for active-target metadata.
pub const ACTIVE_LEASE_CONTRACT_ID: &str = "sbh.active_target_lease.v1";
/// Environment variable inherited by the leased command for authenticated renewal.
pub const ACTIVE_LEASE_TOKEN_ENV: &str = "SBH_ACTIVE_LEASE_TOKEN";
/// Environment variable naming the exact leased target.
pub const ACTIVE_LEASE_TARGET_ENV: &str = "SBH_ACTIVE_LEASE_TARGET";
/// Maximum number of simultaneous active targets beneath one configured root.
pub const DEFAULT_MAX_ACTIVE_LEASES_PER_ROOT: usize = 4;
/// Maximum reservation admitted for one target (64 GiB).
pub const DEFAULT_MAX_BYTES_PER_LEASE: u64 = 64 * 1024 * 1024 * 1024;
/// Maximum aggregate reservation beneath one configured root (128 GiB).
pub const DEFAULT_MAX_RESERVED_BYTES_PER_ROOT: u64 = 128 * 1024 * 1024 * 1024;
/// Hard lifetime ceiling for a lease, including renewals (8 hours).
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_hours(8);
/// Free-space floor below which a lease is not admitted or is cancelled (10 GiB).
pub const DEFAULT_EMERGENCY_RESERVE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Watchdog polling cadence.
pub const DEFAULT_WATCH_INTERVAL: Duration = Duration::from_secs(2);
/// Grace period between TERM and KILL after a lease bound fires.
pub const DEFAULT_TERMINATION_GRACE: Duration = Duration::from_secs(10);

const LOCK_PREFIX: &str = ".sbh-active-lease-";
const LOCK_SUFFIX: &str = ".lock";
const METADATA_SUFFIX: &str = ".json";
const REGISTRY_LOCK_NAME: &str = ".sbh-active-lease-registry.lock";
const MAX_WALK_ENTRIES: usize = 2_000_000;

/// Resource and lifetime caps applied when acquiring and monitoring leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeasePolicy {
    /// Maximum concurrent leases in one root.
    pub max_active_leases_per_root: usize,
    /// Maximum requested bytes for one lease.
    pub max_bytes_per_lease: u64,
    /// Maximum aggregate requested bytes in one root.
    pub max_reserved_bytes_per_root: u64,
    /// Maximum lifetime including renewal.
    pub max_lifetime: Duration,
    /// Free-space floor retained for emergency operation.
    pub emergency_reserve_bytes: u64,
    /// Watchdog polling cadence.
    pub watch_interval: Duration,
    /// Grace between TERM and KILL.
    pub termination_grace: Duration,
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            max_active_leases_per_root: DEFAULT_MAX_ACTIVE_LEASES_PER_ROOT,
            max_bytes_per_lease: DEFAULT_MAX_BYTES_PER_LEASE,
            max_reserved_bytes_per_root: DEFAULT_MAX_RESERVED_BYTES_PER_ROOT,
            max_lifetime: DEFAULT_MAX_LIFETIME,
            emergency_reserve_bytes: DEFAULT_EMERGENCY_RESERVE_BYTES,
            watch_interval: DEFAULT_WATCH_INTERVAL,
            termination_grace: DEFAULT_TERMINATION_GRACE,
        }
    }
}

/// Durable metadata paired with the kernel-held lease lock.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveLeaseMetadata {
    /// Wire contract identifier.
    pub contract_id: String,
    /// Exact canonical target path.
    pub target: PathBuf,
    /// Canonical configured scanner root that admitted the target.
    pub scanner_root: PathBuf,
    /// Process group that owns the lease.
    pub process_group_id: i32,
    /// Target filesystem device identity.
    pub target_device_id: u64,
    /// Target filesystem inode identity.
    pub target_inode: u64,
    /// Lease creation time as Unix seconds.
    pub started_at_unix_seconds: u64,
    /// Renewable soft deadline as Unix seconds.
    pub expires_at_unix_seconds: u64,
    /// Non-renewable hard deadline as Unix seconds.
    pub hard_expires_at_unix_seconds: u64,
    /// Maximum allocated bytes admitted for this target.
    pub max_bytes: u64,
    /// Free-space floor retained for emergency operation.
    pub emergency_reserve_bytes: u64,
    /// SHA-256 of the renewal token; the token itself is never persisted.
    pub renewal_token_sha256: String,
}

/// Why a currently locked target must remain untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveLeaseState {
    /// Metadata and current resource state are within bounds.
    Active,
    /// The renewable or hard lifetime is exhausted; watchdog cancellation is pending.
    Expired,
    /// Allocated target size exceeds the admitted reservation.
    OverQuota,
    /// Emergency free-space reserve has been crossed.
    EmergencyReserveCrossed,
    /// Lock is held but its metadata or target identity cannot be trusted.
    Invalid,
}

/// Result of inspecting a candidate for an ancestor lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveLeaseInspection {
    /// Leased target that contains the candidate.
    pub leased_target: PathBuf,
    /// Current safety state.
    pub state: ActiveLeaseState,
    /// Parsed metadata when it was valid enough to expose.
    pub metadata: Option<ActiveLeaseMetadata>,
    /// Diagnostic suitable for logs.
    pub detail: String,
}

/// A successfully acquired lease. Dropping it releases kernel protection.
#[cfg(unix)]
pub struct ActiveLease {
    metadata: ActiveLeaseMetadata,
    metadata_path: PathBuf,
    renewal_token: String,
    lock: Flock<File>,
}

#[cfg(unix)]
impl std::fmt::Debug for ActiveLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveLease")
            .field("metadata", &self.metadata)
            .field("metadata_path", &self.metadata_path)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl ActiveLease {
    /// Acquire a process-bound lease using the production safety caps.
    pub fn acquire(
        configured_roots: &[PathBuf],
        target: &Path,
        ttl: Duration,
        max_bytes: u64,
    ) -> Result<Self> {
        Self::acquire_with_policy(
            configured_roots,
            target,
            ttl,
            max_bytes,
            LeasePolicy::default(),
        )
    }

    /// Acquire with an explicit policy. This is public to support deterministic
    /// embedders and focused tests; weakening production CLI caps is not implied.
    pub fn acquire_with_policy(
        configured_roots: &[PathBuf],
        target: &Path,
        ttl: Duration,
        max_bytes: u64,
        policy: LeasePolicy,
    ) -> Result<Self> {
        validate_policy(policy)?;
        if ttl.is_zero() || ttl > policy.max_lifetime {
            return Err(invalid_config(format!(
                "active lease ttl must be within 1 second and {} seconds",
                policy.max_lifetime.as_secs()
            )));
        }
        if max_bytes == 0 || max_bytes > policy.max_bytes_per_lease {
            return Err(invalid_config(format!(
                "active lease max_bytes must be within 1 and {}",
                policy.max_bytes_per_lease
            )));
        }

        let (scanner_root, canonical_target) = resolve_new_target(configured_roots, target)?;
        let sidecars = sidecar_paths(&canonical_target)?;
        let registry_lock = lock_file(&scanner_root.join(REGISTRY_LOCK_NAME), false)?;
        let (active_count, reserved_bytes) = active_reservations(&scanner_root)?;
        if active_count >= policy.max_active_leases_per_root {
            return Err(safety_veto(
                &canonical_target,
                format!(
                    "active lease root limit reached ({active_count}/{})",
                    policy.max_active_leases_per_root
                ),
            ));
        }
        if reserved_bytes.saturating_add(max_bytes) > policy.max_reserved_bytes_per_root {
            return Err(safety_veto(
                &canonical_target,
                format!(
                    "active lease aggregate reservation would exceed {} bytes",
                    policy.max_reserved_bytes_per_root
                ),
            ));
        }
        let free_bytes = available_bytes(&scanner_root)?;
        if free_bytes < policy.emergency_reserve_bytes.saturating_add(max_bytes) {
            return Err(safety_veto(
                &canonical_target,
                format!(
                    "active lease needs {max_bytes} bytes plus {} emergency bytes, but only {free_bytes} are free",
                    policy.emergency_reserve_bytes
                ),
            ));
        }

        let lock = lock_file(&sidecars.lock, true)?;
        fs::create_dir(&canonical_target)
            .map_err(|error| SbhError::io(&canonical_target, error))?;
        let target_metadata = fs::symlink_metadata(&canonical_target)
            .map_err(|error| SbhError::io(&canonical_target, error))?;
        if !target_metadata.is_dir() || target_metadata.file_type().is_symlink() {
            return Err(safety_veto(
                &canonical_target,
                "active lease target is not a real directory".to_string(),
            ));
        }

        let now = unix_seconds()?;
        let token = random_token();
        let metadata = ActiveLeaseMetadata {
            contract_id: ACTIVE_LEASE_CONTRACT_ID.to_string(),
            target: canonical_target,
            scanner_root,
            process_group_id: i32::try_from(std::process::id()).map_err(|_| SbhError::Runtime {
                details: "current process id does not fit i32".to_string(),
            })?,
            target_device_id: target_metadata.dev(),
            target_inode: target_metadata.ino(),
            started_at_unix_seconds: now,
            expires_at_unix_seconds: now.saturating_add(ttl.as_secs()),
            hard_expires_at_unix_seconds: now.saturating_add(policy.max_lifetime.as_secs()),
            max_bytes,
            emergency_reserve_bytes: policy.emergency_reserve_bytes,
            renewal_token_sha256: hash_text(&token),
        };
        validate_metadata(&metadata, &sidecars.metadata)?;
        write_metadata(&sidecars.metadata, &metadata)?;
        drop(registry_lock);

        Ok(Self {
            metadata,
            metadata_path: sidecars.metadata,
            renewal_token: token,
            lock,
        })
    }

    /// Exact admitted metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ActiveLeaseMetadata {
        &self.metadata
    }

    /// Secret token exported only to the leased process environment.
    #[must_use]
    pub fn renewal_token(&self) -> &str {
        &self.renewal_token
    }

    /// Metadata sidecar used by the watchdog and renewal command.
    #[must_use]
    pub fn metadata_path(&self) -> &Path {
        self.metadata_path.as_path()
    }

    /// Keep the kernel lock across the final `exec` into the leased command.
    pub fn retain_lock_across_exec(&self) -> Result<()> {
        let raw = fcntl(&*self.lock, FcntlArg::F_GETFD).map_err(|error| SbhError::Runtime {
            details: format!("read active lease fd flags: {error}"),
        })?;
        let mut flags = FdFlag::from_bits_truncate(raw);
        flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(&*self.lock, FcntlArg::F_SETFD(flags)).map_err(|error| SbhError::Runtime {
            details: format!("retain active lease across exec: {error}"),
        })?;
        Ok(())
    }
}

/// Renew a live lease using its inherited token. Returns the new soft deadline.
#[cfg(unix)]
pub fn renew(target: &Path, token: &str, extension: Duration) -> Result<u64> {
    if extension.is_zero() {
        return Err(invalid_config(
            "active lease renewal extension must be positive".to_string(),
        ));
    }
    let canonical_target = target
        .canonicalize()
        .map_err(|error| SbhError::io(target, error))?;
    let sidecars = sidecar_paths(&canonical_target)?;
    let Some(mut inspection) = inspect_exact_target(&canonical_target) else {
        return Err(safety_veto(
            target,
            "active lease is not locked".to_string(),
        ));
    };
    let initial_metadata = inspection.metadata.take().ok_or_else(|| {
        safety_veto(
            target,
            format!("active lease metadata invalid: {}", inspection.detail),
        )
    })?;
    let _registry_lock = lock_file(
        &initial_metadata.scanner_root.join(REGISTRY_LOCK_NAME),
        false,
    )?;
    let mut metadata: ActiveLeaseMetadata = serde_json::from_slice(
        &fs::read(&sidecars.metadata)
            .map_err(|error| SbhError::io(&sidecars.metadata, error))?,
    )?;
    validate_metadata(&metadata, &sidecars.metadata)?;
    if hash_text(token) != metadata.renewal_token_sha256 {
        return Err(safety_veto(
            target,
            "active lease renewal token mismatch".to_string(),
        ));
    }
    let now = unix_seconds()?;
    if now >= metadata.hard_expires_at_unix_seconds {
        return Err(safety_veto(
            target,
            "active lease hard lifetime is exhausted".to_string(),
        ));
    }
    let base = metadata.expires_at_unix_seconds.max(now);
    metadata.expires_at_unix_seconds = base
        .saturating_add(extension.as_secs())
        .min(metadata.hard_expires_at_unix_seconds);
    validate_metadata(&metadata, &sidecars.metadata)?;
    write_metadata(&sidecars.metadata, &metadata)?;
    Ok(metadata.expires_at_unix_seconds)
}

/// Inspect a candidate and its ancestors for a currently kernel-locked lease.
///
/// A locked-but-invalid record still protects the target. The watchdog will
/// cancel it, while deletion waits for the kernel lock to release; safety is
/// never converted into a same-cycle delete.
#[must_use]
#[cfg(unix)]
pub fn inspect_path(path: &Path) -> Option<ActiveLeaseInspection> {
    let absolute = absolute_lexical(path).ok()?;
    for cursor in absolute.ancestors() {
        if let Some(inspection) = inspect_exact_target(cursor) {
            return Some(inspection);
        }
    }
    None
}

/// Whether deletion must skip this path because a lease lock is held.
#[must_use]
#[cfg(unix)]
pub fn path_is_actively_leased(path: &Path) -> bool {
    inspect_path(path).is_some()
}

#[cfg(not(unix))]
#[must_use]
pub const fn path_is_actively_leased(_path: &Path) -> bool {
    false
}

/// Monitor an already acquired lease until it ends or violates a bound.
///
/// Returns `Ok(())` when the owner exits naturally. On expiry, quota breach,
/// invalid identity, or emergency pressure the process group is terminated and
/// a typed runtime error describes the bound that fired.
#[cfg(unix)]
pub fn watch(target: &Path, expected_process_group_id: i32, policy: LeasePolicy) -> Result<()> {
    validate_policy(policy)?;
    if expected_process_group_id <= 0 {
        return Err(invalid_config(
            "active lease watchdog process group must be positive".to_string(),
        ));
    }
    loop {
        let Some(inspection) = inspect_exact_target(target) else {
            return Ok(());
        };
        let state = if inspection
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.process_group_id != expected_process_group_id)
        {
            ActiveLeaseState::Invalid
        } else {
            inspection.state
        };
        match state {
            ActiveLeaseState::Active => thread::sleep(policy.watch_interval),
            state => {
                terminate_process_group(expected_process_group_id, target, state, policy)?;
                return Err(SbhError::Runtime {
                    details: format!(
                        "active lease cancelled for {}: {}",
                        target.display(),
                        state_label(state)
                    ),
                });
            }
        }
    }
}

#[cfg(unix)]
fn terminate_process_group(
    process_group_id: i32,
    target: &Path,
    state: ActiveLeaseState,
    policy: LeasePolicy,
) -> Result<()> {
    let pgid = Pid::from_raw(process_group_id);
    eprintln!(
        "[SBH-ACTIVE-LEASE] cancelling process group {process_group_id} for {}: {}",
        target.display(),
        state_label(state)
    );
    if let Err(error) = killpg(pgid, Signal::SIGTERM)
        && error != nix::errno::Errno::ESRCH
    {
        return Err(SbhError::Runtime {
            details: format!("terminate active lease process group {process_group_id}: {error}"),
        });
    }
    let deadline = SystemTime::now()
        .checked_add(policy.termination_grace)
        .unwrap_or_else(SystemTime::now);
    while SystemTime::now() < deadline {
        if inspect_exact_target(target).is_none() {
            return Ok(());
        }
        thread::sleep(policy.watch_interval.min(Duration::from_millis(250)));
    }
    if let Err(error) = killpg(pgid, Signal::SIGKILL)
        && error != nix::errno::Errno::ESRCH
    {
        return Err(SbhError::Runtime {
            details: format!("kill active lease process group {process_group_id}: {error}"),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_exact_target(target: &Path) -> Option<ActiveLeaseInspection> {
    let sidecars = sidecar_paths(target).ok()?;
    if !sidecars.lock.exists() {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&sidecars.lock);
    let Ok(file) = file else {
        return Some(ActiveLeaseInspection {
            leased_target: target.to_path_buf(),
            state: ActiveLeaseState::Invalid,
            metadata: None,
            detail: format!("cannot open lease lock {}", sidecars.lock.display()),
        });
    };
    if let Ok(probe) = Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        drop(probe);
        return None;
    }

    let parsed = fs::read(&sidecars.metadata)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<ActiveLeaseMetadata>(&bytes).map_err(|error| error.to_string())
        });
    let metadata = match parsed {
        Ok(metadata) => metadata,
        Err(detail) => {
            return Some(ActiveLeaseInspection {
                leased_target: target.to_path_buf(),
                state: ActiveLeaseState::Invalid,
                metadata: None,
                detail: format!("locked lease metadata cannot be read: {detail}"),
            });
        }
    };
    if let Err(error) = validate_metadata(&metadata, &sidecars.metadata) {
        return Some(ActiveLeaseInspection {
            leased_target: target.to_path_buf(),
            state: ActiveLeaseState::Invalid,
            metadata: Some(metadata),
            detail: error.to_string(),
        });
    }
    if metadata.target != target {
        return Some(ActiveLeaseInspection {
            leased_target: target.to_path_buf(),
            state: ActiveLeaseState::Invalid,
            metadata: Some(metadata),
            detail: "locked lease target does not match its sidecar name".to_string(),
        });
    }

    let state = current_state(&metadata).unwrap_or(ActiveLeaseState::Invalid);
    Some(ActiveLeaseInspection {
        leased_target: target.to_path_buf(),
        state,
        metadata: Some(metadata),
        detail: state_label(state).to_string(),
    })
}

#[cfg(unix)]
fn current_state(metadata: &ActiveLeaseMetadata) -> Result<ActiveLeaseState> {
    let target_metadata = fs::symlink_metadata(&metadata.target)
        .map_err(|error| SbhError::io(&metadata.target, error))?;
    if !target_metadata.is_dir()
        || target_metadata.file_type().is_symlink()
        || target_metadata.dev() != metadata.target_device_id
        || target_metadata.ino() != metadata.target_inode
    {
        return Ok(ActiveLeaseState::Invalid);
    }
    let now = unix_seconds()?;
    if now >= metadata.expires_at_unix_seconds || now >= metadata.hard_expires_at_unix_seconds {
        return Ok(ActiveLeaseState::Expired);
    }
    if allocated_bytes(&metadata.target)? > metadata.max_bytes {
        return Ok(ActiveLeaseState::OverQuota);
    }
    if available_bytes(&metadata.scanner_root)? < metadata.emergency_reserve_bytes {
        return Ok(ActiveLeaseState::EmergencyReserveCrossed);
    }
    Ok(ActiveLeaseState::Active)
}

#[derive(Debug)]
struct SidecarPaths {
    lock: PathBuf,
    metadata: PathBuf,
}

fn sidecar_paths(target: &Path) -> Result<SidecarPaths> {
    let parent = target.parent().ok_or_else(|| {
        invalid_config(format!(
            "active lease target has no parent: {}",
            target.display()
        ))
    })?;
    let digest = hash_path(target);
    Ok(SidecarPaths {
        lock: parent.join(format!("{LOCK_PREFIX}{digest}{LOCK_SUFFIX}")),
        metadata: parent.join(format!("{LOCK_PREFIX}{digest}{METADATA_SUFFIX}")),
    })
}

#[cfg(unix)]
fn lock_file(path: &Path, nonblocking: bool) -> Result<Flock<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|error| SbhError::io(path, error))?;
    let mode = if nonblocking {
        FlockArg::LockExclusiveNonblock
    } else {
        FlockArg::LockExclusive
    };
    Flock::lock(file, mode).map_err(|(_file, error)| {
        safety_veto(path, format!("active lease lock is already held: {error}"))
    })
}

#[cfg(unix)]
fn active_reservations(root: &Path) -> Result<(usize, u64)> {
    let entries = fs::read_dir(root).map_err(|error| SbhError::io(root, error))?;
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    for entry in entries {
        let entry = entry.map_err(|error| SbhError::io(root, error))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(LOCK_PREFIX) || !name.ends_with(METADATA_SUFFIX) {
            continue;
        }
        let metadata_path = entry.path();
        let lock_name = format!(
            "{}{}",
            name.strip_suffix(METADATA_SUFFIX)
                .expect("suffix checked above"),
            LOCK_SUFFIX
        );
        let lock_path = root.join(lock_name);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path);
        let lock_file = match lock_file {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A missing stable lock means this metadata cannot describe a
                // live lease. Ignore the stale remnant instead of turning one
                // crashed write into a permanent root-wide denial of service.
                continue;
            }
            Err(error) => return Err(SbhError::io(&lock_path, error)),
        };
        match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
            Ok(probe) => drop(probe),
            Err((_file, _error)) => {
                let metadata: ActiveLeaseMetadata = serde_json::from_slice(
                    &fs::read(&metadata_path)
                        .map_err(|error| SbhError::io(&metadata_path, error))?,
                )?;
                validate_metadata(&metadata, &metadata_path)?;
                let sidecars = sidecar_paths(&metadata.target)?;
                if sidecars.lock != lock_path || metadata.scanner_root != root {
                    return Err(safety_veto(
                        root,
                        format!(
                            "uncertain active lease metadata: {}",
                            metadata_path.display()
                        ),
                    ));
                }
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(metadata.max_bytes);
            }
        }
    }
    Ok((count, bytes))
}

fn resolve_new_target(configured_roots: &[PathBuf], target: &Path) -> Result<(PathBuf, PathBuf)> {
    if !target.is_absolute() {
        return Err(invalid_config(format!(
            "active lease target must be absolute: {}",
            target.display()
        )));
    }
    if target
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid_config(format!(
            "active lease target must not contain traversal components: {}",
            target.display()
        )));
    }
    if fs::symlink_metadata(target).is_ok() {
        return Err(safety_veto(
            target,
            "active lease target must be a fresh absent directory".to_string(),
        ));
    }
    let parent = target.parent().ok_or_else(|| {
        invalid_config(format!(
            "active lease target has no parent: {}",
            target.display()
        ))
    })?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| SbhError::io(parent, error))?;
    let file_name = target.file_name().ok_or_else(|| {
        invalid_config(format!(
            "active lease target has no basename: {}",
            target.display()
        ))
    })?;
    let canonical_target = canonical_parent.join(file_name);
    for root in configured_roots {
        let Ok(canonical_root) = root.canonicalize() else {
            continue;
        };
        if canonical_root == canonical_parent {
            return Ok((canonical_root, canonical_target));
        }
    }
    Err(safety_veto(
        target,
        "active lease target must be an immediate child of a configured scanner root".to_string(),
    ))
}

fn validate_policy(policy: LeasePolicy) -> Result<()> {
    if policy.max_active_leases_per_root == 0
        || policy.max_bytes_per_lease == 0
        || policy.max_reserved_bytes_per_root < policy.max_bytes_per_lease
        || policy.max_lifetime.is_zero()
        || policy.watch_interval.is_zero()
        || policy.termination_grace.is_zero()
    {
        return Err(invalid_config(
            "active lease policy contains a zero or contradictory bound".to_string(),
        ));
    }
    Ok(())
}

fn validate_metadata(metadata: &ActiveLeaseMetadata, metadata_path: &Path) -> Result<()> {
    if metadata.contract_id != ACTIVE_LEASE_CONTRACT_ID {
        return Err(safety_veto(
            metadata_path,
            format!("unknown active lease contract: {}", metadata.contract_id),
        ));
    }
    if !metadata.target.is_absolute()
        || !metadata.scanner_root.is_absolute()
        || metadata.target.parent() != Some(metadata.scanner_root.as_path())
        || metadata.process_group_id <= 0
        || metadata.target_device_id == 0
        || metadata.target_inode == 0
        || metadata.started_at_unix_seconds >= metadata.expires_at_unix_seconds
        || metadata.expires_at_unix_seconds > metadata.hard_expires_at_unix_seconds
        || metadata.max_bytes == 0
        || metadata.renewal_token_sha256.len() != 64
    {
        return Err(safety_veto(
            metadata_path,
            "active lease metadata violates its canonical bounds".to_string(),
        ));
    }
    let expected = sidecar_paths(&metadata.target)?;
    if expected.metadata != metadata_path {
        return Err(safety_veto(
            metadata_path,
            "active lease metadata is stored under the wrong target hash".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn write_metadata(path: &Path, metadata: &ActiveLeaseMetadata) -> Result<()> {
    let bytes = serde_json::to_vec(metadata)?;
    let parent = path.parent().ok_or_else(|| {
        invalid_config(format!(
            "active lease metadata has no parent: {}",
            path.display()
        ))
    })?;
    let temporary = parent.join(format!(
        ".sbh-active-lease-write-{}-{:032x}.tmp",
        std::process::id(),
        rand::random::<u128>()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| SbhError::io(&temporary, error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| SbhError::io(&temporary, error))?;
    fs::rename(&temporary, path).map_err(|error| SbhError::io(path, error))?;
    match File::open(parent).and_then(|directory| directory.sync_all()) {
        Ok(()) => Ok(()),
        // Some otherwise supported filesystems reject directory fsync. The
        // renamed file itself is already synced; do not turn that portability
        // limitation into a false claim that the lease was never written.
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(()),
        Err(error) => Err(SbhError::io(parent, error)),
    }
}

#[cfg(unix)]
fn available_bytes(path: &Path) -> Result<u64> {
    let stats = statvfs(path).map_err(|error| SbhError::FsStats {
        path: path.to_path_buf(),
        details: error.to_string(),
    })?;
    Ok(stats
        .blocks_available()
        .saturating_mul(stats.fragment_size()))
}

#[cfg(unix)]
fn allocated_bytes(root: &Path) -> Result<u64> {
    let mut stack = vec![root.to_path_buf()];
    let mut total = 0_u64;
    let mut entries = 0_usize;
    while let Some(path) = stack.pop() {
        entries = entries.saturating_add(1);
        if entries > MAX_WALK_ENTRIES {
            return Err(safety_veto(
                root,
                format!("active lease target exceeds {MAX_WALK_ENTRIES} filesystem entries"),
            ));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| SbhError::io(&path, error))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        total = total.saturating_add(metadata.blocks().saturating_mul(512));
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| SbhError::io(&path, error))? {
                stack.push(entry.map_err(|error| SbhError::io(&path, error))?.path());
            }
        }
    }
    Ok(total)
}

fn unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| SbhError::Runtime {
            details: format!("system clock predates Unix epoch: {error}"),
        })
}

fn random_token() -> String {
    format!(
        "{:032x}{:032x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    )
}

fn hash_text(text: &str) -> String {
    hash_bytes(text.as_bytes())
}

fn hash_path(path: &Path) -> String {
    #[cfg(unix)]
    {
        hash_bytes(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        hash_text(&path.to_string_lossy())
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn absolute_lexical(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| SbhError::io(path, error))
    }
}

const fn state_label(state: ActiveLeaseState) -> &'static str {
    match state {
        ActiveLeaseState::Active => "active",
        ActiveLeaseState::Expired => "expired",
        ActiveLeaseState::OverQuota => "over quota",
        ActiveLeaseState::EmergencyReserveCrossed => "emergency reserve crossed",
        ActiveLeaseState::Invalid => "invalid",
    }
}

fn invalid_config(details: String) -> SbhError {
    SbhError::InvalidConfig { details }
}

fn safety_veto(path: &Path, reason: String) -> SbhError {
    SbhError::SafetyVeto {
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> LeasePolicy {
        LeasePolicy {
            max_active_leases_per_root: 2,
            max_bytes_per_lease: 1024 * 1024,
            max_reserved_bytes_per_root: 2 * 1024 * 1024,
            max_lifetime: Duration::from_secs(60),
            emergency_reserve_bytes: 0,
            watch_interval: Duration::from_millis(10),
            termination_grace: Duration::from_millis(20),
        }
    }

    #[test]
    fn live_lock_protects_target_and_descendants_then_releases() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("build-output");
        let lease = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &target,
            Duration::from_secs(30),
            4096,
            test_policy(),
        )
        .unwrap();
        let descendant = target.join("debug").join("crate.o");

        let inspection = inspect_path(&descendant).expect("lease must protect descendants");
        assert_eq!(inspection.leased_target, target);
        assert_eq!(inspection.state, ActiveLeaseState::Active);
        assert_eq!(inspection.metadata.as_ref().unwrap(), lease.metadata());

        drop(lease);
        assert!(inspect_path(&descendant).is_none());
    }

    #[test]
    fn unrelated_sibling_is_not_protected() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("leased");
        let _lease = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &target,
            Duration::from_secs(30),
            4096,
            test_policy(),
        )
        .unwrap();

        assert!(inspect_path(&root.path().join("other")).is_none());
    }

    #[test]
    fn quota_breach_remains_protected_for_watchdog_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("leased");
        let _lease = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &target,
            Duration::from_secs(30),
            1,
            test_policy(),
        )
        .unwrap();
        let mut payload = File::create(target.join("payload")).unwrap();
        payload.write_all(&[1_u8; 4096]).unwrap();
        payload.sync_all().unwrap();

        let inspection = inspect_path(&target).unwrap();
        assert_eq!(inspection.state, ActiveLeaseState::OverQuota);
        assert!(path_is_actively_leased(&target));
    }

    #[test]
    fn renewal_requires_exact_token_and_respects_hard_deadline() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("leased");
        let lease = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &target,
            Duration::from_secs(10),
            4096,
            test_policy(),
        )
        .unwrap();

        let wrong = renew(&target, "wrong", Duration::from_secs(10)).unwrap_err();
        assert_eq!(wrong.code(), "SBH-2003");
        let renewed = renew(&target, lease.renewal_token(), Duration::from_secs(120)).unwrap();
        assert_eq!(renewed, lease.metadata().hard_expires_at_unix_seconds);
    }

    #[test]
    fn expired_lock_is_still_protected_for_watchdog_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("leased");
        let lease = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &target,
            Duration::from_secs(30),
            4096,
            test_policy(),
        )
        .unwrap();
        let mut expired = lease.metadata().clone();
        expired.started_at_unix_seconds = 1;
        expired.expires_at_unix_seconds = 2;
        write_metadata(lease.metadata_path(), &expired).unwrap();

        let inspection = inspect_path(&target).expect("expired lock must remain protected");
        assert_eq!(inspection.state, ActiveLeaseState::Expired);
        assert!(path_is_actively_leased(&target));
    }

    #[test]
    fn acquisition_refuses_existing_nested_and_over_reserved_targets() {
        let root = tempfile::tempdir().unwrap();
        let existing = root.path().join("existing");
        fs::create_dir(&existing).unwrap();
        assert!(
            ActiveLease::acquire_with_policy(
                &[root.path().to_path_buf()],
                &existing,
                Duration::from_secs(10),
                1024,
                test_policy(),
            )
            .is_err()
        );

        let nested = root.path().join("nested").join("target");
        fs::create_dir(root.path().join("nested")).unwrap();
        assert!(
            ActiveLease::acquire_with_policy(
                &[root.path().to_path_buf()],
                &nested,
                Duration::from_secs(10),
                1024,
                test_policy(),
            )
            .is_err()
        );

        let mut tiny = test_policy();
        tiny.max_bytes_per_lease = 1024;
        tiny.max_reserved_bytes_per_root = 1024;
        assert!(
            ActiveLease::acquire_with_policy(
                &[root.path().to_path_buf()],
                &root.path().join("too-large"),
                Duration::from_secs(10),
                1025,
                tiny,
            )
            .is_err()
        );
    }

    #[test]
    fn stale_corrupt_metadata_with_an_unlocked_sidecar_does_not_block_new_work() {
        let root = tempfile::tempdir().unwrap();
        let stale_target = root.path().join("stale-target");
        let stale = sidecar_paths(&stale_target).unwrap();
        fs::write(&stale.metadata, b"{not valid json").unwrap();
        File::create(&stale.lock).unwrap();

        let fresh_target = root.path().join("fresh-target");
        let lease = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &fresh_target,
            Duration::from_secs(30),
            4096,
            test_policy(),
        )
        .expect("unlocked stale metadata must not deny the root forever");
        assert_eq!(lease.metadata().target, fresh_target);
    }

    #[test]
    fn locked_tampered_metadata_fails_safe_until_the_kernel_lock_releases() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("leased");
        let lease = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &target,
            Duration::from_secs(30),
            4096,
            test_policy(),
        )
        .unwrap();
        fs::write(lease.metadata_path(), b"{tampered").unwrap();

        let inspection = inspect_path(&target).expect("locked invalid record must protect");
        assert_eq!(inspection.state, ActiveLeaseState::Invalid);
        assert!(inspection.metadata.is_none());

        drop(lease);
        assert!(inspect_path(&target).is_none());
    }

    #[test]
    fn root_count_and_aggregate_caps_are_enforced_against_live_locks_only() {
        let root = tempfile::tempdir().unwrap();
        let mut policy = test_policy();
        policy.max_active_leases_per_root = 2;
        policy.max_bytes_per_lease = 1024;
        policy.max_reserved_bytes_per_root = 1536;
        let first = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &root.path().join("first"),
            Duration::from_secs(30),
            1024,
            policy,
        )
        .unwrap();
        let aggregate = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &root.path().join("aggregate-refused"),
            Duration::from_secs(30),
            1024,
            policy,
        )
        .unwrap_err();
        assert_eq!(aggregate.code(), "SBH-2003");

        drop(first);
        let second = ActiveLease::acquire_with_policy(
            &[root.path().to_path_buf()],
            &root.path().join("second"),
            Duration::from_secs(30),
            1024,
            policy,
        )
        .expect("released locks must stop counting against aggregate capacity");
        assert_eq!(second.metadata().max_bytes, 1024);
    }
}
