//! Parallel directory walker with cross-device, symlink, and protection safety.
//!
//! The walker is the "eyes" of the scanner: it discovers candidate files and
//! directories for cleanup, collects structural markers for the scoring engine,
//! and integrates with the protection system to skip `.sbh-protect`ed subtrees.

#![allow(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crossbeam_channel as channel;

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::Platform;
use crate::scanner::patterns::{
    OpaqueTreeClassification, OpaqueTreeContext, OpaqueTreeDisposition, StructuralSignals,
    classify_opaque_tree,
};
use crate::scanner::protection::ProtectionRegistry;
use crate::scanner::scoring::ActiveReferenceSummary;

pub const DEFAULT_ACTIVE_REFERENCE_CACHE_TTL_SECS: u64 = 30;
pub const DEFAULT_ACTIVE_REFERENCE_MIN_SIZE_BYTES: u64 = 100 * 1024 * 1024;
pub const MACOS_USER_SCOPE_ACTIVE_REFERENCE_WARNING: &str =
    "fd check incomplete: other-user processes not visible";

/// Walker configuration derived from `ScannerConfig`.
#[derive(Debug, Clone)]
pub struct WalkerConfig {
    pub root_paths: Vec<PathBuf>,
    pub max_depth: usize,
    pub follow_symlinks: bool,
    pub cross_devices: bool,
    pub parallelism: usize,
    pub excluded_paths: HashSet<PathBuf>,
    pub opaque_pruning: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveReferenceScanConfig {
    pub cache_ttl: Duration,
    pub min_candidate_size_bytes: u64,
}

impl ActiveReferenceScanConfig {
    #[must_use]
    pub fn new(cache_ttl: Duration, min_candidate_size_bytes: u64) -> Self {
        Self {
            cache_ttl,
            min_candidate_size_bytes,
        }
    }

    #[must_use]
    pub fn should_probe(self, candidate_size_bytes: u64) -> bool {
        self.min_candidate_size_bytes == 0 || candidate_size_bytes >= self.min_candidate_size_bytes
    }
}

impl Default for ActiveReferenceScanConfig {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(DEFAULT_ACTIVE_REFERENCE_CACHE_TTL_SECS),
            min_candidate_size_bytes: DEFAULT_ACTIVE_REFERENCE_MIN_SIZE_BYTES,
        }
    }
}

/// Metadata collected for each filesystem entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadata {
    /// Allocated on-disk size (`st_blocks * 512` on Unix), not the apparent
    /// length: sparse files count only the blocks they actually consume.
    pub size_bytes: u64,
    /// Estimated content size for directories: sum of immediate children's file
    /// sizes observed during iteration. For files, equals `size_bytes`.
    /// This is a lower bound (capped at `MAX_ENTRIES_PER_DIR` children, does not
    /// recurse into subdirectories), but far more useful for scoring than the
    /// inode entry size (~4096) that `size_bytes` returns for directories.
    pub content_size_bytes: u64,
    pub modified: SystemTime,
    pub created: Option<SystemTime>,
    pub is_dir: bool,
    pub inode: u64,
    pub device_id: u64,
    pub kind: FsEntryKind,
    pub permissions: u32,
}

/// Filesystem object kind used with device/inode identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// Stable filesystem identity for a single observed directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FsIdentity {
    pub device_id: u64,
    pub inode: u64,
    pub kind: FsEntryKind,
}

impl EntryMetadata {
    /// Return the timestamp to use for age-based scoring.
    ///
    /// For **directories**, returns the creation (birth) time when available,
    /// because directory `mtime` updates whenever any direct child is added or
    /// removed — making active build caches like `target/` appear perpetually
    /// young. Birth time reflects when the directory was actually created and is
    /// stable across builds.
    ///
    /// For **files**, always returns `modified` (content change is what matters).
    pub fn effective_age_timestamp(&self) -> SystemTime {
        if self.is_dir {
            self.created.unwrap_or(self.modified)
        } else {
            self.modified
        }
    }

    #[must_use]
    pub fn identity(&self) -> FsIdentity {
        FsIdentity {
            device_id: self.device_id,
            inode: self.inode,
            kind: self.kind,
        }
    }
}

/// A single entry discovered during a walk.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    pub path: PathBuf,
    pub metadata: EntryMetadata,
    pub depth: usize,
    pub structural_signals: StructuralSignals,
    pub is_open: bool,
    pub opaque_tree: Option<OpaqueTreeClassification>,
}

/// Item in the internal work queue.
#[derive(Debug, Clone)]
struct WorkItem {
    path: PathBuf,
    depth: usize,
    root_device_id: u64,
    opaque_tree: Option<OpaqueTreeClassification>,
}

const OPAQUE_CANDIDATE_SIZE_FLOOR: u64 = 100 * 1_048_576;

/// Parallel directory walker with safety guards.
///
/// Safety invariants:
/// - Honors `follow_symlinks` config during traversal
/// - Never crosses filesystem boundaries unless configured
/// - Skips excluded and protected paths
/// - Bounded by `max_depth` to prevent runaway traversal
pub struct DirectoryWalker {
    config: WalkerConfig,
    protection: Arc<parking_lot::RwLock<ProtectionRegistry>>,
    heartbeat: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Shared cancellation flag. When set to `true`, walker threads exit promptly
    /// instead of blocking on full channels. This prevents thread leaks when the
    /// scanner times out a scan pass.
    cancel: Arc<AtomicBool>,
}

impl DirectoryWalker {
    pub fn new(config: WalkerConfig, protection: ProtectionRegistry) -> Self {
        Self {
            config,
            protection: Arc::new(parking_lot::RwLock::new(protection)),
            heartbeat: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Return a handle to the cancellation flag.
    ///
    /// The caller (scanner) keeps this and sets it to `true` when the scan
    /// budget expires. Walker threads check the flag periodically and exit
    /// instead of blocking on full channels.
    pub fn cancel_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }

    /// Set a heartbeat callback to be called periodically by worker threads.
    #[must_use]
    pub fn with_heartbeat<F>(mut self, callback: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.heartbeat = Some(Arc::new(callback));
        self
    }

    /// Perform a full parallel walk of all root paths.
    ///
    /// Returns all discovered entries. The caller (scanner) will classify and
    /// score them. Open-file set should be collected separately and matched
    /// against results afterward.
    pub fn walk(&self) -> Result<Vec<WalkEntry>> {
        Ok(self.stream()?.into_iter().collect())
    }

    /// Stream entries as they are discovered.
    ///
    /// Returns a receiver that yields entries. The walk runs in background threads.
    pub fn stream(&self) -> Result<channel::Receiver<WalkEntry>> {
        let parallelism = self.config.parallelism.max(1);

        // Channels: work items (unbounded) and results (bounded for memory safety).
        // Worker threads both produce and consume directory work. A bounded work queue
        // can deadlock when every worker is trying to enqueue child directories into a
        // full queue and no worker is left to drain it. Keep only the result channel
        // bounded; callers drain it while the walk runs.
        //
        // Per-directory iteration cap (MAX_ENTRIES_PER_DIR) prevents any single huge
        // directory (e.g. /data/tmp with 60K+ children) from monopolizing traversal.
        // Result channel bounded to 10,000 entries to prevent unbounded memory growth
        // on large trees (previously unbounded, causing 14GB+ RSS on trj).
        let (work_tx, work_rx) = channel::unbounded::<WorkItem>();
        let (result_tx, result_rx) = channel::bounded::<WalkEntry>(10_000);

        // Track in-flight work items so workers know when to stop.
        let in_flight = Arc::new(AtomicUsize::new(0));

        // Seed work queue with root paths.
        for root in &self.config.root_paths {
            let meta = match metadata_for_path(root, self.config.follow_symlinks) {
                Ok(m) => m,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => continue,
                Err(err) => {
                    return Err(SbhError::Io {
                        path: root.clone(),
                        source: err,
                    });
                }
            };
            if !meta.is_dir() {
                continue;
            }
            let dev = device_id(&meta);
            in_flight.fetch_add(1, Ordering::Release);
            let _ = work_tx.send(WorkItem {
                path: root.clone(),
                depth: 0,
                root_device_id: dev,
                opaque_tree: None,
            });
        }

        // Clone sender for workers; drop original so channel closes when workers finish.
        for _ in 0..parallelism {
            let work_rx = work_rx.clone();
            let work_tx = work_tx.clone();
            let result_tx = result_tx.clone();
            let in_flight = Arc::clone(&in_flight);
            let config = self.config.clone();
            let protection = Arc::clone(&self.protection);
            let heartbeat = self.heartbeat.clone();
            let cancel = Arc::clone(&self.cancel);

            thread::spawn(move || {
                walker_thread(
                    &work_rx,
                    &work_tx,
                    &result_tx,
                    &in_flight,
                    &config,
                    &protection,
                    heartbeat.as_ref(),
                    &cancel,
                );
            });
        }

        Ok(result_rx)
    }

    /// Access the protection registry (e.g. to list discovered markers).
    pub fn protection(&self) -> &parking_lot::RwLock<ProtectionRegistry> {
        &self.protection
    }
}

/// Worker thread function: pulls directories from work channel, processes them,
/// sends results and new subdirectories back.
#[allow(clippy::too_many_arguments)]
fn walker_thread(
    work_rx: &channel::Receiver<WorkItem>,
    work_tx: &channel::Sender<WorkItem>,
    result_tx: &channel::Sender<WalkEntry>,
    in_flight: &AtomicUsize,
    config: &WalkerConfig,
    protection: &parking_lot::RwLock<ProtectionRegistry>,
    heartbeat: Option<&Arc<dyn Fn() + Send + Sync>>,
    cancel: &AtomicBool,
) {
    loop {
        // Check cancellation flag before doing any work.
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Beat the heart if configured.
        if let Some(hb) = heartbeat {
            hb();
        }

        match work_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(item) => {
                process_directory(
                    &item.path,
                    item.depth,
                    item.root_device_id,
                    item.opaque_tree,
                    work_tx,
                    result_tx,
                    in_flight,
                    config,
                    protection,
                    heartbeat,
                    cancel,
                );
                // Mark this work item as completed.
                let remaining = in_flight.fetch_sub(1, Ordering::AcqRel);
                if remaining == 1 {
                    // We were the last in-flight item. Signal termination by
                    // dropping our sender (happens when thread exits).
                }
            }
            Err(channel::RecvTimeoutError::Timeout) => {
                // Check cancel on timeout too, so threads don't linger waiting for work.
                if cancel.load(Ordering::Relaxed) || in_flight.load(Ordering::Acquire) == 0 {
                    return;
                }
            }
            Err(channel::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn send_walk_entry(
    result_tx: &channel::Sender<WalkEntry>,
    walk_entry: &WalkEntry,
    cancel: &AtomicBool,
) -> bool {
    loop {
        match result_tx.send_timeout(walk_entry.clone(), Duration::from_millis(100)) {
            Ok(()) => return true,
            Err(channel::SendTimeoutError::Timeout(_)) => {
                if cancel.load(Ordering::Relaxed) {
                    return false;
                }
            }
            Err(channel::SendTimeoutError::Disconnected(_)) => return false,
        }
    }
}

/// Process one directory: read entries, emit WalkEntry results, enqueue subdirectories.
///
/// Performance: the hot path avoids per-child stat() calls. The directory is stat'd
/// once at the start for device-check and WalkEntry metadata. Child directories are
/// dispatched without stat — the device check is deferred to when each child is
/// processed. On directories with 60K+ children (e.g. /data/tmp), this eliminates
/// tens of thousands of syscalls per scan pass.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn process_directory(
    dir_path: &Path,
    depth: usize,
    root_dev: u64,
    opaque_tree: Option<OpaqueTreeClassification>,
    work_tx: &channel::Sender<WorkItem>,
    result_tx: &channel::Sender<WalkEntry>,
    in_flight: &AtomicUsize,
    config: &WalkerConfig,
    protection: &parking_lot::RwLock<ProtectionRegistry>,
    heartbeat: Option<&Arc<dyn Fn() + Send + Sync>>,
    cancel: &AtomicBool,
) {
    // Check exclusion list.
    if config.excluded_paths.contains(dir_path) {
        return;
    }

    // Check protection registry (covers config patterns and previously discovered markers).
    // Note: .sbh-protect marker files are detected during child iteration below,
    // avoiding a separate lstat per directory.
    if protection.read().is_protected(dir_path) {
        return;
    }

    // Stat the directory once (at depth > 0) — used for both cross-device guard
    // and WalkEntry emission. At depth 0 (root paths), device was already checked
    // at seed time in stream().
    let dir_meta = if depth > 0 {
        match metadata_for_path(dir_path, config.follow_symlinks) {
            Ok(m) => Some(m),
            Err(_) => return,
        }
    } else {
        None
    };

    // Cross-device guard: if this directory is on a different filesystem than
    // its root path, skip the entire subtree. This catches mount points that
    // were queued by the parent (which doesn't per-child stat for device).
    if !config.cross_devices
        && let Some(ref meta) = dir_meta
        && device_id(meta) != root_dev
    {
        return;
    }

    // Read directory entries, gracefully handling permission errors.
    let entries = match fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => return,
        Err(err) if err.kind() == ErrorKind::NotFound => return,
        Err(_) => return, // Other errors: skip gracefully.
    };

    // State for structural signals (incremental accumulation).
    let mut signals = StructuralSignals::default();
    let mut object_count = 0u32;
    let mut total_count = 0u32;
    let mut content_size: u64 = 0;
    let mut parent_has_node_manifest = false;

    // Collect child directories during iteration; queue them AFTER the loop.
    // This prevents a race where a child dir is queued and processed by another
    // thread before we discover a .sbh-protect marker later in the listing.
    let mut pending_children: Vec<PathBuf> = Vec::new();

    for entry_result in entries {
        // Large flat directories can take a long time to iterate. Honor
        // cancellation during the hot loop so the daemon can stop promptly
        // when a scan budget expires instead of waiting for the entire
        // directory to finish.
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Keep the daemon heartbeat alive while iterating a huge directory.
        if total_count.is_multiple_of(256)
            && let Some(hb) = heartbeat
        {
            hb();
        }

        let Ok(entry) = entry_result else {
            continue;
        };

        let child_path = entry.path();

        // ─── Incremental Signal Collection ───
        // We can check signals purely from the name without stat-ing the file.
        if let Some(name_os) = child_path.file_name() {
            let name = name_os.to_string_lossy();
            total_count += 1;

            // Per-directory iteration budget: avoid spending seconds iterating
            // directories with tens of thousands of entries. Structural markers
            // appear early; MAX_ENTRIES_PER_DIR (65 536) is generous.
            if total_count >= MAX_ENTRIES_PER_DIR {
                break;
            }

            match name.as_ref() {
                // Detect .sbh-protect marker during iteration. If found,
                // register the marker and bail — no children get queued.
                ".sbh-protect" => {
                    protection.write().register_marker(dir_path);
                    return; // Skip rest of directory — protected subtree.
                }
                "incremental" => signals.has_incremental = true,
                "deps" => signals.has_deps = true,
                "build" => signals.has_build = true,
                ".fingerprint" => signals.has_fingerprint = true,
                ".git" => signals.has_git = true,
                // Root-level cache-directory tag (Cache Directory Tagging
                // Standard, case-sensitive uppercase per the spec). This is the
                // one signal that identifies an arbitrarily-named build cache —
                // whose deps/incremental/.fingerprint markers live one level
                // deeper under debug/ and release/ — without a name match.
                // Validate the signature line so an unrelated file that merely
                // shares the name cannot mark a directory reclaimable.
                "CACHEDIR.TAG" => {
                    if is_valid_cachedir_tag(&child_path) {
                        signals.has_cachedir_tag = true;
                    }
                }
                "cargo.toml" | "Cargo.toml" => signals.has_cargo_toml = true,
                "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "bun.lock"
                | "bun.lockb" => {
                    parent_has_node_manifest = true;
                }
                _ => {}
            }

            // Check extension for object file heuristics.
            if let Some(ext) = Path::new(name_os).extension() {
                let ext_str = ext.to_string_lossy();
                if ext_str.eq_ignore_ascii_case("o")
                    || ext_str.eq_ignore_ascii_case("rlib")
                    || ext_str.eq_ignore_ascii_case("rmeta")
                    || ext_str.eq_ignore_ascii_case("d")
                {
                    object_count += 1;
                }
            }
        }

        // ─── Type Check & Symlink Handling ───
        // Use file_type() which is often free (cached in directory entry).
        let Ok(ft) = entry.file_type() else {
            continue;
        };

        // Skip symlinks entirely unless following symlinks is explicitly enabled.
        // We do this AFTER collecting signals so that a symlinked .git or Cargo.toml
        // still counts as a signal for the parent directory.
        if !config.follow_symlinks && ft.is_symlink() {
            continue;
        }

        // Determine if we should recurse.
        // If following symlinks, we must stat to see if the target is a dir.
        let is_dir = if config.follow_symlinks && ft.is_symlink() {
            metadata_for_path(&child_path, true).is_ok_and(|m| m.is_dir())
        } else {
            ft.is_dir()
        };

        // ─── Accumulate Content Size ───
        // For files: lstat to get actual size. On ext4 this is ~1μs per call,
        // so 2000 children ≈ 2ms — acceptable for accurate scoring.
        // For child dirs: skip (their recursive size will be computed when they
        // are processed as their own WalkEntry).
        if !is_dir && let Ok(child_meta) = entry.metadata() {
            // Allocated blocks, not apparent length (see `allocated_size`):
            // sparse files must not inflate the directory's reclaim estimate.
            content_size = content_size.saturating_add(allocated_size(&child_meta));
        }

        // ─── Collect Child Dirs ───
        // Deferred dispatch: collect child dirs but don't queue yet. Queueing
        // happens after the loop, ensuring .sbh-protect markers are discovered
        // before any children are dispatched to other worker threads.
        if depth < config.max_depth && is_dir && !config.excluded_paths.contains(&child_path) {
            pending_children.push(child_path);
        }
    }

    // ─── Deferred Recursion Dispatch ───
    // Now that we've confirmed no .sbh-protect marker exists (we would have
    // returned above), queue collected child dirs for worker threads.
    //
    // Use send_timeout + cancel check instead of blocking send to prevent
    // thread leaks: when the scanner times out and sets the cancel flag,
    // threads stuck on a full work channel will notice within 100ms and exit.
    for child_path in pending_children {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let opaque_tree = if config.opaque_pruning {
            classify_opaque_tree(
                &child_path,
                OpaqueTreeContext {
                    parent_has_cargo_toml: signals.has_cargo_toml,
                    parent_has_node_manifest,
                },
            )
        } else {
            None
        };
        if let Some(opaque) = opaque_tree.clone() {
            match opaque.disposition {
                OpaqueTreeDisposition::CandidateOpaque => {
                    let Ok(meta) = metadata_for_path(&child_path, config.follow_symlinks) else {
                        continue;
                    };
                    if !config.cross_devices && device_id(&meta) != root_dev {
                        continue;
                    }
                    let mut emeta = entry_metadata(&meta);
                    if emeta.is_dir {
                        emeta.content_size_bytes =
                            emeta.content_size_bytes.max(OPAQUE_CANDIDATE_SIZE_FLOOR);
                    }
                    let walk_entry = WalkEntry {
                        path: child_path,
                        metadata: emeta,
                        depth: depth + 1,
                        structural_signals: StructuralSignals::default(),
                        is_open: false,
                        opaque_tree: Some(opaque),
                    };
                    if !send_walk_entry(result_tx, &walk_entry, cancel) {
                        return;
                    }
                    continue;
                }
                OpaqueTreeDisposition::ProtectedOpaque => continue,
                OpaqueTreeDisposition::SignalOnly => {}
            }
        }
        in_flight.fetch_add(1, Ordering::Release);
        loop {
            match work_tx.send_timeout(
                WorkItem {
                    path: child_path.clone(),
                    depth: depth + 1,
                    root_device_id: root_dev,
                    opaque_tree: opaque_tree.clone(),
                },
                Duration::from_millis(100),
            ) {
                Ok(()) => break,
                Err(channel::SendTimeoutError::Timeout(_)) => {
                    // Channel full — check cancel before retrying.
                    if cancel.load(Ordering::Relaxed) {
                        in_flight.fetch_sub(1, Ordering::Release);
                        return;
                    }
                }
                Err(channel::SendTimeoutError::Disconnected(_)) => {
                    in_flight.fetch_sub(1, Ordering::Release);
                    return;
                }
            }
        }
    }

    // Finalize structural signals.
    if total_count > 0 && object_count > 0 {
        signals.mostly_object_files = object_count * 2 >= total_count;
    }

    // Emit a WalkEntry for this directory itself (reuse stat from top of function).
    if depth > 0
        && let Some(meta) = dir_meta
    {
        let mut emeta = entry_metadata(&meta);
        // Override content_size_bytes with the sum of immediate children's file
        // sizes. This is a lower bound (doesn't recurse into subdirs, capped at
        // MAX_ENTRIES_PER_DIR children) but vastly better than the inode entry
        // size (~4096) for scoring purposes.
        if emeta.is_dir && content_size > 0 {
            emeta.content_size_bytes = content_size;
        }
        let walk_entry = WalkEntry {
            path: dir_path.to_path_buf(),
            metadata: emeta,
            depth,
            structural_signals: signals,
            is_open: false, // Caller sets this after walk using /proc scan.
            opaque_tree,
        };

        let _ = send_walk_entry(result_tx, &walk_entry, cancel);
    }
}

/// Build `StructuralSignals` by checking presence of well-known child names.
#[allow(dead_code)]
fn signals_from_children(child_names: &[String]) -> StructuralSignals {
    let mut signals = StructuralSignals::default();
    let mut object_count = 0u32;
    let mut total_count = 0u32;

    for name in child_names {
        total_count += 1;
        match name.as_str() {
            "incremental" => signals.has_incremental = true,
            "deps" => signals.has_deps = true,
            "build" => signals.has_build = true,
            ".fingerprint" => signals.has_fingerprint = true,
            ".git" => signals.has_git = true,
            "cargo.toml" => signals.has_cargo_toml = true,
            // Presence-only in this name-list helper (the live walker validates
            // the tag's signature). The spec name is uppercase CACHEDIR.TAG;
            // this helper receives already-lowercased names.
            "cachedir.tag" => signals.has_cachedir_tag = true,
            _ => {}
        }
        // Names are already lowercased, so case-insensitive matching is not needed.
        let ext = std::path::Path::new(name.as_str())
            .extension()
            .map(|e| e.to_string_lossy());
        if matches!(ext.as_deref(), Some("o" | "rlib" | "rmeta" | "d")) {
            object_count += 1;
        }
    }

    if total_count > 0 && object_count > 0 {
        signals.mostly_object_files = object_count * 2 >= total_count;
    }

    signals
}

/// The mandatory signature line that opens a `CACHEDIR.TAG` file, per the Cache
/// Directory Tagging Standard (<https://bford.info/cachedir/>). A conforming
/// file's contents begin with exactly these 43 bytes.
const CACHEDIR_TAG_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Returns true when `path` is a valid `CACHEDIR.TAG` file — i.e. its contents
/// begin with the standard signature line. The read is bounded to the signature
/// length so a large or adversarial file that merely shares the name cannot cost
/// more than a couple of hundred bytes of I/O, and cannot falsely mark a
/// directory as a reclaimable cache.
fn is_valid_cachedir_tag(path: &Path) -> bool {
    use std::io::Read;

    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; CACHEDIR_TAG_SIGNATURE.len()];
    // `read_exact` fills the whole buffer or fails; a file shorter than the
    // signature cannot be a valid tag, so a short read is a clean rejection.
    if file.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == CACHEDIR_TAG_SIGNATURE
}

/// Allocated on-disk size of an entry in bytes.
///
/// On Unix this is `st_blocks * 512` (POSIX defines `st_blocks` in 512-byte
/// units regardless of the filesystem block size), which reflects the space
/// actually consumed on the volume. This is what a disk-pressure tool must
/// score and rank on: a sparse file contributes only its allocated blocks
/// (possibly 0), not its apparent logical length, so "reclaiming this frees
/// N bytes" holds. On non-Unix platforms falls back to the apparent length.
fn allocated_size(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512)
    }
    #[cfg(not(unix))]
    {
        meta.len()
    }
}

/// Extract `EntryMetadata` from `fs::Metadata` (Unix-specific fields via MetadataExt).
fn entry_metadata(meta: &fs::Metadata) -> EntryMetadata {
    let file_type = meta.file_type();
    let kind = if file_type.is_symlink() {
        FsEntryKind::Symlink
    } else if meta.is_dir() {
        FsEntryKind::Directory
    } else if meta.is_file() {
        FsEntryKind::File
    } else {
        FsEntryKind::Other
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Allocated blocks, not apparent length: a sparse file's `len()` can be
        // orders of magnitude larger than the space it consumes on disk (and a
        // hard-linked/cloned tree smaller). Scoring, ranking, and the reclaim
        // estimate all consume this field as "bytes freed if removed".
        let size = allocated_size(meta);
        EntryMetadata {
            size_bytes: size,
            content_size_bytes: size, // Overridden for directories in process_directory.
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            created: meta.created().ok(),
            is_dir: meta.is_dir(),
            inode: meta.ino(),
            device_id: meta.dev(),
            kind,
            permissions: meta.mode(),
        }
    }
    #[cfg(not(unix))]
    {
        let size = meta.len();
        EntryMetadata {
            size_bytes: size,
            content_size_bytes: size,
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            created: meta.created().ok(),
            is_dir: meta.is_dir(),
            inode: 0,
            device_id: 0,
            kind,
            permissions: 0,
        }
    }
}

fn metadata_for_path(path: &Path, follow_symlinks: bool) -> std::io::Result<fs::Metadata> {
    if follow_symlinks {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    }
}

pub fn identity_for_path(path: &Path, follow_symlinks: bool) -> std::io::Result<FsIdentity> {
    metadata_for_path(path, follow_symlinks).map(|meta| entry_metadata(&meta).identity())
}

/// Get device ID from metadata (for cross-device detection).
fn device_id(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.dev()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// Collect all open files as (device, inode) pairs.
///
/// On Linux, scans /proc. Returns an empty set on non-Linux
/// or if /proc is unavailable.
pub fn collect_open_files() -> HashSet<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        collect_open_files_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        HashSet::new()
    }
}

#[cfg(target_os = "linux")]
fn collect_open_files_linux() -> HashSet<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::time::Instant;

    let mut open = HashSet::with_capacity(4096);

    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return open;
    };

    let deadline = Instant::now() + OPEN_FILES_SCAN_BUDGET;
    let mut pids_scanned: usize = 0;

    for proc_entry in proc_dir.flatten() {
        // Budget checks: stop if we've exceeded time or PID limits.
        if pids_scanned >= OPEN_FILES_MAX_PIDS || Instant::now() >= deadline {
            // We do not log here to avoid spamming stderr every batch.
            // The logic fails conservative (partial set = some open files might be missed),
            // but this prevents the daemon from hanging the system.
            break;
        }

        let pid_name = proc_entry.file_name();
        let pid_bytes = pid_name.as_bytes();

        // Only numeric directories (PIDs).
        if pid_bytes.is_empty() || !pid_bytes.iter().all(u8::is_ascii_digit) {
            continue;
        }

        pids_scanned += 1;

        let Ok(fd_entries) = fs::read_dir(proc_entry.path().join("fd")) else {
            continue;
        };

        for fd_entry in fd_entries.flatten() {
            // DirEntry::metadata follows the /proc/<pid>/fd symlink to the target.
            if let Ok(meta) = fd_entry.metadata() {
                open.insert((meta.dev(), meta.ino()));
            }
        }
    }

    open
}

/// Maximum child entries iterated per directory for signal collection.
/// Increased to 65536 to ensure full coverage of large project directories (e.g.
/// node_modules or flat object directories). Iteration is reasonably cheap; missing
/// entries causes permanent blind spots.
const MAX_ENTRIES_PER_DIR: u32 = 65_536;

/// Maximum time to spend scanning /proc for open file ancestors.
/// On agent swarms with many processes, /proc scanning can take minutes.
/// A 5-second budget captures enough data for reliable veto decisions.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const OPEN_FILES_SCAN_BUDGET: Duration = Duration::from_secs(5);

/// Maximum number of PIDs to scan before bailing out.
/// Increased to 50,000 to handle busy swarm machines without false-negative open checks.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const OPEN_FILES_MAX_PIDS: usize = 50_000;

/// Collect absolute open-path ancestors for open file descriptors under `root_paths`.
///
/// For each open file path, all ancestors are inserted, allowing O(1) subtree-open
/// checks with `is_path_open_by_ancestor`.
///
/// Returns `(ancestors, is_complete)`. If `is_complete` is false, scanning was
/// truncated due to budget limits, and open checks may yield false negatives.
pub fn collect_open_path_ancestors(root_paths: &[PathBuf]) -> (HashSet<PathBuf>, bool) {
    #[cfg(target_os = "linux")]
    {
        collect_open_path_ancestors_linux(root_paths)
    }
    #[cfg(not(target_os = "linux"))]
    {
        collect_open_path_ancestors_platform(root_paths)
    }
}

#[derive(Debug, Clone)]
struct CachedOpenPathAncestors {
    roots: Vec<PathBuf>,
    collected_at: Instant,
    paths: HashSet<PathBuf>,
    complete: bool,
}

static OPEN_PATH_ANCESTOR_CACHE: OnceLock<parking_lot::Mutex<Option<CachedOpenPathAncestors>>> =
    OnceLock::new();

#[must_use]
pub fn collect_open_path_ancestors_cached(
    root_paths: &[PathBuf],
    cache_ttl: Duration,
) -> (HashSet<PathBuf>, bool) {
    if cache_ttl.is_zero() {
        return collect_open_path_ancestors(root_paths);
    }

    let roots = normalized_root_cache_key(root_paths);
    let now = Instant::now();
    let cache = OPEN_PATH_ANCESTOR_CACHE.get_or_init(|| parking_lot::Mutex::new(None));

    if let Some(cached) = cache.lock().as_ref()
        && cached.roots == roots
        && now.duration_since(cached.collected_at) <= cache_ttl
    {
        return (cached.paths.clone(), cached.complete);
    }

    let (paths, complete) = collect_open_path_ancestors(&roots);
    *cache.lock() = Some(CachedOpenPathAncestors {
        roots,
        collected_at: now,
        paths: paths.clone(),
        complete,
    });
    (paths, complete)
}

fn normalized_open_roots(root_paths: &[PathBuf]) -> Vec<(PathBuf, usize)> {
    root_paths
        .iter()
        .map(|path| {
            let normalized = crate::core::paths::resolve_absolute_path(path);
            let depth = normalized.components().count();
            (normalized, depth)
        })
        .collect()
}

#[cfg(any(not(target_os = "linux"), test))]
fn common_open_file_probe_root(normalized_roots: &[(PathBuf, usize)]) -> Option<PathBuf> {
    let (first, _) = normalized_roots.first()?;
    let mut candidate = first.as_path();

    while !normalized_roots
        .iter()
        .all(|(root, _)| root.starts_with(candidate))
    {
        candidate = candidate.parent()?;
    }

    // Do not collapse unrelated roots to the filesystem root. A root-wide
    // process-fd query is broader than the per-candidate fallback and can be
    // prohibitively expensive on busy developer machines.
    candidate.parent()?;
    Some(candidate.to_path_buf())
}

fn add_open_path_ancestor_chain(
    ancestors: &mut HashSet<PathBuf>,
    target: &Path,
    normalized_roots: &[(PathBuf, usize)],
) {
    if !target.is_absolute() {
        return;
    }
    let normalized_target = crate::core::paths::resolve_absolute_path(target);
    let stop_at = if normalized_roots.is_empty() {
        None
    } else {
        normalized_roots
            .iter()
            .filter(|(root, _)| normalized_target.starts_with(root))
            // Stop at the outermost matching root so nested-root callers
            // still get ancestor coverage for parent candidates.
            .min_by_key(|(_, depth)| *depth)
            .map(|(root, _)| root.as_path())
    };
    if !normalized_roots.is_empty() && stop_at.is_none() {
        return;
    }

    let mut current = Some(normalized_target.as_path());
    while let Some(path) = current {
        if !ancestors.insert(path.to_path_buf()) {
            break; // Already seen this ancestor chain — skip rest.
        }
        if Some(path) == stop_at {
            break;
        }
        let Some(parent) = path.parent() else {
            break;
        };
        if parent == path {
            break;
        }
        current = Some(parent);
    }
}

#[cfg(target_os = "linux")]
fn collect_open_path_ancestors_linux(root_paths: &[PathBuf]) -> (HashSet<PathBuf>, bool) {
    use std::os::unix::ffi::OsStrExt;
    use std::time::Instant;

    let mut ancestors = HashSet::with_capacity(4096);
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return (ancestors, true);
    };

    let normalized_roots = normalized_open_roots(root_paths);

    let deadline = Instant::now() + OPEN_FILES_SCAN_BUDGET;
    let mut pids_scanned: usize = 0;
    let mut incomplete = false;

    for proc_entry in proc_dir.flatten() {
        // Budget checks: stop if we've exceeded time or PID limits.
        if pids_scanned >= OPEN_FILES_MAX_PIDS || Instant::now() >= deadline {
            incomplete = true;
            break;
        }

        let pid_name = proc_entry.file_name();
        let pid_bytes = pid_name.as_bytes();
        if pid_bytes.is_empty() || !pid_bytes.iter().all(u8::is_ascii_digit) {
            continue;
        }

        pids_scanned += 1;

        let Ok(fd_entries) = fs::read_dir(proc_entry.path().join("fd")) else {
            continue;
        };

        for fd_entry in fd_entries.flatten() {
            let Ok(mut target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            if !target.is_absolute() {
                continue;
            }
            if let Some(stripped) = target.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
                target = PathBuf::from(stripped);
            }
            add_open_path_ancestor_chain(&mut ancestors, &target, &normalized_roots);
        }
    }

    (ancestors, !incomplete)
}

#[cfg(not(target_os = "linux"))]
fn collect_open_path_ancestors_platform(root_paths: &[PathBuf]) -> (HashSet<PathBuf>, bool) {
    let normalized_roots = normalized_open_roots(root_paths);
    if normalized_roots.is_empty() {
        return (HashSet::new(), true);
    }

    let platform = crate::platform::current();
    let mut ancestors = HashSet::with_capacity(4096);
    let probe_roots = common_open_file_probe_root(&normalized_roots).map_or_else(
        || {
            normalized_roots
                .iter()
                .map(|(root, _)| root.clone())
                .collect::<Vec<_>>()
        },
        |root| vec![root],
    );
    for root in &probe_roots {
        let Ok(open_files) = platform.open_files_under(root) else {
            return (ancestors, false);
        };
        for open_file in open_files {
            add_open_path_ancestor_chain(&mut ancestors, &open_file.path, &normalized_roots);
        }
    }

    (ancestors, true)
}

#[derive(Debug, Clone)]
struct CachedActiveReferenceIndex {
    platform_name: &'static str,
    roots: Vec<PathBuf>,
    collected_at: Instant,
    index: ActiveReferenceIndex,
}

static ACTIVE_REFERENCE_INDEX_CACHE: OnceLock<
    parking_lot::Mutex<Option<CachedActiveReferenceIndex>>,
> = OnceLock::new();

fn normalized_root_cache_key(root_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = root_paths
        .iter()
        .map(|path| crate::core::paths::resolve_absolute_path(path))
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

#[derive(Debug, Clone)]
pub struct ActiveReferenceIndex {
    references: HashMap<PathBuf, ActiveReferenceSummary>,
    references_by_identity: HashMap<FsIdentity, ActiveReferenceSummary>,
    complete: bool,
    incomplete_reason: Option<String>,
}

impl Default for ActiveReferenceIndex {
    fn default() -> Self {
        Self::empty()
    }
}

impl ActiveReferenceIndex {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            references: HashMap::new(),
            references_by_identity: HashMap::new(),
            complete: true,
            incomplete_reason: None,
        }
    }

    #[must_use]
    pub fn incomplete(reason: impl Into<String>) -> Self {
        Self {
            references: HashMap::new(),
            references_by_identity: HashMap::new(),
            complete: false,
            incomplete_reason: Some(reason.into()),
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub fn incomplete_reason(&self) -> Option<&str> {
        self.incomplete_reason.as_deref()
    }

    #[must_use]
    pub fn summary_for(&self, path: &Path) -> ActiveReferenceSummary {
        let mut summary = self.references.get(path).cloned().unwrap_or_default();
        if let Some(reason) = &self.incomplete_reason {
            summary.mark_incomplete(reason.clone());
        }
        summary
    }

    #[must_use]
    pub fn summary_for_identity(&self, identity: FsIdentity) -> ActiveReferenceSummary {
        let mut summary = self
            .references_by_identity
            .get(&identity)
            .cloned()
            .unwrap_or_default();
        if let Some(reason) = &self.incomplete_reason {
            summary.mark_incomplete(reason.clone());
        }
        summary
    }

    fn add_reference<F>(&mut self, roots: &[PathBuf], reference_path: &Path, mut add: F)
    where
        F: FnMut(&mut ActiveReferenceSummary),
    {
        let normalized = crate::core::paths::resolve_absolute_path(reference_path);
        let stop_at = roots
            .iter()
            .filter(|root| normalized.starts_with(root))
            .min_by_key(|root| root.components().count())
            .map(PathBuf::as_path);
        let Some(stop_at) = stop_at else {
            return;
        };

        let mut current = Some(normalized.as_path());
        while let Some(path) = current {
            add(self.references.entry(path.to_path_buf()).or_default());
            if let Ok(meta) = fs::symlink_metadata(path) {
                add(self
                    .references_by_identity
                    .entry(entry_metadata(&meta).identity())
                    .or_default());
            }
            if path == stop_at {
                break;
            }
            let Some(parent) = path.parent() else {
                break;
            };
            if parent == path {
                break;
            }
            current = Some(parent);
        }
    }
}

/// Collect structured active-reference evidence under scan roots using the PAL.
///
/// Unsupported PAL methods are treated as incomplete evidence rather than scan
/// failures; callers should keep any cheaper platform-specific fallback checks.
#[must_use]
pub fn collect_active_reference_index(
    platform: &dyn Platform,
    root_paths: &[PathBuf],
) -> ActiveReferenceIndex {
    let roots = root_paths
        .iter()
        .map(|path| crate::core::paths::resolve_absolute_path(path))
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return ActiveReferenceIndex::empty();
    }

    let mut index = ActiveReferenceIndex {
        references: HashMap::new(),
        references_by_identity: HashMap::new(),
        complete: true,
        incomplete_reason: active_reference_visibility_warning(platform).map(str::to_string),
    };
    if index.incomplete_reason.is_some() {
        index.complete = false;
    }
    let mut process_names = HashMap::new();
    match platform.process_list() {
        Ok(processes) => {
            for process in processes {
                process_names.insert(process.pid, process.name);
            }
        }
        Err(_) => index.complete = false,
    }

    for root in &roots {
        match platform.open_files_under(root) {
            Ok(open_files) => {
                for open_file in open_files {
                    let name = process_names.get(&open_file.pid).cloned();
                    index.add_reference(&roots, &open_file.path, |summary| {
                        summary.add_open_file_descriptor(open_file.pid, name.clone());
                    });
                }
            }
            Err(_) => index.complete = false,
        }

        match platform.executables_under(root) {
            Ok(processes) => {
                for process in processes {
                    if let Some(executable) = process.executable.as_deref() {
                        let name = Some(process.name.clone());
                        index.add_reference(&roots, executable, |summary| {
                            summary.add_running_executable(process.pid, name.clone());
                        });
                    }
                }
            }
            Err(_) => index.complete = false,
        }

        match platform.mmap_regions_under(root) {
            Ok(regions) => {
                for region in regions {
                    let name = process_names.get(&region.pid).cloned();
                    index.add_reference(&roots, &region.path, |summary| {
                        summary.add_mmap_region(region.pid, name.clone());
                    });
                }
            }
            Err(_) => index.complete = false,
        }
    }

    index
}

fn active_reference_visibility_warning(platform: &dyn Platform) -> Option<&'static str> {
    if platform.name() == "macos" && !process_can_inspect_all_users() {
        Some(MACOS_USER_SCOPE_ACTIVE_REFERENCE_WARNING)
    } else {
        None
    }
}

#[cfg(unix)]
fn process_can_inspect_all_users() -> bool {
    // A root-scoped LaunchDaemon can inspect system-wide process state; a
    // user-scoped LaunchAgent generally cannot see other users' file handles.
    nix::unistd::Uid::effective().is_root()
}

#[cfg(not(unix))]
fn process_can_inspect_all_users() -> bool {
    true
}

#[must_use]
pub fn collect_active_reference_index_cached(
    platform: &dyn Platform,
    root_paths: &[PathBuf],
    cache_ttl: Duration,
) -> ActiveReferenceIndex {
    if cache_ttl.is_zero() {
        return collect_active_reference_index(platform, root_paths);
    }

    let roots = normalized_root_cache_key(root_paths);
    if roots.is_empty() {
        return ActiveReferenceIndex::empty();
    }

    let now = Instant::now();
    let platform_name = platform.name();
    let cache = ACTIVE_REFERENCE_INDEX_CACHE.get_or_init(|| parking_lot::Mutex::new(None));

    if let Some(cached) = cache.lock().as_ref()
        && cached.platform_name == platform_name
        && cached.roots == roots
        && now.duration_since(cached.collected_at) <= cache_ttl
    {
        return cached.index.clone();
    }

    let index = collect_active_reference_index(platform, &roots);
    *cache.lock() = Some(CachedActiveReferenceIndex {
        platform_name,
        roots,
        collected_at: now,
        index: index.clone(),
    });
    index
}

/// Check if `path` is present in the open-ancestor index.
#[must_use]
pub fn is_path_open_by_ancestor<S: std::hash::BuildHasher>(
    path: &Path,
    open_ancestors: &HashSet<PathBuf, S>,
) -> bool {
    open_ancestors.contains(path)
}

/// Memoized open-file detector for repeated path checks during one scan pass.
#[cfg_attr(not(unix), allow(dead_code))]
pub struct OpenPathCache<'a, S = std::collections::hash_map::RandomState> {
    open_inodes: &'a HashSet<(u64, u64), S>,
    dir_cache: HashMap<PathBuf, bool>,
}

impl<'a, S: std::hash::BuildHasher> OpenPathCache<'a, S> {
    #[must_use]
    pub fn new(open_inodes: &'a HashSet<(u64, u64), S>) -> Self {
        Self {
            open_inodes,
            dir_cache: HashMap::new(),
        }
    }

    #[must_use]
    pub fn is_path_open(&mut self, path: &Path) -> bool {
        #[cfg(unix)]
        {
            self.is_path_open_unix(path)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            false
        }
    }

    #[cfg(unix)]
    fn is_path_open_unix(&mut self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        const MAX_SCAN: usize = 20_000;

        if let Some(cached) = self.dir_cache.get(path).copied() {
            return cached;
        }

        let mut stack = vec![path.to_path_buf()];
        let mut checked = 0usize;
        let mut visited_dirs: Vec<PathBuf> = Vec::new();

        while let Some(p) = stack.pop() {
            if let Some(cached) = self.dir_cache.get(&p).copied() {
                if cached {
                    self.dir_cache.insert(path.to_path_buf(), true);
                    return true;
                }
                continue;
            }

            // Use symlink_metadata to avoid following symlinks. Following symlinks
            // can lead to infinite recursion on loops and escapes the directory tree.
            // If the symlink points to a directory, is_dir() will be false, so we
            // won't recurse, which is correct (we don't delete through symlinks).
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };

            if self.open_inodes.contains(&(meta.dev(), meta.ino())) {
                self.dir_cache.insert(path.to_path_buf(), true);
                return true;
            }

            checked += 1;
            if checked >= MAX_SCAN {
                // Limit reached, assume unsafe.
                self.dir_cache.insert(path.to_path_buf(), true);
                return true;
            }

            if meta.is_dir() {
                visited_dirs.push(p.clone());
                if let Ok(entries) = fs::read_dir(&p) {
                    for entry in entries.flatten() {
                        stack.push(entry.path());
                    }
                }
            }
        }

        // Fully explored with no open inode hit: every visited directory is safe to cache false.
        for dir in visited_dirs {
            self.dir_cache.insert(dir, false);
        }
        self.dir_cache.insert(path.to_path_buf(), false);
        false
    }
}

/// Check if any file under `path` is currently open (inode match).
///
/// Returns `true` if an open file is found OR if the scan limit is reached
/// (fail conservative).
pub fn is_path_open<S: std::hash::BuildHasher>(
    path: &Path,
    open_inodes: &HashSet<(u64, u64), S>,
) -> bool {
    let mut checker = OpenPathCache::new(open_inodes);
    checker.is_path_open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ScoringConfig;
    use crate::scanner::patterns::ArtifactPatternRegistry;
    use crate::scanner::protection;
    use crate::scanner::scoring::{
        ActiveReferenceSummary, CandidateInput, DecisionAction, ScoringEngine,
    };
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn open_path_ancestor_chain_stops_at_outermost_matching_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let nested_root = root.join("project");
        let leaf_dir = nested_root.join("target").join("debug");
        fs::create_dir_all(&leaf_dir).unwrap();
        let open_file = leaf_dir.join("build.log");
        fs::write(&open_file, "active").unwrap();

        let roots = normalized_open_roots(&[root.clone(), nested_root.clone()]);
        let mut ancestors = HashSet::new();
        add_open_path_ancestor_chain(&mut ancestors, &open_file, &roots);
        let normalized_open_file = crate::core::paths::resolve_absolute_path(&open_file);
        let normalized_leaf_dir = crate::core::paths::resolve_absolute_path(&leaf_dir);
        let normalized_nested_root = crate::core::paths::resolve_absolute_path(&nested_root);
        let normalized_root = crate::core::paths::resolve_absolute_path(&root);
        let normalized_tmp = crate::core::paths::resolve_absolute_path(dir.path());

        assert!(ancestors.contains(&normalized_open_file));
        assert!(ancestors.contains(&normalized_leaf_dir));
        assert!(ancestors.contains(&normalized_nested_root));
        assert!(ancestors.contains(&normalized_root));
        assert!(
            !ancestors.contains(&normalized_tmp),
            "ancestor chain should stop at the outermost matching scan root"
        );
    }

    #[test]
    fn common_open_file_probe_root_groups_related_candidates() {
        let roots = normalized_open_roots(&[
            PathBuf::from("/tmp/sbh-run/scan-root/project-a/target"),
            PathBuf::from("/tmp/sbh-run/scan-root/project-b/target"),
        ]);
        let expected =
            crate::core::paths::resolve_absolute_path(Path::new("/tmp/sbh-run/scan-root"));

        assert_eq!(
            common_open_file_probe_root(&roots).as_deref(),
            Some(expected.as_path())
        );
    }

    #[test]
    fn common_open_file_probe_root_does_not_collapse_to_filesystem_root() {
        let roots = normalized_open_roots(&[
            PathBuf::from("/tmp/sbh-run/target"),
            PathBuf::from("/Users/example/project/target"),
        ]);

        assert_eq!(common_open_file_probe_root(&roots), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn open_path_ancestors_uses_platform_collector_on_macos() {
        let dir = tempfile::tempdir().unwrap();
        let active_dir = dir.path().join("active-target");
        fs::create_dir(&active_dir).unwrap();
        let active_file = active_dir.join("in-use.bin");
        fs::write(&active_file, "payload").unwrap();
        let handle = fs::File::open(&active_file).unwrap();

        let (ancestors, complete) = collect_open_path_ancestors(&[dir.path().to_path_buf()]);
        assert!(
            complete,
            "macOS PAL open-file preflight should complete for a temp root"
        );

        if !ancestors.contains(&active_file) {
            drop(handle);
            return;
        }

        assert!(ancestors.contains(&active_dir));
        assert!(is_path_open_by_ancestor(&active_dir, &ancestors));
        drop(handle);
    }

    #[derive(Debug, Default)]
    struct TestActiveRefPlatform {
        processes: Vec<crate::platform::types::ProcessInfo>,
        open_files: Vec<crate::platform::types::OpenFile>,
        executables: Vec<crate::platform::types::ProcessInfo>,
        mmap_regions: Vec<crate::platform::types::MappedRegion>,
        probe_calls: AtomicUsize,
    }

    impl Platform for TestActiveRefPlatform {
        fn name(&self) -> &'static str {
            "test-active-ref"
        }

        fn fs_stats(&self, path: &Path) -> Result<crate::platform::pal::FsStats> {
            Ok(crate::platform::pal::FsStats {
                total_bytes: 1,
                free_bytes: 1,
                available_bytes: 1,
                fs_type: "test".to_string(),
                mount_point: path.to_path_buf(),
                is_readonly: false,
            })
        }

        fn mount_points(&self) -> Result<Vec<crate::platform::pal::MountPoint>> {
            Ok(Vec::new())
        }

        fn is_ram_backed(&self, _path: &Path) -> Result<bool> {
            Ok(false)
        }

        fn default_paths(&self) -> crate::platform::pal::PlatformPaths {
            crate::platform::pal::PlatformPaths::default()
        }

        fn memory_info(&self) -> Result<crate::platform::pal::MemoryInfo> {
            Ok(crate::platform::pal::MemoryInfo {
                total_bytes: 1,
                available_bytes: 1,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            })
        }

        fn service_manager(&self) -> Box<dyn crate::platform::pal::ServiceManager> {
            Box::<crate::platform::pal::NoopServiceManager>::default()
        }

        fn process_list(&self) -> Result<Vec<crate::platform::types::ProcessInfo>> {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.processes.clone())
        }

        fn open_files_under(&self, _path: &Path) -> Result<Vec<crate::platform::types::OpenFile>> {
            Ok(self.open_files.clone())
        }

        fn executables_under(
            &self,
            _path: &Path,
        ) -> Result<Vec<crate::platform::types::ProcessInfo>> {
            Ok(self.executables.clone())
        }

        fn mmap_regions_under(
            &self,
            _path: &Path,
        ) -> Result<Vec<crate::platform::types::MappedRegion>> {
            Ok(self.mmap_regions.clone())
        }
    }

    fn process(
        pid: i32,
        name: &str,
        executable: Option<PathBuf>,
    ) -> crate::platform::types::ProcessInfo {
        crate::platform::types::ProcessInfo {
            pid,
            parent_pid: None,
            name: name.to_string(),
            command_line: Vec::new(),
            executable,
            cwd: None,
            start_time_unix_ms: None,
            virtual_memory_bytes: None,
            resident_memory_bytes: None,
            cpu_user_micros: None,
            cpu_system_micros: None,
        }
    }

    fn test_config(root: &Path) -> WalkerConfig {
        WalkerConfig {
            root_paths: vec![root.to_path_buf()],
            max_depth: 10,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 2,
            excluded_paths: HashSet::new(),
            opaque_pruning: false,
        }
    }

    /// Regression test for GH#17: the scanner must size entries by allocated
    /// blocks (`st_blocks * 512`), not apparent length (`st_size`). A sparse
    /// file created via `set_len` has a huge logical size but allocates no
    /// data blocks, so it must contribute (almost) nothing to `size_bytes`
    /// or to its parent directory's `content_size_bytes`.
    #[cfg(unix)]
    #[test]
    fn sparse_files_are_sized_by_allocated_blocks_not_apparent_length() {
        const APPARENT: u64 = 1 << 30; // 1 GiB logical size, zero data written.
        // Allow generous slack (metadata/indirect blocks), but far below 1 GiB.
        const ALLOCATED_CEILING: u64 = 16 * 1024 * 1024;

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("scratch-build");
        fs::create_dir_all(&dir).unwrap();
        let sparse_path = dir.join("disk.img");
        let file = fs::File::create(&sparse_path).unwrap();
        file.set_len(APPARENT).unwrap();
        drop(file);

        // Sanity: the filesystem really reports the full apparent length.
        let meta = fs::metadata(&sparse_path).unwrap();
        assert_eq!(meta.len(), APPARENT);
        // Skip (vacuously pass) only if the filesystem doesn't support sparse
        // files at all and actually allocated the full gigabyte.
        {
            use std::os::unix::fs::MetadataExt;
            if meta.blocks().saturating_mul(512) >= APPARENT {
                eprintln!("filesystem does not support sparse files; skipping");
                return;
            }
        }

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        // `entry_metadata` (the path CandidateOpaque emission also takes) must
        // report the allocated size, not the 1 GiB apparent length.
        let emeta = entry_metadata(&meta);
        assert_eq!(emeta.size_bytes, allocated_size(&meta));
        assert!(
            emeta.size_bytes < ALLOCATED_CEILING,
            "sparse file size_bytes should reflect allocated blocks, got {} (apparent {})",
            emeta.size_bytes,
            APPARENT
        );

        // The walker emits directory entries; the sparse file must not inflate
        // its parent's accumulated content size.
        let dir_entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert!(
            dir_entry.metadata.content_size_bytes < ALLOCATED_CEILING,
            "directory content_size_bytes should sum allocated blocks, got {} (apparent {})",
            dir_entry.metadata.content_size_bytes,
            APPARENT
        );
    }

    #[test]
    fn active_reference_index_maps_fd_exec_and_mmap_to_ancestors() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let candidate = root.join("target");
        let open_file_path = candidate.join("debug").join("object.o");
        let executable_path = candidate.join("debug").join("tool");
        let mmap_path = candidate.join("incremental").join("cache.bin");
        fs::create_dir_all(open_file_path.parent().unwrap()).unwrap();
        fs::create_dir_all(executable_path.parent().unwrap()).unwrap();
        fs::create_dir_all(mmap_path.parent().unwrap()).unwrap();
        fs::write(&open_file_path, b"object").unwrap();
        fs::write(&executable_path, b"tool").unwrap();
        fs::write(&mmap_path, b"cache").unwrap();

        let platform = TestActiveRefPlatform {
            processes: vec![process(42, "rustc", None)],
            open_files: vec![crate::platform::types::OpenFile {
                pid: 42,
                path: open_file_path,
                fd: Some(9),
                kind: crate::platform::types::OpenFileKind::Regular,
                mode: crate::platform::types::OpenFileMode::ReadWrite,
            }],
            executables: vec![process(42, "rustc", Some(executable_path))],
            mmap_regions: vec![crate::platform::types::MappedRegion {
                pid: 42,
                path: mmap_path,
                start_address: Some(0x1000),
                end_address: Some(0x2000),
                protection: Some("r--".to_string()),
            }],
            ..Default::default()
        };

        let index = collect_active_reference_index(&platform, std::slice::from_ref(&root));
        assert!(index.is_complete());

        let normalized_candidate = crate::core::paths::resolve_absolute_path(&candidate);
        let summary = index.summary_for(&normalized_candidate);
        let process = summary
            .processes
            .iter()
            .find(|process| process.pid == 42)
            .expect("candidate should inherit active references from children");
        assert_eq!(process.name.as_deref(), Some("rustc"));
        assert_eq!(process.open_file_descriptors, 1);
        assert!(process.running_executable);
        assert_eq!(process.mmap_regions, 1);

        let reason = summary
            .safe_reclaim_reason()
            .expect("active summary should explain safety veto");
        assert!(reason.contains("open file descriptor"));
        assert!(reason.contains("running executable"));
        assert!(reason.contains("mmap region"));

        let identity_summary =
            index.summary_for_identity(identity_for_path(&candidate, false).unwrap());
        assert_eq!(
            identity_summary, summary,
            "candidate root identity should provide the same O(1) active-reference answer"
        );
    }

    #[test]
    fn incomplete_active_reference_index_marks_candidate_summaries() {
        let index = ActiveReferenceIndex::incomplete(MACOS_USER_SCOPE_ACTIVE_REFERENCE_WARNING);
        let summary = index.summary_for(Path::new("/tmp/cargo-target-active"));

        assert!(!index.is_complete());
        assert_eq!(
            index.incomplete_reason(),
            Some(MACOS_USER_SCOPE_ACTIVE_REFERENCE_WARNING)
        );
        assert_eq!(
            summary.safe_reclaim_reason().as_deref(),
            Some(MACOS_USER_SCOPE_ACTIVE_REFERENCE_WARNING)
        );
    }

    #[test]
    fn active_reference_scan_config_gates_small_candidates() {
        let config = ActiveReferenceScanConfig::new(Duration::from_secs(30), 100 * 1024 * 1024);

        assert!(!config.should_probe(100 * 1024 * 1024 - 1));
        assert!(config.should_probe(100 * 1024 * 1024));
        assert!(ActiveReferenceScanConfig::new(Duration::ZERO, 0).should_probe(1));
    }

    #[test]
    fn cached_active_reference_collection_reuses_snapshot_within_ttl() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let candidate = root.join("target");
        let open_file_path = candidate.join("debug").join("object.o");
        fs::create_dir_all(open_file_path.parent().unwrap()).unwrap();
        fs::write(&open_file_path, b"object").unwrap();

        let platform = TestActiveRefPlatform {
            processes: vec![process(42, "rustc", None)],
            open_files: vec![crate::platform::types::OpenFile {
                pid: 42,
                path: open_file_path,
                fd: Some(9),
                kind: crate::platform::types::OpenFileKind::Regular,
                mode: crate::platform::types::OpenFileMode::ReadWrite,
            }],
            ..Default::default()
        };

        let first = collect_active_reference_index_cached(
            &platform,
            std::slice::from_ref(&root),
            Duration::from_secs(30),
        );
        let second = collect_active_reference_index_cached(
            &platform,
            std::slice::from_ref(&root),
            Duration::from_secs(30),
        );

        let candidate_identity = identity_for_path(&candidate, false).unwrap();
        assert!(!first.summary_for_identity(candidate_identity).is_empty());
        assert!(!second.summary_for_identity(candidate_identity).is_empty());
        assert_eq!(platform.probe_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[test]
    fn active_reference_summary_uses_inode_identity_for_alias_paths() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let real_root = tmp.path().join("real");
        let alias_root = tmp.path().join("alias");
        let candidate = real_root.join("target");
        let open_file_path = candidate.join("debug").join("object.o");
        fs::create_dir_all(open_file_path.parent().unwrap()).unwrap();
        fs::write(&open_file_path, b"object").unwrap();
        symlink(&real_root, &alias_root).unwrap();

        let platform = TestActiveRefPlatform {
            processes: vec![process(42, "rustc", None)],
            open_files: vec![crate::platform::types::OpenFile {
                pid: 42,
                path: open_file_path,
                fd: Some(9),
                kind: crate::platform::types::OpenFileKind::Regular,
                mode: crate::platform::types::OpenFileMode::ReadWrite,
            }],
            ..Default::default()
        };

        let index = collect_active_reference_index(&platform, std::slice::from_ref(&real_root));
        let alias_candidate = alias_root.join("target");
        let alias_meta = entry_metadata(&fs::symlink_metadata(&alias_candidate).unwrap());

        assert!(
            index.summary_for(&alias_candidate).is_empty(),
            "path lookup should not canonicalize candidate aliases in the hot path"
        );
        assert!(
            !index.summary_for_identity(alias_meta.identity()).is_empty(),
            "identity lookup should preserve alias safety without per-candidate realpath"
        );
    }

    #[test]
    fn walks_simple_tree() {
        let tmp = TempDir::new().unwrap();

        // root/
        //   a/
        //     b/
        //   c/
        fs::create_dir_all(tmp.path().join("a").join("b")).unwrap();
        fs::create_dir_all(tmp.path().join("c")).unwrap();

        let config = test_config(tmp.path());
        let protection = ProtectionRegistry::marker_only();
        let walker = DirectoryWalker::new(config, protection);
        let entries = walker.walk().unwrap();

        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(paths.contains(&tmp.path().join("a")));
        assert!(paths.contains(&tmp.path().join("a").join("b")));
        assert!(paths.contains(&tmp.path().join("c")));
    }

    #[test]
    fn respects_max_depth() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("a").join("b").join("c").join("d")).unwrap();

        let mut config = test_config(tmp.path());
        config.max_depth = 2;
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        // Depth 0 = root (not emitted), depth 1 = a, depth 2 = b, depth 3 = c (not reached)
        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(paths.contains(&tmp.path().join("a")));
        assert!(paths.contains(&tmp.path().join("a").join("b")));
        assert!(!paths.contains(&tmp.path().join("a").join("b").join("c")));
    }

    #[test]
    fn skips_excluded_paths() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("keep")).unwrap();
        fs::create_dir_all(tmp.path().join("skip")).unwrap();

        let mut config = test_config(tmp.path());
        config.excluded_paths.insert(tmp.path().join("skip"));
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(paths.contains(&tmp.path().join("keep")));
        assert!(!paths.contains(&tmp.path().join("skip")));
    }

    #[test]
    fn skips_protected_directories() {
        let tmp = TempDir::new().unwrap();
        let protected_dir = tmp.path().join("critical");
        let unprotected_dir = tmp.path().join("disposable");
        fs::create_dir_all(protected_dir.join("subdir")).unwrap();
        fs::create_dir_all(&unprotected_dir).unwrap();

        // Create a .sbh-protect marker.
        protection::create_marker(&protected_dir, None).unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(paths.contains(&unprotected_dir));
        // Protected dir and its children should not appear.
        assert!(!paths.iter().any(|p| p.starts_with(&protected_dir)));
    }

    #[test]
    fn collects_structural_signals() {
        let tmp = TempDir::new().unwrap();
        let target_dir = tmp.path().join("target");
        fs::create_dir_all(target_dir.join("incremental")).unwrap();
        fs::create_dir_all(target_dir.join("deps")).unwrap();
        fs::create_dir_all(target_dir.join(".fingerprint")).unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let target_entry = entries.iter().find(|e| e.path == target_dir).unwrap();
        assert!(target_entry.structural_signals.has_incremental);
        assert!(target_entry.structural_signals.has_deps);
        assert!(target_entry.structural_signals.has_fingerprint);
    }

    const VALID_CACHEDIR_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n# For information about cache directory tags see https://bford.info/cachedir/\n";

    #[test]
    fn collects_cachedir_tag_signal_on_arbitrarily_named_dir() {
        // The whole point of bd-k0t3r: a build cache under an arbitrary name
        // (here "srw", which matches no `rch_target_*`/target pattern) whose
        // real cargo markers live one level down under debug/ and release/ must
        // still be detected — via the root CACHEDIR.TAG cargo writes.
        let tmp = TempDir::new().unwrap();
        let cache_dir = tmp.path().join("srw");
        fs::create_dir_all(cache_dir.join("debug").join("deps")).unwrap();
        fs::create_dir_all(cache_dir.join("release")).unwrap();
        fs::write(cache_dir.join("CACHEDIR.TAG"), VALID_CACHEDIR_TAG).unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let cache_entry = entries.iter().find(|e| e.path == cache_dir).unwrap();
        assert!(
            cache_entry.structural_signals.has_cachedir_tag,
            "root CACHEDIR.TAG should set has_cachedir_tag regardless of dir name"
        );
        assert!(
            cache_entry.structural_signals.has_strong_signal(),
            "a validated CACHEDIR.TAG is a strong build/cache signal on its own"
        );
    }

    #[test]
    fn cachedir_tag_with_wrong_signature_is_ignored() {
        // A file that merely shares the name CACHEDIR.TAG but lacks the standard
        // signature must NOT mark the directory reclaimable.
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("looks-tagged");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("CACHEDIR.TAG"), "not the real signature\n").unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let entry = entries.iter().find(|e| e.path == dir).unwrap();
        assert!(
            !entry.structural_signals.has_cachedir_tag,
            "a CACHEDIR.TAG without the standard signature must be ignored"
        );
    }

    #[test]
    fn is_valid_cachedir_tag_checks_signature() {
        let tmp = TempDir::new().unwrap();
        let good = tmp.path().join("good.tag");
        fs::write(&good, VALID_CACHEDIR_TAG).unwrap();
        assert!(is_valid_cachedir_tag(&good));

        let bad = tmp.path().join("bad.tag");
        fs::write(&bad, "Signature: deadbeef\n").unwrap();
        assert!(!is_valid_cachedir_tag(&bad));

        let short = tmp.path().join("short.tag");
        fs::write(&short, "Signature:").unwrap();
        assert!(!is_valid_cachedir_tag(&short));

        assert!(!is_valid_cachedir_tag(&tmp.path().join("absent.tag")));
    }

    #[test]
    fn opaque_pruning_emits_target_once_without_descending() {
        let tmp = TempDir::new().unwrap();
        let project = tmp.path().join("project");
        let target_dir = project.join("target");
        fs::create_dir_all(target_dir.join("debug").join("deps")).unwrap();
        fs::write(project.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();

        let mut config = test_config(tmp.path());
        config.opaque_pruning = true;
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let target_entries: Vec<_> = entries
            .iter()
            .filter(|entry| entry.path == target_dir)
            .collect();
        assert_eq!(target_entries.len(), 1);
        assert_eq!(
            target_entries[0]
                .opaque_tree
                .as_ref()
                .map(|opaque| opaque.disposition),
            Some(OpaqueTreeDisposition::CandidateOpaque)
        );
        assert!(
            !entries
                .iter()
                .any(|entry| entry.path.starts_with(target_dir.join("debug")))
        );
    }

    fn synthetic_large_cargo_tree(root: &Path, crate_count: usize) -> PathBuf {
        let project = root.join("project");
        let target_dir = project.join("target");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();

        for index in 0..crate_count {
            let crate_dir = target_dir
                .join("debug")
                .join("deps")
                .join(format!("crate_{index:03}"));
            fs::create_dir_all(crate_dir.join("src")).unwrap();
            fs::create_dir_all(crate_dir.join("incremental")).unwrap();
            fs::write(crate_dir.join("src").join("lib.rs"), b"pub fn demo() {}\n").unwrap();
        }

        target_dir
    }

    fn walk_fixture(root: &Path, opaque_pruning: bool) -> Vec<WalkEntry> {
        let mut config = test_config(root);
        config.parallelism = 1;
        config.opaque_pruning = opaque_pruning;

        DirectoryWalker::new(config, ProtectionRegistry::marker_only())
            .walk()
            .unwrap()
    }

    #[derive(Debug)]
    struct ScannerValidationReport {
        entries_visited: usize,
        opaque_pruned_dirs: usize,
        delete_paths: HashSet<PathBuf>,
        hard_veto_paths: HashMap<PathBuf, String>,
        delete_candidate_bytes: u64,
        elapsed: Duration,
        process_cpu_micros: Option<u64>,
    }

    impl ScannerValidationReport {
        fn deterministic_effort_ratio_against(&self, other: &Self) -> usize {
            other.entries_visited / self.entries_visited.max(1)
        }

        fn elapsed_wall_seconds(&self) -> f64 {
            self.elapsed.as_secs_f64()
        }
    }

    #[derive(Debug, serde::Serialize)]
    struct ScannerValidationMetrics {
        engine: &'static str,
        dispatch: &'static str,
        entries_visited: usize,
        opaque_pruned_dirs: usize,
        delete_candidates: usize,
        hard_vetoes: usize,
        delete_candidate_bytes: u64,
        elapsed_wall_seconds: f64,
        process_cpu_micros: Option<u64>,
    }

    #[derive(Debug, serde::Serialize)]
    struct ScannerValidationArtifact {
        schema_version: u32,
        scenario: &'static str,
        v1: ScannerValidationMetrics,
        v2: ScannerValidationMetrics,
        deterministic_effort_ratio: usize,
        observed_cpu_ratio: Option<f64>,
        v2_delete_subset_of_v1: bool,
        v2_approves_v1_hard_vetoes: Vec<String>,
    }

    fn current_process_cpu_micros() -> Option<u64> {
        let stats = crate::platform::current().self_stats().ok()?;
        Some(
            stats
                .cpu_user_micros
                .saturating_add(stats.cpu_system_micros),
        )
    }

    fn scanner_validation_metrics(
        report: &ScannerValidationReport,
        engine: &'static str,
        dispatch: &'static str,
    ) -> ScannerValidationMetrics {
        ScannerValidationMetrics {
            engine,
            dispatch,
            entries_visited: report.entries_visited,
            opaque_pruned_dirs: report.opaque_pruned_dirs,
            delete_candidates: report.delete_paths.len(),
            hard_vetoes: report.hard_veto_paths.len(),
            delete_candidate_bytes: report.delete_candidate_bytes,
            elapsed_wall_seconds: report.elapsed_wall_seconds(),
            process_cpu_micros: report.process_cpu_micros,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn observed_cpu_ratio(v1: Option<u64>, v2: Option<u64>) -> Option<f64> {
        let (v1, v2) = v1.zip(v2)?;
        if v1 == 0 || v2 == 0 {
            return None;
        }
        Some(v1 as f64 / v2 as f64)
    }

    fn scanner_validation_artifact(
        scenario: &'static str,
        v1: &ScannerValidationReport,
        v2: &ScannerValidationReport,
    ) -> ScannerValidationArtifact {
        let mut veto_violations = v2
            .delete_paths
            .iter()
            .filter(|path| v1.hard_veto_paths.contains_key(*path))
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        veto_violations.sort();

        ScannerValidationArtifact {
            schema_version: 1,
            scenario,
            v1: scanner_validation_metrics(v1, "v1", "v1_directory_walker"),
            v2: scanner_validation_metrics(v2, "v2", "v2_opaque_pruning_walker"),
            deterministic_effort_ratio: v2.deterministic_effort_ratio_against(v1),
            observed_cpu_ratio: observed_cpu_ratio(v1.process_cpu_micros, v2.process_cpu_micros),
            v2_delete_subset_of_v1: v2.delete_paths.is_subset(&v1.delete_paths),
            v2_approves_v1_hard_vetoes: veto_violations,
        }
    }

    fn scanner_validation_report(
        root: &Path,
        opaque_pruning: bool,
        open_ancestors: &HashSet<PathBuf>,
    ) -> ScannerValidationReport {
        let start_cpu = current_process_cpu_micros();
        let start = Instant::now();
        let entries = walk_fixture(root, opaque_pruning);
        let elapsed = start.elapsed();
        let process_cpu_micros = start_cpu
            .zip(current_process_cpu_micros())
            .map(|(start, end)| end.saturating_sub(start));
        let registry = ArtifactPatternRegistry::default();
        let scoring = ScoringEngine::from_config(&ScoringConfig::default(), 0);
        let mut delete_paths = HashSet::new();
        let mut hard_veto_paths = HashMap::new();
        let mut opaque_pruned_dirs = 0usize;
        let mut delete_candidate_bytes = 0u64;

        for entry in &entries {
            let classification = if let Some(opaque_tree) = &entry.opaque_tree {
                match opaque_tree.disposition {
                    OpaqueTreeDisposition::CandidateOpaque => {
                        opaque_pruned_dirs += 1;
                        opaque_tree.classification.clone()
                    }
                    OpaqueTreeDisposition::ProtectedOpaque | OpaqueTreeDisposition::SignalOnly => {
                        continue;
                    }
                }
            } else {
                registry.classify(&entry.path, entry.structural_signals)
            };

            if classification.category == crate::scanner::patterns::ArtifactCategory::Unknown {
                continue;
            }

            let input = CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.content_size_bytes,
                age: Duration::from_hours(48),
                classification,
                signals: entry.structural_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: is_path_open_by_ancestor(&entry.path, open_ancestors),
                excluded: false,
            };
            let score = scoring.score_candidate(&input, 0.9);
            if score.vetoed {
                hard_veto_paths.insert(
                    entry.path.clone(),
                    score
                        .veto_reason
                        .unwrap_or_else(|| "vetoed".into())
                        .into_owned(),
                );
            } else if score.decision.action == DecisionAction::Delete {
                delete_candidate_bytes =
                    delete_candidate_bytes.saturating_add(entry.metadata.content_size_bytes);
                delete_paths.insert(entry.path.clone());
            }
        }

        ScannerValidationReport {
            entries_visited: entries.len(),
            opaque_pruned_dirs,
            delete_paths,
            hard_veto_paths,
            delete_candidate_bytes,
            elapsed,
            process_cpu_micros,
        }
    }

    #[test]
    fn scanner_v2_validation_prunes_synthetic_cargo_tree_by_more_than_50x() {
        let tmp = TempDir::new().unwrap();
        let target_dir = synthetic_large_cargo_tree(tmp.path(), 120);

        let v1_entries = walk_fixture(tmp.path(), false);
        let v2_entries = walk_fixture(tmp.path(), true);

        let v1_effort = v1_entries.len();
        let v2_effort = v2_entries.len().max(1);
        let effort_ratio = v1_effort / v2_effort;

        assert!(
            v1_effort >= 300,
            "fixture should force v1 to descend a large synthetic target tree; v1_entries={v1_effort}"
        );
        assert!(
            effort_ratio >= 50,
            "v2 should reduce deterministic walk effort by >=50x; v1_entries={v1_effort} v2_entries={} ratio={effort_ratio}",
            v2_entries.len()
        );

        let target_entries = v2_entries
            .iter()
            .filter(|entry| entry.path == target_dir)
            .collect::<Vec<_>>();
        assert_eq!(
            target_entries.len(),
            1,
            "v2 should emit the target root as one opaque candidate"
        );
        assert_eq!(
            target_entries[0]
                .opaque_tree
                .as_ref()
                .map(|opaque| opaque.disposition),
            Some(OpaqueTreeDisposition::CandidateOpaque)
        );
        assert!(
            !v2_entries
                .iter()
                .any(|entry| entry.path.starts_with(target_dir.join("debug"))),
            "v2 must not descend into the opaque target tree"
        );
    }

    #[test]
    fn scanner_v2_validation_ab_report_records_effort_and_shadow_parity() {
        let tmp = TempDir::new().unwrap();
        let target_dir = synthetic_large_cargo_tree(tmp.path(), 160);
        let open_ancestors = HashSet::new();

        let v1 = scanner_validation_report(tmp.path(), false, &open_ancestors);
        let v2 = scanner_validation_report(tmp.path(), true, &open_ancestors);

        assert!(
            v1.entries_visited >= 400,
            "fixture should force substantial v1 traversal; v1={v1:?}"
        );
        assert_eq!(
            v2.opaque_pruned_dirs, 1,
            "v2 should record the target root as the single opaque-pruned directory"
        );
        assert!(
            v2.deterministic_effort_ratio_against(&v1) >= 50,
            "v2 deterministic effort must be >=50x lower; v1={v1:?} v2={v2:?}"
        );
        assert!(v1.elapsed_wall_seconds().is_finite());
        assert!(v2.elapsed_wall_seconds().is_finite());
        assert!(
            v2.delete_paths.contains(&target_dir),
            "v2 should retain the same target-root deletion candidate"
        );
        assert!(
            v2.delete_paths.is_subset(&v1.delete_paths),
            "v2 shadow candidates must be a subset of v1-approved candidates; v1={v1:?} v2={v2:?}"
        );
    }

    #[test]
    fn scanner_v2_validation_artifact_is_machine_readable() {
        let tmp = TempDir::new().unwrap();
        let target_dir = synthetic_large_cargo_tree(tmp.path(), 160);
        let open_ancestors = HashSet::new();

        let v1 = scanner_validation_report(tmp.path(), false, &open_ancestors);
        let v2 = scanner_validation_report(tmp.path(), true, &open_ancestors);
        let artifact = scanner_validation_artifact("synthetic-cargo-tree", &v1, &v2);
        let payload = serde_json::to_value(&artifact).unwrap();

        assert_eq!(payload["schema_version"].as_u64(), Some(1));
        assert_eq!(payload["scenario"].as_str(), Some("synthetic-cargo-tree"));
        assert_eq!(
            payload["v1"]["dispatch"].as_str(),
            Some("v1_directory_walker")
        );
        assert_eq!(
            payload["v2"]["dispatch"].as_str(),
            Some("v2_opaque_pruning_walker")
        );
        assert!(
            artifact.deterministic_effort_ratio >= 50,
            "validation artifact must preserve the >=50x deterministic effort proof: {artifact:?}"
        );
        assert!(artifact.v2_delete_subset_of_v1);
        assert!(artifact.v2_approves_v1_hard_vetoes.is_empty());
        assert!(
            artifact.v2.delete_candidate_bytes > 0,
            "opaque root should retain reclaimable candidate bytes for {}",
            target_dir.display()
        );
        eprintln!(
            "scanner_v2_validation_artifact={}",
            serde_json::to_string(&artifact).unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scanner_v2_validation_deep_open_file_vetoes_opaque_candidate() {
        let tmp = TempDir::new().unwrap();
        let target_dir = synthetic_large_cargo_tree(tmp.path(), 4);
        let open_file = target_dir
            .join("debug")
            .join("deps")
            .join("crate_000")
            .join("src")
            .join("lib.rs");
        let open_handle = fs::File::open(&open_file).unwrap();

        let entries = walk_fixture(tmp.path(), true);
        let target_entry = entries
            .iter()
            .find(|entry| entry.path == target_dir)
            .expect("v2 should emit opaque target candidate");

        let (open_ancestors, complete) = collect_open_path_ancestors(&[tmp.path().to_path_buf()]);

        // Containers or hidepid settings can hide even our own fd. Keep the
        // fixture non-flaky there; normal Linux workers exercise the assertion.
        if !open_ancestors.contains(&open_file) {
            drop(open_handle);
            return;
        }

        assert!(complete, "open-file ancestor scan should complete");
        assert!(
            is_path_open_by_ancestor(&target_dir, &open_ancestors),
            "an open descendant must mark the opaque candidate root busy"
        );

        let classification = target_entry
            .opaque_tree
            .as_ref()
            .expect("target should have opaque classification")
            .classification
            .clone();
        let input = CandidateInput {
            path: target_dir,
            size_bytes: target_entry.metadata.content_size_bytes,
            age: Duration::from_hours(48),
            classification,
            signals: StructuralSignals::default(),
            active_references: ActiveReferenceSummary::default(),
            is_open: true,
            excluded: false,
        };
        let score =
            ScoringEngine::from_config(&ScoringConfig::default(), 0).score_candidate(&input, 0.9);

        assert!(score.vetoed, "deep open-file evidence must hard-veto v2");
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("currently open by another process")
        );
        drop(open_handle);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scanner_v2_validation_ab_shadow_never_approves_v1_open_file_veto() {
        let tmp = TempDir::new().unwrap();
        let target_dir = synthetic_large_cargo_tree(tmp.path(), 16);
        let open_file = target_dir
            .join("debug")
            .join("deps")
            .join("crate_000")
            .join("src")
            .join("lib.rs");
        let open_handle = fs::File::open(&open_file).unwrap();
        let (open_ancestors, complete) = collect_open_path_ancestors(&[tmp.path().to_path_buf()]);

        if !open_ancestors.contains(&open_file) {
            drop(open_handle);
            return;
        }

        assert!(complete, "open-file ancestor scan should complete");
        let v1 = scanner_validation_report(tmp.path(), false, &open_ancestors);
        let v2 = scanner_validation_report(tmp.path(), true, &open_ancestors);

        assert!(
            v1.hard_veto_paths.contains_key(&target_dir),
            "v1 should hard-veto the target root while a descendant file is open; v1={v1:?}"
        );
        assert!(
            v2.hard_veto_paths.contains_key(&target_dir),
            "v2 should hard-veto the opaque target root while a descendant file is open; v2={v2:?}"
        );
        for candidate in &v2.delete_paths {
            assert!(
                !v1.hard_veto_paths.contains_key(candidate),
                "v2 approved a path that v1 hard-vetoed: {} v1={v1:?} v2={v2:?}",
                candidate.display()
            );
        }
        drop(open_handle);
    }

    #[test]
    fn opaque_pruning_protects_git_without_emitting_candidate() {
        let tmp = TempDir::new().unwrap();
        let project = tmp.path().join("project");
        let git_dir = project.join(".git");
        fs::create_dir_all(git_dir.join("objects")).unwrap();

        let mut config = test_config(tmp.path());
        config.opaque_pruning = true;
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let project_entry = entries.iter().find(|entry| entry.path == project).unwrap();
        assert!(project_entry.structural_signals.has_git);
        assert!(!entries.iter().any(|entry| entry.path.starts_with(&git_dir)));
    }

    #[test]
    fn opaque_signal_only_dependency_dir_is_not_marked_candidate() {
        let tmp = TempDir::new().unwrap();
        let vendor_dir = tmp.path().join("project").join("vendor");
        fs::create_dir_all(vendor_dir.join("nested")).unwrap();

        let mut config = test_config(tmp.path());
        config.opaque_pruning = true;
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let vendor_entry = entries
            .iter()
            .find(|entry| entry.path == vendor_dir)
            .unwrap();
        assert_eq!(
            vendor_entry
                .opaque_tree
                .as_ref()
                .map(|opaque| opaque.disposition),
            Some(OpaqueTreeDisposition::SignalOnly)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.path == vendor_dir.join("nested")),
            "signal-only dependency dirs should keep normal traversal"
        );
    }

    #[test]
    fn detects_git_structural_signal() {
        let tmp = TempDir::new().unwrap();
        let project = tmp.path().join("myproject");
        fs::create_dir_all(project.join(".git")).unwrap();
        fs::create_dir_all(project.join("src")).unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let proj_entry = entries.iter().find(|e| e.path == project).unwrap();
        assert!(proj_entry.structural_signals.has_git);
    }

    #[test]
    fn does_not_follow_symlinks() {
        let tmp = TempDir::new().unwrap();
        let real_dir = tmp.path().join("real");
        let link_dir = tmp.path().join("link");
        fs::create_dir_all(real_dir.join("nested")).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        // "real" and "real/nested" should be found, but "link" should not.
        assert!(paths.contains(&real_dir));
        assert!(!paths.contains(&link_dir));
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinks_when_enabled() {
        let tmp = TempDir::new().unwrap();
        let real_dir = tmp.path().join("real");
        let link_dir = tmp.path().join("link");
        fs::create_dir_all(real_dir.join("nested")).unwrap();
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let mut config = test_config(tmp.path());
        config.follow_symlinks = true;
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(paths.contains(&real_dir));
        assert!(paths.contains(&link_dir));
        assert!(paths.contains(&link_dir.join("nested")));
    }

    #[test]
    fn handles_empty_directory() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("empty")).unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let empty_dir = tmp.path().join("empty");
        assert!(entries.iter().map(|e| &e.path).any(|p| p == &empty_dir));
    }

    #[test]
    fn nonexistent_root_is_skipped() {
        let config = WalkerConfig {
            root_paths: vec![PathBuf::from("/definitely/does/not/exist")],
            max_depth: 5,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 1,
            excluded_paths: HashSet::new(),
            opaque_pruning: false,
        };
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn walk_completes_when_workers_enqueue_many_child_directories() {
        use std::sync::atomic::Ordering;
        use std::thread;
        use std::time::Duration;

        let tmp = TempDir::new().unwrap();
        let parent_count = 8;
        let children_per_parent = 1024;

        for parent_index in 0..parent_count {
            let parent = tmp.path().join(format!("parent-{parent_index}"));
            fs::create_dir(&parent).unwrap();
            for child_index in 0..children_per_parent {
                fs::create_dir(parent.join(format!("child-{child_index}"))).unwrap();
            }
        }

        let mut config = test_config(tmp.path());
        config.max_depth = 2;
        config.parallelism = parent_count;
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let cancel = walker.cancel_token();
        let (done_tx, done_rx) = channel::bounded(1);

        let join = thread::spawn(move || {
            let result = walker.walk().map(|entries| entries.len());
            let _ = done_tx.send(result);
        });

        let entries_len = match done_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(result) => result.unwrap(),
            Err(err) => {
                cancel.store(true, Ordering::Relaxed);
                join.join().unwrap();
                panic!("walker did not finish under heavy child-directory fanout: {err}");
            }
        };
        join.join().unwrap();

        let expected_dirs = parent_count + (parent_count * children_per_parent);
        assert!(
            entries_len >= expected_dirs,
            "walker should visit all generated directories"
        );
    }

    #[test]
    fn process_directory_exits_when_result_channel_is_backpressured_and_cancelled() {
        use crossbeam_channel as channel;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::thread;
        use std::time::{Duration, Instant};

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("artifacts");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("file.bin"), b"payload").unwrap();

        let (work_tx, work_rx) = channel::bounded::<WorkItem>(1);
        let (result_tx, result_rx) = channel::bounded::<WalkEntry>(1);
        drop(work_rx);

        // Fill the result channel so the directory emitter must wait.
        result_tx
            .send(WalkEntry {
                path: tmp.path().join("placeholder"),
                metadata: EntryMetadata {
                    size_bytes: 0,
                    content_size_bytes: 0,
                    modified: SystemTime::UNIX_EPOCH,
                    created: None,
                    is_dir: true,
                    inode: 0,
                    device_id: 0,
                    kind: FsEntryKind::Directory,
                    permissions: 0,
                },
                depth: 1,
                structural_signals: StructuralSignals::default(),
                is_open: false,
                opaque_tree: None,
            })
            .unwrap();

        let in_flight = AtomicUsize::new(0);
        let protection = parking_lot::RwLock::new(ProtectionRegistry::marker_only());
        let config = WalkerConfig {
            root_paths: vec![tmp.path().to_path_buf()],
            max_depth: 4,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 1,
            excluded_paths: HashSet::new(),
            opaque_pruning: false,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);

        let dir_clone = dir;
        let start = Instant::now();
        let join = thread::spawn(move || {
            process_directory(
                &dir_clone,
                1,
                0,
                None,
                &work_tx,
                &result_tx,
                &in_flight,
                &config,
                &protection,
                None,
                &worker_cancel,
            );
        });

        thread::sleep(Duration::from_millis(150));
        cancel.store(true, Ordering::Relaxed);
        join.join().unwrap();

        assert!(
            start.elapsed() < Duration::from_secs(2),
            "process_directory should stop promptly when cancellation is requested",
        );
        assert_eq!(result_rx.len(), 1, "no extra entries should be emitted");
    }

    #[test]
    fn signals_from_children_detects_rust_markers() {
        let names = vec![
            "incremental".to_string(),
            "deps".to_string(),
            ".fingerprint".to_string(),
            "build".to_string(),
            "debug".to_string(),
            "release".to_string(),
        ];
        let signals = signals_from_children(&names);
        assert!(signals.has_incremental);
        assert!(signals.has_deps);
        assert!(signals.has_fingerprint);
        assert!(signals.has_build);
        assert!(!signals.has_git);
        assert!(!signals.has_cargo_toml);
    }

    #[test]
    fn signals_detects_mostly_object_files() {
        let names = vec![
            "foo.o".to_string(),
            "bar.rlib".to_string(),
            "baz.rmeta".to_string(),
            "deps.d".to_string(),
        ];
        let signals = signals_from_children(&names);
        assert!(signals.mostly_object_files);
    }

    #[test]
    fn is_path_open_works() {
        use std::os::unix::fs::MetadataExt;

        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("target").join("debug");
        fs::create_dir_all(&sub).unwrap();
        let file = sub.join("libfoo.rlib");
        fs::write(&file, b"data").unwrap();

        let meta = fs::metadata(&file).unwrap();
        let mut open = HashSet::new();
        open.insert((meta.dev(), meta.ino()));

        assert!(is_path_open(tmp.path().join("target").as_path(), &open));
        // A different path with no matching inodes should return false.
        let other = tmp.path().join("other");
        fs::create_dir_all(&other).unwrap();
        assert!(!is_path_open(&other, &open));
    }

    #[test]
    fn is_path_open_handles_relative_candidate_paths() {
        use std::os::unix::fs::MetadataExt;

        let cwd = std::env::current_dir().unwrap();
        let tmp = tempfile::Builder::new()
            .prefix("walker-open-relative-")
            .tempdir_in(&cwd)
            .unwrap();

        let child = tmp.path().join("debug");
        fs::create_dir_all(&child).unwrap();
        let file = child.join("libfoo.rlib");
        fs::write(&file, b"data").unwrap();

        let meta = fs::metadata(&file).unwrap();
        let mut open = HashSet::new();
        open.insert((meta.dev(), meta.ino()));

        let rel = tmp.path().strip_prefix(&cwd).unwrap();
        assert!(is_path_open(rel, &open));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_ancestor_check_does_not_mark_sibling_subtree_open() {
        let tmp = TempDir::new().unwrap();
        let open_dir = tmp.path().join("open");
        let sibling_dir = tmp.path().join("sibling");
        fs::create_dir_all(&open_dir).unwrap();
        fs::create_dir_all(&sibling_dir).unwrap();

        let file = open_dir.join("in_use.bin");
        fs::write(&file, b"data").unwrap();
        let handle = fs::File::open(&file).unwrap();

        let (open_ancestors, _) = collect_open_path_ancestors(&[tmp.path().to_path_buf()]);

        // Guard: skip if /proc doesn't expose our own FDs (hidepid=2, containers).
        if !open_ancestors.contains(&file) {
            drop(handle);
            return;
        }

        assert!(is_path_open_by_ancestor(&open_dir, &open_ancestors));
        assert!(!is_path_open_by_ancestor(&sibling_dir, &open_ancestors));
        drop(handle);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_ancestor_check_handles_nested_roots_with_child_first() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("parent");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();

        let file = child.join("in_use.bin");
        fs::write(&file, b"data").unwrap();
        let handle = fs::File::open(&file).unwrap();

        // Child first exercises nested-root ordering.
        let (open_ancestors, _) = collect_open_path_ancestors(&[child.clone(), parent.clone()]);

        // Guard: skip if /proc doesn't expose our own FDs (hidepid=2, containers).
        if !open_ancestors.contains(&file) {
            drop(handle);
            return;
        }

        assert!(is_path_open_by_ancestor(&child, &open_ancestors));
        assert!(is_path_open_by_ancestor(&parent, &open_ancestors));
        drop(handle);
    }

    #[test]
    fn protection_registry_updated_during_walk() {
        let tmp = TempDir::new().unwrap();
        let protected = tmp.path().join("protected_project");
        fs::create_dir_all(protected.join("subdir")).unwrap();
        protection::create_marker(&protected, None).unwrap();

        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        walker.walk().unwrap();

        // Protection registry should have the discovered marker.
        let prot = walker.protection().read();
        assert!(prot.is_protected(&protected));
        assert!(prot.is_protected(&protected.join("subdir")));
        drop(prot);
    }

    #[test]
    fn config_pattern_protection_skips_matching_dirs() {
        let tmp = TempDir::new().unwrap();
        let prod = tmp.path().join("production-app");
        let staging = tmp.path().join("staging-app");
        fs::create_dir_all(prod.join("target")).unwrap();
        fs::create_dir_all(staging.join("target")).unwrap();

        let mut config = test_config(tmp.path());
        config.excluded_paths.clear();

        let pattern = format!("{}/**/production-*", tmp.path().display());
        let protection = ProtectionRegistry::new(Some(&[pattern])).unwrap();
        let walker = DirectoryWalker::new(config, protection);
        let entries = walker.walk().unwrap();

        let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        // Staging should be found.
        assert!(paths.contains(&staging));
        // Production should be skipped by config pattern.
        assert!(!paths.iter().any(|p| p.starts_with(&prod)));
    }

    #[cfg(unix)]
    #[test]
    fn signals_detects_symlinked_markers() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let project = tmp.path().join("symlinked_signal_project");
        fs::create_dir(&project).unwrap();

        // Create a real file elsewhere
        let real_git = tmp.path().join("real_git");
        fs::write(&real_git, "gitdir: ...").unwrap();

        // Symlink .git -> real_git
        symlink(&real_git, project.join(".git")).unwrap();

        // Config with follow_symlinks = false
        let config = test_config(tmp.path());
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();

        let proj_entry = entries.iter().find(|e| e.path == project).unwrap();
        assert!(
            proj_entry.structural_signals.has_git,
            "should detect symlinked .git"
        );
    }
}
