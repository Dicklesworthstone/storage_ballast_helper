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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

use crossbeam_channel as channel;

use crate::core::errors::{Result, SbhError};
use crate::scanner::patterns::StructuralSignals;
use crate::scanner::protection::{self, ProtectionRegistry};

/// Walker configuration derived from `ScannerConfig`.
#[derive(Debug, Clone)]
pub struct WalkerConfig {
    pub root_paths: Vec<PathBuf>,
    pub max_depth: usize,
    pub follow_symlinks: bool,
    pub cross_devices: bool,
    pub parallelism: usize,
    pub excluded_paths: HashSet<PathBuf>,
}

/// Metadata collected for each filesystem entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadata {
    pub size_bytes: u64,
    pub modified: SystemTime,
    pub created: Option<SystemTime>,
    pub is_dir: bool,
    pub inode: u64,
    pub device_id: u64,
    pub permissions: u32,
}

/// A single entry discovered during a walk.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    pub path: PathBuf,
    pub metadata: EntryMetadata,
    pub depth: usize,
    pub structural_signals: StructuralSignals,
    pub is_open: bool,
}

/// Item in the internal work queue: (directory_path, depth, root_device_id).
type WorkItem = (PathBuf, usize, u64);

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
}

impl DirectoryWalker {
    pub fn new(config: WalkerConfig, protection: ProtectionRegistry) -> Self {
        Self {
            config,
            protection: Arc::new(parking_lot::RwLock::new(protection)),
            heartbeat: None,
        }
    }

    /// Set a heartbeat callback to be called periodically by worker threads.
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
        let parallelism = self.config.parallelism.max(1);

        // Channels: work items (bounded) and results (unbounded for throughput).
        let (work_tx, work_rx) = channel::bounded::<WorkItem>(1024);
        let (result_tx, result_rx) = channel::unbounded::<WalkEntry>();

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
            let _ = work_tx.send((root.clone(), 0, dev));
        }

        // Clone sender for workers; drop original so channel closes when workers finish.
        let workers: Vec<_> = (0..parallelism)
            .map(|_| {
                let work_rx = work_rx.clone();
                let work_tx = work_tx.clone();
                let result_tx = result_tx.clone();
                let in_flight = Arc::clone(&in_flight);
                let config = self.config.clone();
                let protection = Arc::clone(&self.protection);
                let heartbeat = self.heartbeat.clone();

                thread::spawn(move || {
                    walker_thread(
                        &work_rx,
                        &work_tx,
                        &result_tx,
                        &in_flight,
                        &config,
                        &protection,
                        &heartbeat,
                    );
                })
            })
            .collect();

        // Drop our copies of the senders.
        drop(work_tx);
        drop(result_tx);

        // Collect results.
        let entries: Vec<WalkEntry> = result_rx.iter().collect();

        // Wait for all workers to finish.
        for handle in workers {
            let _ = handle.join();
        }

        Ok(entries)
    }

    /// Access the protection registry (e.g. to list discovered markers).
    pub fn protection(&self) -> &parking_lot::RwLock<ProtectionRegistry> {
        &self.protection
    }
}

/// Worker thread function: pulls directories from work channel, processes them,
/// sends results and new subdirectories back.
fn walker_thread(
    work_rx: &channel::Receiver<WorkItem>,
    work_tx: &channel::Sender<WorkItem>,
    result_tx: &channel::Sender<WalkEntry>,
    in_flight: &AtomicUsize,
    config: &WalkerConfig,
    protection: &parking_lot::RwLock<ProtectionRegistry>,
    heartbeat: &Option<Arc<dyn Fn() + Send + Sync>>,
) {
    loop {
        // Beat the heart if configured.
        if let Some(hb) = heartbeat {
            hb();
        }

        match work_rx.recv_timeout(Duration::from_millis(50)) {
            Ok((dir_path, depth, root_dev)) => {
                process_directory(
                    &dir_path, depth, root_dev, work_tx, result_tx, in_flight, config, protection,
                );
                // Mark this work item as completed.
                let remaining = in_flight.fetch_sub(1, Ordering::AcqRel);
                if remaining == 1 {
                    // We were the last in-flight item. Signal termination by
                    // dropping our sender (happens when thread exits).
                }
            }
            Err(channel::RecvTimeoutError::Timeout) => {
                if in_flight.load(Ordering::Acquire) == 0 {
                    return;
                }
            }
            Err(channel::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Process one directory: read entries, emit WalkEntry results, enqueue subdirectories.
#[allow(clippy::too_many_arguments)]
fn process_directory(
    dir_path: &Path,
    depth: usize,
    root_dev: u64,
    work_tx: &channel::Sender<WorkItem>,
    result_tx: &channel::Sender<WalkEntry>,
    in_flight: &AtomicUsize,
    config: &WalkerConfig,
    protection: &parking_lot::RwLock<ProtectionRegistry>,
) {
    // Check for .sbh-protect marker before reading directory.
    let marker_path = dir_path.join(protection::MARKER_FILENAME);
    if fs::symlink_metadata(&marker_path).is_ok() {
        protection.write().register_marker(dir_path);
        return; // Skip entire protected subtree.
    }

    // Check exclusion list.
    if config.excluded_paths.contains(dir_path) {
        return;
    }

    // Check protection registry (covers config patterns and previously discovered markers).
    if protection.read().is_protected(dir_path) {
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

    for entry_result in entries {
        let Ok(entry) = entry_result else {
            continue;
        };

        let child_path = entry.path();

        let Ok(meta) = metadata_for_path(&child_path, config.follow_symlinks) else {
            continue;
        };

        // Skip symlinks entirely unless following symlinks is explicitly enabled.
        if !config.follow_symlinks && meta.file_type().is_symlink() {
            continue;
        }

        // ─── Incremental Signal Collection ───
        if let Some(name_os) = child_path.file_name() {
            let name = name_os.to_string_lossy();
            total_count += 1;

            match name.as_ref() {
                "incremental" => signals.has_incremental = true,
                "deps" => signals.has_deps = true,
                "build" => signals.has_build = true,
                ".fingerprint" => signals.has_fingerprint = true,
                ".git" => signals.has_git = true,
                "cargo.toml" | "Cargo.toml" => signals.has_cargo_toml = true,
                _ => {}
            }

            // Check extension for object file heuristics via byte suffix.
            let name_bytes = name_os.as_encoded_bytes();
            if name_bytes.ends_with(b".o")
                || name_bytes.ends_with(b".rlib")
                || name_bytes.ends_with(b".rmeta")
                || name_bytes.ends_with(b".d")
            {
                object_count += 1;
            }
        }

        // ─── Recursion Dispatch ───
        // Only recurse if it's a directory and within depth limits.
        if depth < config.max_depth && meta.is_dir() {
            let child_dev = device_id(&meta);

            // Cross-device guard: don't cross filesystem boundaries.
            if !config.cross_devices && child_dev != root_dev {
                continue;
            }

            // Don't re-enter excluded paths.
            if config.excluded_paths.contains(&child_path) {
                continue;
            }

            in_flight.fetch_add(1, Ordering::Release);
            if work_tx.send((child_path, depth + 1, root_dev)).is_err() {
                in_flight.fetch_sub(1, Ordering::Release);
            }
        }
    }

    // Finalize structural signals.
    if total_count > 0 && object_count > 0 {
        signals.mostly_object_files = object_count * 2 >= total_count;
    }

    // Emit a WalkEntry for this directory itself.
    if depth > 0
        && let Ok(dir_meta) = metadata_for_path(dir_path, config.follow_symlinks)
    {
        let _ = result_tx.send(WalkEntry {
            path: dir_path.to_path_buf(),
            metadata: entry_metadata(&dir_meta),
            depth,
            structural_signals: signals,
            is_open: false, // Caller sets this after walk using /proc scan.
        });
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

/// Extract `EntryMetadata` from `fs::Metadata` (Unix-specific fields via MetadataExt).
fn entry_metadata(meta: &fs::Metadata) -> EntryMetadata {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        EntryMetadata {
            size_bytes: meta.len(),
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            created: meta.created().ok(),
            is_dir: meta.is_dir(),
            inode: meta.ino(),
            device_id: meta.dev(),
            permissions: meta.mode(),
        }
    }
    #[cfg(not(unix))]
    {
        EntryMetadata {
            size_bytes: meta.len(),
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            created: meta.created().ok(),
            is_dir: meta.is_dir(),
            inode: 0,
            device_id: 0,
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

    let mut open = HashSet::with_capacity(4096);

    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return open;
    };

    for proc_entry in proc_dir.flatten() {
        let pid_name = proc_entry.file_name();
        let pid_bytes = pid_name.as_bytes();

        // Only numeric directories (PIDs).
        if pid_bytes.is_empty() || !pid_bytes.iter().all(|byte| byte.is_ascii_digit()) {
            continue;
        }

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

/// Memoized open-file detector for repeated path checks during one scan pass.
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
        #[cfg(target_os = "linux")]
        {
            self.is_path_open_linux(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn is_path_open_linux(&mut self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;

        if let Some(cached) = self.dir_cache.get(path).copied() {
            return cached;
        }

        const MAX_SCAN: usize = 20_000;
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

            let Ok(meta) = fs::metadata(&p) else {
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
    use std::fs;
    use tempfile::TempDir;

    fn test_config(root: &Path) -> WalkerConfig {
        WalkerConfig {
            root_paths: vec![root.to_path_buf()],
            max_depth: 10,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 2,
            excluded_paths: HashSet::new(),
        }
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
        };
        let walker = DirectoryWalker::new(config, ProtectionRegistry::marker_only());
        let entries = walker.walk().unwrap();
        assert!(entries.is_empty());
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
}
