//! Incremental Merkle scan index with full-scan fallback.
//!
//! Builds a hash tree over directory metadata so repeated daemon cycles can
//! detect unchanged subtrees without a full recursive walk.  Any integrity
//! failure forces an immediate full-scan fallback and marks the index as
//! unhealthy until rebuilt.

#![allow(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, BufWriter, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::errors::{Result, SbhError};
use crate::scanner::walker::WalkEntry;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// 32-byte SHA-256 hash used throughout the Merkle tree.
pub type MerkleHash = [u8; 32];

/// Zero hash constant for empty/missing nodes.
const ZERO_HASH: MerkleHash = [0u8; 32];

/// Overall health of the scan index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexHealth {
    /// Index is valid and usable for incremental scans.
    Healthy,
    /// Index has partial corruption; usable for some subtrees.
    Degraded,
    /// Index is corrupt or missing; full scan required.
    Corrupt,
    /// Index has not been built yet.
    Uninitialized,
}

/// Metadata snapshot for a single directory entry used for change detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySnapshot {
    pub path: PathBuf,
    pub size_bytes: u64,
    /// Modification time as nanoseconds since epoch.
    pub modified_nanos: u128,
    pub inode: u64,
    pub device_id: u64,
    pub is_dir: bool,
}

impl EntrySnapshot {
    /// Create a snapshot from a `WalkEntry`.
    pub fn from_walk_entry(entry: &WalkEntry) -> Self {
        let modified_nanos = entry
            .metadata
            .modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        Self {
            path: entry.path.clone(),
            size_bytes: entry.metadata.size_bytes,
            modified_nanos,
            inode: entry.metadata.inode,
            device_id: entry.metadata.device_id,
            is_dir: entry.metadata.is_dir,
        }
    }

    /// Compute the metadata hash for this entry.
    pub fn metadata_hash(&self) -> MerkleHash {
        let mut hasher = Sha256::new();
        hasher.update(self.path.to_string_lossy().as_bytes());
        hasher.update(self.size_bytes.to_le_bytes());
        hasher.update(self.modified_nanos.to_le_bytes());
        hasher.update(self.inode.to_le_bytes());
        hasher.update(self.device_id.to_le_bytes());
        hasher.update([u8::from(self.is_dir)]);
        hasher.finalize().into()
    }
}

/// A node in the Merkle tree representing one scanned directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Hash of this directory's own metadata.
    pub metadata_hash: MerkleHash,
    /// Combined hash of metadata_hash + sorted child subtree hashes.
    pub subtree_hash: MerkleHash,
    /// Depth in the walk tree.
    pub depth: usize,
    /// Ordered child directory paths (for deterministic re-hashing).
    pub children: Vec<PathBuf>,
}

/// Budget constraints for incremental scan operations.
#[derive(Debug, Clone)]
pub struct ScanBudget {
    /// Maximum number of subtree hash recomputations per cycle.
    pub max_subtree_updates: usize,
    /// Maximum checkpoint write size in bytes (0 = unlimited).
    pub max_checkpoint_bytes: usize,
    /// Count of updates performed so far in this cycle.
    updates_used: usize,
}

impl ScanBudget {
    pub fn new(max_subtree_updates: usize, max_checkpoint_bytes: usize) -> Self {
        Self {
            max_subtree_updates,
            max_checkpoint_bytes,
            updates_used: 0,
        }
    }

    /// Check if budget allows another update. Returns false if exhausted.
    pub fn try_consume(&mut self) -> bool {
        if self.updates_used >= self.max_subtree_updates {
            return false;
        }
        self.updates_used += 1;
        true
    }

    /// How many updates remain.
    pub fn remaining(&self) -> usize {
        self.max_subtree_updates.saturating_sub(self.updates_used)
    }

    /// Whether the budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.updates_used >= self.max_subtree_updates
    }
}

/// Result of an incremental scan comparison.
#[derive(Debug)]
pub struct IncrementalDiff {
    /// Paths whose subtree hash changed (need re-scanning and re-scoring).
    pub changed_paths: Vec<PathBuf>,
    /// Paths that were unchanged (can skip scoring).
    pub unchanged_count: usize,
    /// Paths that are new (not in the previous index).
    pub new_paths: Vec<PathBuf>,
    /// Paths that were removed (in old index but not in new scan).
    pub removed_paths: Vec<PathBuf>,
    /// Whether budget was exhausted (some paths deferred to full scan).
    pub budget_exhausted: bool,
    /// Paths deferred due to budget exhaustion.
    pub deferred_paths: Vec<PathBuf>,
    /// Health assessment after the diff.
    pub health: IndexHealth,
}

/// Persistent checkpoint format for the Merkle index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexCheckpoint {
    /// Format version for forward compatibility.
    pub version: u32,
    /// Timestamp of last successful full build.
    pub built_at_nanos: u128,
    /// SHA-256 of the serialized nodes map (integrity check).
    pub integrity_hash: MerkleHash,
    /// The actual Merkle tree data.
    pub nodes: BTreeMap<PathBuf, MerkleNode>,
    /// Snapshot metadata for each entry (for diffing).
    pub snapshots: BTreeMap<PathBuf, EntrySnapshot>,
    /// Root paths that were scanned.
    pub root_paths: Vec<PathBuf>,
    /// Health at time of checkpoint.
    pub health: IndexHealth,
}

const CHECKPOINT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// MerkleScanIndex
// ---------------------------------------------------------------------------

/// The main incremental scan index.
///
/// Builds a Merkle tree from walk entries so that subsequent scans can detect
/// changed subtrees by comparing subtree hashes. On any integrity failure,
/// falls back to full scan mode.
#[derive(Debug)]
pub struct MerkleScanIndex {
    /// Path → Merkle node mapping.
    nodes: BTreeMap<PathBuf, MerkleNode>,
    /// Path → entry snapshot for metadata comparison.
    snapshots: BTreeMap<PathBuf, EntrySnapshot>,
    /// Root paths being tracked.
    root_paths: Vec<PathBuf>,
    /// Current health status.
    health: IndexHealth,
    /// When the index was last fully built.
    built_at: SystemTime,
}

impl MerkleScanIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            root_paths: Vec::new(),
            health: IndexHealth::Uninitialized,
            built_at: UNIX_EPOCH,
        }
    }

    /// Build a complete index from a set of walk entries.
    ///
    /// This is the "full scan" path: processes all entries, builds the complete
    /// Merkle tree from scratch.
    pub fn build_from_entries(&mut self, entries: &[WalkEntry], root_paths: &[PathBuf]) {
        self.nodes.clear();
        self.snapshots.clear();
        self.root_paths = root_paths.to_vec();
        self.built_at = SystemTime::now();

        // Build snapshots for all entries.
        for entry in entries {
            let snapshot = EntrySnapshot::from_walk_entry(entry);
            self.snapshots.insert(entry.path.clone(), snapshot);
        }

        // Build parent→children mapping from paths.
        let mut children_map: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
        for entry in entries {
            if let Some(parent) = entry.path.parent() {
                children_map
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(entry.path.clone());
            }
        }

        // Sort children for deterministic hashing.
        for children in children_map.values_mut() {
            children.sort();
        }

        // Build Merkle nodes bottom-up (BTreeMap iteration is sorted, but we
        // need reverse depth order). Collect entries with their depths first.
        let mut entries_by_depth: Vec<(&PathBuf, usize)> =
            entries.iter().map(|e| (&e.path, e.depth)).collect();
        // Process deepest first so children are hashed before parents.
        entries_by_depth.sort_by(|a, b| b.1.cmp(&a.1));

        for (path, depth) in entries_by_depth {
            let metadata_hash = self
                .snapshots
                .get(path)
                .map_or(ZERO_HASH, EntrySnapshot::metadata_hash);

            let children = children_map.get(path).cloned().unwrap_or_default();

            let subtree_hash = compute_subtree_hash(metadata_hash, &children, &self.nodes);

            self.nodes.insert(
                path.clone(),
                MerkleNode {
                    metadata_hash,
                    subtree_hash,
                    depth,
                    children,
                },
            );
        }

        self.health = IndexHealth::Healthy;
    }

    /// Compare this index against fresh walk entries to find changed subtrees.
    ///
    /// Returns an `IncrementalDiff` describing what changed. If budget is
    /// exhausted, some paths are deferred to full scan.
    pub fn diff(
        &mut self,
        fresh_entries: &[WalkEntry],
        budget: &mut ScanBudget,
    ) -> IncrementalDiff {
        if self.health == IndexHealth::Corrupt || self.health == IndexHealth::Uninitialized {
            return IncrementalDiff {
                changed_paths: fresh_entries.iter().map(|e| e.path.clone()).collect(),
                unchanged_count: 0,
                new_paths: Vec::new(),
                removed_paths: Vec::new(),
                budget_exhausted: false,
                deferred_paths: Vec::new(),
                health: self.health,
            };
        }

        let mut changed = Vec::new();
        let mut new_paths = Vec::new();
        let mut unchanged_count: usize = 0;
        let mut deferred = Vec::new();
        let mut budget_exhausted = false;

        // Build fresh snapshots for comparison.
        let fresh_snapshots: BTreeMap<PathBuf, EntrySnapshot> = fresh_entries
            .iter()
            .map(|e| (e.path.clone(), EntrySnapshot::from_walk_entry(e)))
            .collect();

        for (path, fresh_snap) in &fresh_snapshots {
            match self.snapshots.get(path) {
                None => {
                    // New path not in previous index.
                    if budget.try_consume() {
                        new_paths.push(path.clone());
                    } else {
                        budget_exhausted = true;
                        deferred.push(path.clone());
                    }
                }
                Some(old_snap) => {
                    let old_hash = old_snap.metadata_hash();
                    let new_hash = fresh_snap.metadata_hash();

                    if old_hash == new_hash {
                        // Metadata unchanged. Change detection is per-entry so
                        // children are checked individually when they appear in
                        // the fresh entries list.
                        unchanged_count += 1;
                    } else {
                        // Metadata changed - this path needs re-scanning.
                        if budget.try_consume() {
                            changed.push(path.clone());
                        } else {
                            budget_exhausted = true;
                            deferred.push(path.clone());
                        }
                    }
                }
            }
        }

        // Find removed paths (in old index but not in fresh scan).
        let removed: Vec<PathBuf> = self
            .snapshots
            .keys()
            .filter(|p| !fresh_snapshots.contains_key(*p))
            .cloned()
            .collect();

        let health = if budget_exhausted {
            IndexHealth::Degraded
        } else {
            IndexHealth::Healthy
        };
        self.health = health;

        IncrementalDiff {
            changed_paths: changed,
            unchanged_count,
            new_paths,
            removed_paths: removed,
            budget_exhausted,
            deferred_paths: deferred,
            health,
        }
    }

    /// Update the index with fresh entries for paths that changed.
    ///
    /// Call this after re-scanning the changed paths to bring the index
    /// up to date.
    pub fn update_entries(&mut self, entries: &[WalkEntry]) {
        for entry in entries {
            let snapshot = EntrySnapshot::from_walk_entry(entry);
            self.snapshots.insert(entry.path.clone(), snapshot);
        }

        // Rebuild Merkle nodes for affected paths (bottom-up).
        let mut children_map: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();

        // Rebuild full children map from current snapshots.
        for path in self.snapshots.keys() {
            if let Some(parent) = path.parent() {
                children_map
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(path.clone());
            }
        }

        for children in children_map.values_mut() {
            children.sort();
        }

        // Recompute nodes for updated entries and their ancestors.
        let mut paths_to_update: Vec<PathBuf> = entries.iter().map(|e| e.path.clone()).collect();

        // Also update ancestors up to root.
        for entry in entries {
            let mut current = entry.path.as_path();
            while let Some(parent) = current.parent() {
                if self
                    .root_paths
                    .iter()
                    .any(|r| parent.starts_with(r) || r.starts_with(parent))
                {
                    paths_to_update.push(parent.to_path_buf());
                }
                current = parent;
                // Stop at root paths.
                if self.root_paths.contains(&parent.to_path_buf()) {
                    break;
                }
            }
        }

        paths_to_update.sort();
        paths_to_update.dedup();

        // Sort by depth descending (deepest first).
        paths_to_update.sort_by(|a, b| {
            let depth_a = a.components().count();
            let depth_b = b.components().count();
            depth_b.cmp(&depth_a)
        });

        for path in &paths_to_update {
            let metadata_hash = self
                .snapshots
                .get(path)
                .map_or(ZERO_HASH, EntrySnapshot::metadata_hash);

            let children = children_map.get(path).cloned().unwrap_or_default();
            let depth = path.components().count().saturating_sub(1);
            let subtree_hash = compute_subtree_hash(metadata_hash, &children, &self.nodes);

            self.nodes.insert(
                path.clone(),
                MerkleNode {
                    metadata_hash,
                    subtree_hash,
                    depth,
                    children,
                },
            );
        }
    }

    /// Remove paths from the index that no longer exist.
    pub fn remove_paths(&mut self, paths: &[PathBuf]) {
        let mut ancestors_to_refresh = Vec::new();
        for path in paths {
            self.nodes.remove(path);
            self.snapshots.remove(path);
            let mut current = path.parent();
            while let Some(parent) = current {
                if self
                    .root_paths
                    .iter()
                    .any(|root| parent.starts_with(root) || root.starts_with(parent))
                {
                    ancestors_to_refresh.push(parent.to_path_buf());
                }
                if self.root_paths.iter().any(|root| root == parent) {
                    break;
                }
                current = parent.parent();
            }
        }

        if ancestors_to_refresh.is_empty() {
            return;
        }

        let mut children_map: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
        for path in self.snapshots.keys() {
            if let Some(parent) = path.parent() {
                children_map
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(path.clone());
            }
        }
        for children in children_map.values_mut() {
            children.sort();
        }

        ancestors_to_refresh.sort();
        ancestors_to_refresh.dedup();
        ancestors_to_refresh.sort_by_key(|path| std::cmp::Reverse(path.components().count()));

        for path in ancestors_to_refresh {
            let has_snapshot = self.snapshots.contains_key(&path);
            let has_children = children_map.contains_key(&path);
            if !has_snapshot && !has_children {
                self.nodes.remove(&path);
                continue;
            }

            let metadata_hash = self
                .snapshots
                .get(&path)
                .map_or(ZERO_HASH, EntrySnapshot::metadata_hash);
            let children = children_map.get(&path).cloned().unwrap_or_default();
            let depth = path.components().count().saturating_sub(1);
            let subtree_hash = compute_subtree_hash(metadata_hash, &children, &self.nodes);

            self.nodes.insert(
                path,
                MerkleNode {
                    metadata_hash,
                    subtree_hash,
                    depth,
                    children,
                },
            );
        }
    }

    /// Save the index to a checkpoint file.
    pub fn save_checkpoint(&self, path: &Path) -> Result<()> {
        let nodes_bytes = serde_json::to_vec(&self.nodes).map_err(|e| SbhError::Serialization {
            context: "merkle_checkpoint",
            details: e.to_string(),
        })?;
        let snaps_bytes =
            serde_json::to_vec(&self.snapshots).map_err(|e| SbhError::Serialization {
                context: "merkle_checkpoint",
                details: e.to_string(),
            })?;

        let mut integrity_hasher = Sha256::new();
        integrity_hasher.update(&nodes_bytes);
        integrity_hasher.update(&snaps_bytes);
        let integrity_hash: MerkleHash = integrity_hasher.finalize().into();

        let built_at_nanos = self
            .built_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        let checkpoint = IndexCheckpoint {
            version: CHECKPOINT_VERSION,
            built_at_nanos,
            integrity_hash,
            nodes: self.nodes.clone(),
            snapshots: self.snapshots.clone(),
            root_paths: self.root_paths.clone(),
            health: self.health,
        };

        // Write atomically: write to temp file, then rename.
        let temp_path = path.with_extension("tmp");

        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).map_err(|e| SbhError::io(parent, e))?;
        }

        let file = fs::File::create(&temp_path).map_err(|e| SbhError::io(&temp_path, e))?;

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &checkpoint).map_err(|e| SbhError::Serialization {
            context: "merkle_checkpoint_write",
            details: e.to_string(),
        })?;
        writer.flush().map_err(|e| SbhError::io(&temp_path, e))?;

        fs::rename(&temp_path, path).map_err(|e| SbhError::io(path, e))?;

        Ok(())
    }

    /// Load the index from a checkpoint file.
    ///
    /// Returns `Err` or sets health to `Corrupt` if the checkpoint is invalid.
    pub fn load_checkpoint(path: &Path) -> Result<Self> {
        let file = fs::File::open(path).map_err(|e| SbhError::io(path, e))?;
        let reader = BufReader::new(file);

        let checkpoint: IndexCheckpoint =
            serde_json::from_reader(reader).map_err(|e| SbhError::Serialization {
                context: "merkle_checkpoint_load",
                details: e.to_string(),
            })?;

        if checkpoint.version != CHECKPOINT_VERSION {
            return Err(SbhError::Serialization {
                context: "merkle_checkpoint_version",
                details: format!(
                    "unsupported checkpoint version {} (expected {CHECKPOINT_VERSION})",
                    checkpoint.version
                ),
            });
        }

        // Verify integrity hash (covers both nodes and snapshots).
        let nodes_bytes =
            serde_json::to_vec(&checkpoint.nodes).map_err(|e| SbhError::Serialization {
                context: "merkle_checkpoint_verify",
                details: e.to_string(),
            })?;
        let snaps_bytes =
            serde_json::to_vec(&checkpoint.snapshots).map_err(|e| SbhError::Serialization {
                context: "merkle_checkpoint_verify",
                details: e.to_string(),
            })?;

        let mut hasher = Sha256::new();
        hasher.update(&nodes_bytes);
        hasher.update(&snaps_bytes);
        let computed: MerkleHash = hasher.finalize().into();

        if computed != checkpoint.integrity_hash {
            return Err(SbhError::Serialization {
                context: "merkle_checkpoint_integrity",
                details: "checkpoint integrity hash mismatch — index is corrupt".to_string(),
            });
        }

        let built_at = UNIX_EPOCH
            + Duration::from_nanos(u64::try_from(checkpoint.built_at_nanos).unwrap_or(0));

        Ok(Self {
            nodes: checkpoint.nodes,
            snapshots: checkpoint.snapshots,
            root_paths: checkpoint.root_paths,
            health: checkpoint.health,
            built_at,
        })
    }

    /// Get the current health status.
    pub fn health(&self) -> IndexHealth {
        self.health
    }

    /// Mark the index as corrupt, forcing full scan on next cycle.
    pub fn mark_corrupt(&mut self) {
        self.health = IndexHealth::Corrupt;
    }

    /// Number of tracked entries.
    pub fn entry_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Number of Merkle nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Check if a specific path's metadata has changed compared to the index.
    pub fn is_path_changed(&self, path: &Path, current_meta: &WalkEntry) -> bool {
        let Some(old_snap) = self.snapshots.get(path) else {
            return true; // New path = changed
        };
        let fresh = EntrySnapshot::from_walk_entry(current_meta);
        old_snap.metadata_hash() != fresh.metadata_hash()
    }

    /// Get the subtree hash for a path, if tracked.
    pub fn subtree_hash(&self, path: &Path) -> Option<MerkleHash> {
        self.nodes.get(path).map(|n| n.subtree_hash)
    }

    /// Determine whether a full scan is required.
    ///
    /// Returns true if health is Corrupt, Uninitialized, or the index is empty.
    pub fn requires_full_scan(&self) -> bool {
        matches!(
            self.health,
            IndexHealth::Corrupt | IndexHealth::Uninitialized
        ) || self.snapshots.is_empty()
    }

    /// Filter walk entries to only those whose subtrees changed.
    ///
    /// This is the main entry point for the incremental scan workflow:
    /// 1. Take fresh top-level entries from a shallow walk
    /// 2. Compare against stored subtree hashes
    /// 3. Return only entries that need full re-scanning
    ///
    /// If the index requires a full scan, returns all entries unchanged.
    pub fn filter_changed(&self, entries: &[WalkEntry]) -> Vec<WalkEntry> {
        if self.requires_full_scan() {
            return entries.to_vec();
        }

        entries
            .iter()
            .filter(|entry| self.is_path_changed(&entry.path, entry))
            .cloned()
            .collect()
    }
}

impl Default for MerkleScanIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the subtree hash from a node's metadata hash and its children's subtree hashes.
fn compute_subtree_hash(
    metadata_hash: MerkleHash,
    children: &[PathBuf],
    nodes: &BTreeMap<PathBuf, MerkleNode>,
) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(metadata_hash);

    for child_path in children {
        let child_hash = nodes.get(child_path).map_or(ZERO_HASH, |n| n.subtree_hash);
        hasher.update(child_hash);
    }

    hasher.finalize().into()
}

/// Format a `MerkleHash` as a hex string (for logging/display).
pub fn hash_hex(hash: &MerkleHash) -> String {
    use std::fmt::Write;
    hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::patterns::StructuralSignals;
    use crate::scanner::walker::EntryMetadata;
    use std::time::Duration;
    use tempfile::TempDir;

    fn make_entry(path: &str, size: u64, modified_secs: u64, depth: usize) -> WalkEntry {
        WalkEntry {
            path: PathBuf::from(path),
            metadata: EntryMetadata {
                size_bytes: size,
                modified: UNIX_EPOCH + Duration::from_secs(modified_secs),
                created: None,
                is_dir: true,
                inode: 0,
                device_id: 0,
                permissions: 0o755,
            },
            depth,
            structural_signals: StructuralSignals::default(),
            is_open: false,
        }
    }

    #[test]
    fn build_from_entries_creates_nodes() {
        let entries = vec![
            make_entry("/data/projects/target", 4096, 1000, 1),
            make_entry("/data/projects/target/debug", 4096, 1000, 2),
            make_entry("/data/projects/target/release", 4096, 1000, 2),
        ];
        let roots = vec![PathBuf::from("/data/projects")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        assert_eq!(index.entry_count(), 3);
        assert_eq!(index.node_count(), 3);
        assert_eq!(index.health(), IndexHealth::Healthy);
    }

    #[test]
    fn metadata_hash_changes_with_mtime() {
        let e1 = make_entry("/tmp/a", 100, 1000, 1);
        let e2 = make_entry("/tmp/a", 100, 2000, 1);

        let s1 = EntrySnapshot::from_walk_entry(&e1);
        let s2 = EntrySnapshot::from_walk_entry(&e2);

        assert_ne!(s1.metadata_hash(), s2.metadata_hash());
    }

    #[test]
    fn metadata_hash_changes_with_size() {
        let e1 = make_entry("/tmp/a", 100, 1000, 1);
        let e2 = make_entry("/tmp/a", 200, 1000, 1);

        let s1 = EntrySnapshot::from_walk_entry(&e1);
        let s2 = EntrySnapshot::from_walk_entry(&e2);

        assert_ne!(s1.metadata_hash(), s2.metadata_hash());
    }

    #[test]
    fn metadata_hash_stable_for_same_input() {
        let e1 = make_entry("/tmp/a", 100, 1000, 1);
        let e2 = make_entry("/tmp/a", 100, 1000, 1);

        let s1 = EntrySnapshot::from_walk_entry(&e1);
        let s2 = EntrySnapshot::from_walk_entry(&e2);

        assert_eq!(s1.metadata_hash(), s2.metadata_hash());
    }

    #[test]
    fn diff_detects_changed_entry() {
        let original = vec![
            make_entry("/data/target", 4096, 1000, 1),
            make_entry("/data/target/debug", 4096, 1000, 2),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&original, &roots);

        // Change mtime of /data/target/debug.
        let fresh = vec![
            make_entry("/data/target", 4096, 1000, 1),
            make_entry("/data/target/debug", 4096, 2000, 2),
        ];

        let mut budget = ScanBudget::new(100, 0);
        let diff = index.diff(&fresh, &mut budget);

        assert_eq!(diff.changed_paths.len(), 1);
        assert_eq!(diff.changed_paths[0], PathBuf::from("/data/target/debug"));
        assert_eq!(diff.unchanged_count, 1);
        assert!(diff.new_paths.is_empty());
        assert!(diff.removed_paths.is_empty());
        assert!(!diff.budget_exhausted);
    }

    #[test]
    fn diff_detects_new_path() {
        let original = vec![make_entry("/data/target", 4096, 1000, 1)];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&original, &roots);

        let fresh = vec![
            make_entry("/data/target", 4096, 1000, 1),
            make_entry("/data/target/new_dir", 4096, 3000, 2),
        ];

        let mut budget = ScanBudget::new(100, 0);
        let diff = index.diff(&fresh, &mut budget);

        assert_eq!(diff.new_paths.len(), 1);
        assert_eq!(diff.new_paths[0], PathBuf::from("/data/target/new_dir"));
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn diff_defers_new_paths_when_budget_exhausted() {
        let original = vec![make_entry("/data/target", 4096, 1000, 1)];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&original, &roots);

        let fresh = vec![
            make_entry("/data/target", 4096, 1000, 1),
            make_entry("/data/target/new_a", 4096, 3000, 2),
            make_entry("/data/target/new_b", 4096, 3001, 2),
        ];

        // Only one new-path update allowed.
        let mut budget = ScanBudget::new(1, 0);
        let diff = index.diff(&fresh, &mut budget);

        assert!(diff.budget_exhausted);
        assert_eq!(diff.new_paths.len(), 1);
        assert_eq!(diff.deferred_paths.len(), 1);
    }

    #[test]
    fn diff_detects_removed_path() {
        let original = vec![
            make_entry("/data/target", 4096, 1000, 1),
            make_entry("/data/target/debug", 4096, 1000, 2),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&original, &roots);

        // Only target remains, debug was removed.
        let fresh = vec![make_entry("/data/target", 4096, 1000, 1)];

        let mut budget = ScanBudget::new(100, 0);
        let diff = index.diff(&fresh, &mut budget);

        assert_eq!(diff.removed_paths.len(), 1);
        assert_eq!(diff.removed_paths[0], PathBuf::from("/data/target/debug"));
    }

    #[test]
    fn diff_respects_budget() {
        let original = vec![
            make_entry("/data/a", 4096, 1000, 1),
            make_entry("/data/b", 4096, 1000, 1),
            make_entry("/data/c", 4096, 1000, 1),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&original, &roots);

        // All three changed.
        let fresh = vec![
            make_entry("/data/a", 4096, 2000, 1),
            make_entry("/data/b", 4096, 2000, 1),
            make_entry("/data/c", 4096, 2000, 1),
        ];

        // Budget for only 1 update.
        let mut budget = ScanBudget::new(1, 0);
        let diff = index.diff(&fresh, &mut budget);

        assert_eq!(diff.changed_paths.len(), 1);
        assert!(diff.budget_exhausted);
        assert_eq!(diff.deferred_paths.len(), 2);
        assert_eq!(diff.health, IndexHealth::Degraded);
        assert_eq!(index.health(), IndexHealth::Degraded);
    }

    #[test]
    fn diff_recovery_restores_healthy_index_state() {
        let original = vec![
            make_entry("/data/a", 4096, 1000, 1),
            make_entry("/data/b", 4096, 1000, 1),
            make_entry("/data/c", 4096, 1000, 1),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&original, &roots);

        let fresh = vec![
            make_entry("/data/a", 4096, 2000, 1),
            make_entry("/data/b", 4096, 2000, 1),
            make_entry("/data/c", 4096, 2000, 1),
        ];

        let mut tight_budget = ScanBudget::new(1, 0);
        let _ = index.diff(&fresh, &mut tight_budget);
        assert_eq!(index.health(), IndexHealth::Degraded);

        let mut ample_budget = ScanBudget::new(10, 0);
        let _ = index.diff(&fresh, &mut ample_budget);
        assert_eq!(index.health(), IndexHealth::Healthy);
    }

    #[test]
    fn diff_budget_exhaustion_does_not_defer_unchanged_paths() {
        let original = vec![
            make_entry("/data/a", 4096, 1000, 1),
            make_entry("/data/b", 4096, 1000, 1),
            make_entry("/data/c", 4096, 1000, 1),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&original, &roots);

        let fresh = vec![
            make_entry("/data/a", 4096, 2000, 1),
            make_entry("/data/b", 4096, 2000, 1),
            make_entry("/data/c", 4096, 1000, 1),
        ];

        let mut budget = ScanBudget::new(1, 0);
        let diff = index.diff(&fresh, &mut budget);

        assert!(diff.budget_exhausted);
        assert_eq!(diff.changed_paths.len(), 1);
        assert_eq!(diff.deferred_paths, vec![PathBuf::from("/data/b")]);
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn no_changes_yields_empty_diff() {
        let entries = vec![
            make_entry("/data/target", 4096, 1000, 1),
            make_entry("/data/target/debug", 4096, 1000, 2),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        let mut budget = ScanBudget::new(100, 0);
        let diff = index.diff(&entries, &mut budget);

        assert!(diff.changed_paths.is_empty());
        assert!(diff.new_paths.is_empty());
        assert!(diff.removed_paths.is_empty());
        assert_eq!(diff.unchanged_count, 2);
        assert!(!diff.budget_exhausted);
        assert_eq!(diff.health, IndexHealth::Healthy);
    }

    #[test]
    fn checkpoint_roundtrip() {
        let entries = vec![
            make_entry("/data/target", 4096, 1000, 1),
            make_entry("/data/target/debug", 4096, 1000, 2),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        let tmp = TempDir::new().expect("temp dir");
        let checkpoint_path = tmp.path().join("merkle.json");

        index.save_checkpoint(&checkpoint_path).expect("save");
        let loaded = MerkleScanIndex::load_checkpoint(&checkpoint_path).expect("load");

        assert_eq!(loaded.entry_count(), index.entry_count());
        assert_eq!(loaded.node_count(), index.node_count());
        assert_eq!(loaded.health(), IndexHealth::Healthy);

        // Verify same subtree hashes.
        for (path, node) in &index.nodes {
            let loaded_node = loaded.nodes.get(path).expect("node should exist");
            assert_eq!(node.subtree_hash, loaded_node.subtree_hash);
        }
    }

    #[test]
    fn corrupt_checkpoint_detected() {
        let entries = vec![make_entry("/data/target", 4096, 1000, 1)];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        let tmp = TempDir::new().expect("temp dir");
        let checkpoint_path = tmp.path().join("merkle.json");

        index.save_checkpoint(&checkpoint_path).expect("save");

        // Corrupt the file by modifying the snapshots section. The integrity
        // hash covers both nodes and snapshots so any change is detected.
        let data = fs::read_to_string(&checkpoint_path).expect("read");
        // Replace a size_bytes value inside the snapshots section.
        let corrupted = data.replacen("\"size_bytes\":4096", "\"size_bytes\":9999", 1);
        assert_ne!(data, corrupted, "corruption must change the file");
        fs::write(&checkpoint_path, corrupted).expect("write");

        let result = MerkleScanIndex::load_checkpoint(&checkpoint_path);
        assert!(result.is_err(), "corrupt checkpoint should fail to load");
    }

    #[test]
    fn uninitialized_index_requires_full_scan() {
        let index = MerkleScanIndex::new();
        assert!(index.requires_full_scan());
        assert_eq!(index.health(), IndexHealth::Uninitialized);
    }

    #[test]
    fn corrupt_index_requires_full_scan() {
        let mut index = MerkleScanIndex::new();
        index.mark_corrupt();
        assert!(index.requires_full_scan());
    }

    #[test]
    fn filter_changed_returns_all_when_uninitialized() {
        let index = MerkleScanIndex::new();
        let entries = vec![
            make_entry("/data/a", 4096, 1000, 1),
            make_entry("/data/b", 4096, 1000, 1),
        ];

        let filtered = index.filter_changed(&entries);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_changed_skips_unchanged() {
        let entries = vec![
            make_entry("/data/a", 4096, 1000, 1),
            make_entry("/data/b", 4096, 1000, 1),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        // Only /data/a changed.
        let fresh = vec![
            make_entry("/data/a", 4096, 2000, 1),
            make_entry("/data/b", 4096, 1000, 1),
        ];

        let filtered = index.filter_changed(&fresh);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, PathBuf::from("/data/a"));
    }

    #[test]
    fn update_entries_refreshes_index() {
        let entries = vec![
            make_entry("/data/a", 4096, 1000, 1),
            make_entry("/data/b", 4096, 1000, 1),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        // Update /data/a with new mtime.
        let updated = vec![make_entry("/data/a", 4096, 2000, 1)];
        index.update_entries(&updated);

        // Now a fresh scan with the same mtime should show no changes.
        let fresh = vec![
            make_entry("/data/a", 4096, 2000, 1),
            make_entry("/data/b", 4096, 1000, 1),
        ];

        let mut budget = ScanBudget::new(100, 0);
        let diff = index.diff(&fresh, &mut budget);
        assert!(diff.changed_paths.is_empty());
        assert_eq!(diff.unchanged_count, 2);
    }

    #[test]
    fn remove_paths_cleans_index() {
        let entries = vec![
            make_entry("/data/a", 4096, 1000, 1),
            make_entry("/data/b", 4096, 1000, 1),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        assert_eq!(index.entry_count(), 2);

        index.remove_paths(&[PathBuf::from("/data/a")]);

        assert_eq!(index.entry_count(), 1);
        assert!(index.subtree_hash(Path::new("/data/a")).is_none());
        assert!(index.subtree_hash(Path::new("/data/b")).is_some());
    }

    #[test]
    fn remove_paths_rehashes_ancestors_after_child_removal() {
        let entries = vec![
            make_entry("/data/parent", 4096, 1000, 1),
            make_entry("/data/parent/a", 4096, 1000, 2),
            make_entry("/data/parent/b", 4096, 1000, 2),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);
        let before = index.subtree_hash(Path::new("/data/parent")).unwrap();

        index.remove_paths(&[PathBuf::from("/data/parent/b")]);

        let after = index.subtree_hash(Path::new("/data/parent")).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn hash_hex_formatting() {
        let hash: MerkleHash = [0xab; 32];
        let hex = hash_hex(&hash);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hex.starts_with("abab"));
    }

    #[test]
    fn subtree_hash_changes_when_child_changes() {
        let entries = vec![
            make_entry("/data/parent", 4096, 1000, 1),
            make_entry("/data/parent/child", 4096, 1000, 2),
        ];
        let roots = vec![PathBuf::from("/data")];

        let mut index = MerkleScanIndex::new();
        index.build_from_entries(&entries, &roots);

        let parent_hash1 = index.subtree_hash(Path::new("/data/parent")).unwrap();

        // Rebuild with changed child.
        let entries2 = vec![
            make_entry("/data/parent", 4096, 1000, 1),
            make_entry("/data/parent/child", 8192, 2000, 2),
        ];

        let mut index2 = MerkleScanIndex::new();
        index2.build_from_entries(&entries2, &roots);

        let parent_hash2 = index2.subtree_hash(Path::new("/data/parent")).unwrap();

        // Parent subtree hash should differ because child changed.
        assert_ne!(parent_hash1, parent_hash2);
    }

    #[test]
    fn scan_budget_tracks_consumption() {
        let mut budget = ScanBudget::new(3, 0);
        assert_eq!(budget.remaining(), 3);
        assert!(!budget.is_exhausted());

        assert!(budget.try_consume());
        assert_eq!(budget.remaining(), 2);

        assert!(budget.try_consume());
        assert!(budget.try_consume());
        assert!(!budget.try_consume()); // Exhausted.
        assert!(budget.is_exhausted());
        assert_eq!(budget.remaining(), 0);
    }
}
