#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use storage_ballast_helper::scanner::merkle::MerkleScanIndex;
    use storage_ballast_helper::scanner::patterns::StructuralSignals;
    use storage_ballast_helper::scanner::walker::{EntryMetadata, FsEntryKind, WalkEntry};

    fn make_entry(path: &str, mtime_secs: u64) -> WalkEntry {
        WalkEntry {
            path: PathBuf::from(path),
            metadata: EntryMetadata {
                size_bytes: 100,
                content_size_bytes: 100,
                modified: SystemTime::UNIX_EPOCH + Duration::from_secs(mtime_secs),
                created: None,
                tree_last_modified: None,
                is_dir: false,
                inode: 0,
                device_id: 0,
                kind: FsEntryKind::File,
                permissions: 0,
            },
            depth: 1,
            structural_signals: StructuralSignals::default(),
            is_open: false,
            opaque_tree: None,
        }
    }

    #[test]
    fn incremental_scan_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint = tmp.path().join("index.json");

        // 1. Initial scan (full).
        let mut index = MerkleScanIndex::new();
        let entries = vec![make_entry("/tmp/a", 100), make_entry("/tmp/b", 100)];

        // Simulate scanner loop logic.
        let mut changed = Vec::new();

        for entry in &entries {
            if !index.is_path_changed(&entry.path, entry) {
                continue;
            }
            changed.push(entry.clone());
        }

        // Initial run: everything changed.
        assert_eq!(changed.len(), 2);

        // Update index.
        if index.requires_full_scan() {
            index.build_from_entries(&changed, &[PathBuf::from("/tmp")]);
        } else {
            index.update_entries(&changed);
        }
        index.save_checkpoint(&checkpoint).unwrap();

        // 2. Second scan (incremental).
        let mut index = MerkleScanIndex::load_checkpoint(&checkpoint).unwrap();

        // Modify 'b'.
        let entries_2 = vec![
            make_entry("/tmp/a", 100), // Unchanged
            make_entry("/tmp/b", 200), // Changed mtime
        ];

        let mut changed = Vec::new();

        for entry in &entries_2 {
            if !index.is_path_changed(&entry.path, entry) {
                continue;
            }
            changed.push(entry.clone());
        }

        // Only 'b' should be changed.
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].path, PathBuf::from("/tmp/b"));

        index.update_entries(&changed);
        index.save_checkpoint(&checkpoint).unwrap();

        // 3. Third scan (removal).
        let mut index = MerkleScanIndex::load_checkpoint(&checkpoint).unwrap();
        let entries_3 = vec![
            make_entry("/tmp/a", 100),
            // 'b' removed
        ];

        let mut seen = HashSet::new();
        let mut changed = Vec::new();

        for entry in &entries_3 {
            seen.insert(entry.path.clone());
            if !index.is_path_changed(&entry.path, entry) {
                continue;
            }
            changed.push(entry.clone());
        }

        assert_eq!(changed.len(), 0);

        let removed: Vec<PathBuf> = index
            .tracked_paths()
            .into_iter()
            .filter(|p| !seen.contains(p))
            .collect();

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], PathBuf::from("/tmp/b"));

        index.remove_paths(&removed);
        assert_eq!(index.entry_count(), 1);
    }
}
