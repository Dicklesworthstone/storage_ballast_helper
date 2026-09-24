//! Backup publication, identity, and retention regressions.

use super::BackupStore;
use std::fs;

#[test]
fn consecutive_backups_never_overwrite_an_existing_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let store = BackupStore::open(temp.path().join("backups"));
    let source = temp.path().join("sbh");
    fs::write(&source, b"first version").unwrap();
    let first = store.create(&source, "first").unwrap();
    fs::write(&source, b"second version").unwrap();
    let second = store.create(&source, "second").unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(fs::read(first.path).unwrap(), b"first version");
    assert_eq!(fs::read(second.path).unwrap(), b"second version");
    let entries = store.list();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].id, second.id);
    assert_eq!(entries[1].id, first.id);
}

#[test]
fn failed_backup_does_not_leave_a_published_or_partial_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let store = BackupStore::open(temp.path().join("backups"));
    let source = temp.path().join("missing");
    assert!(store.create(&source, "missing").is_err());
    assert!(store.list().is_empty());
    assert_eq!(fs::read_dir(store.dir()).unwrap().count(), 0);
}

#[test]
fn incomplete_binary_is_not_visible_to_inventory_or_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let store = BackupStore::open(temp.path().join("backups"));
    let entry = store.dir().join("123-000000001-test");
    fs::create_dir_all(&entry).unwrap();
    fs::write(entry.join("sbh.partial"), b"incomplete").unwrap();
    fs::write(entry.join("backup.json"), br#"{"version":"test","timestamp":123}"#).unwrap();
    assert!(store.list().is_empty());
    assert!(store.rollback(&temp.path().join("restored"), None).is_err());
    fs::rename(entry.join("sbh.partial"), entry.join("sbh")).unwrap();
    assert_eq!(store.list().len(), 1);
}

#[test]
fn equal_second_timestamps_are_ordered_by_subsecond_snapshot_id() {
    let temp = tempfile::tempdir().unwrap();
    let store = BackupStore::open(temp.path().join("backups"));
    for id in ["123-000000001-first", "123-000000002-second"] {
        let entry = store.dir().join(id);
        fs::create_dir_all(&entry).unwrap();
        fs::write(entry.join("sbh"), id).unwrap();
        fs::write(entry.join("backup.json"), br#"{"version":"test","timestamp":123}"#).unwrap();
    }
    let entries = store.list();
    assert_eq!(entries[0].id, "123-000000002-second");
    assert_eq!(entries[1].id, "123-000000001-first");
}

#[test]
fn pruning_preserves_the_newest_snapshot_within_the_same_second() {
    let temp = tempfile::tempdir().unwrap();
    let store = BackupStore::open(temp.path().join("backups"));
    let source = temp.path().join("sbh");
    fs::write(&source, b"first").unwrap();
    let first = store.create(&source, "first").unwrap();
    fs::write(&source, b"second").unwrap();
    let second = store.create(&source, "second").unwrap();
    store.prune(1).unwrap();
    assert!(!first.path.exists());
    assert!(second.path.exists());
    assert_eq!(store.list()[0].id, second.id);
}
