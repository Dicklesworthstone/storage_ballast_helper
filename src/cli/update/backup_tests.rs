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
    fs::write(
        entry.join("backup.json"),
        br#"{"version":"test","timestamp":123}"#,
    )
    .unwrap();
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
        fs::write(
            entry.join("backup.json"),
            br#"{"version":"test","timestamp":123}"#,
        )
        .unwrap();
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


#[test]
fn rollback_rejects_same_size_snapshot_corruption_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let store = BackupStore::open(temp.path().join("backups"));
    let install = temp.path().join("bin/sbh");
    fs::create_dir_all(install.parent().unwrap()).unwrap();
    fs::copy(std::env::current_exe().unwrap(), &install).unwrap();
    let snapshot = store.create(&install, "known-good").unwrap();

    let installed_before = fs::read(&install).unwrap();
    let mut corrupted = fs::read(&snapshot.path).unwrap();
    assert!(!corrupted.is_empty());
    corrupted[0] ^= 0xff;
    fs::write(&snapshot.path, &corrupted).unwrap();

    let error = store
        .rollback(&install, Some(&snapshot.id))
        .unwrap_err();
    assert!(error.contains("SHA-256 mismatch"), "{error}");
    assert_eq!(fs::read(&install).unwrap(), installed_before);
}

#[test]
fn rollback_refuses_legacy_snapshot_without_digest_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let store = BackupStore::open(temp.path().join("backups"));
    let install = temp.path().join("bin/sbh");
    fs::create_dir_all(install.parent().unwrap()).unwrap();
    fs::copy(std::env::current_exe().unwrap(), &install).unwrap();
    let snapshot = store.create(&install, "known-good").unwrap();

    let metadata_path = snapshot.path.parent().unwrap().join("backup.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
    metadata.as_object_mut().unwrap().remove("sha256");
    fs::write(&metadata_path, serde_json::to_vec_pretty(&metadata).unwrap()).unwrap();

    let installed_before = fs::read(&install).unwrap();
    let error = store
        .rollback(&install, Some(&snapshot.id))
        .unwrap_err();
    assert!(error.contains("missing sha256"), "{error}");
    assert_eq!(fs::read(&install).unwrap(), installed_before);
}
