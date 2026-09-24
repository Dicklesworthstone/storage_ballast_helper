//! Exercise the same select / advance / complete sequence used by the daemon,
//! with small page sizes so a test need not create 200,000 filesystem entries.

use super::*;

fn make_root(base: &Path, name: &str, count: usize) -> PathBuf {
    let root = base.join(name);
    fs::create_dir_all(&root).unwrap();
    for index in 0..count {
        fs::create_dir(root.join(format!("item-{index:03}"))).unwrap();
    }
    root
}

fn page(cursor: &mut PrescanCursor, roots: &[PathBuf], root: &Path, cap: usize) -> Vec<PathBuf> {
    let entries = cursor.entries_with_capacity(root, cap).unwrap();
    for entry in &entries {
        cursor.advance(root, entry);
    }
    cursor.complete_root(roots, root);
    entries
}

fn expected(root: &Path, start: usize, end: usize) -> Vec<PathBuf> {
    (start..end)
        .map(|index| root.join(format!("item-{index:03}")))
        .collect()
}

#[test]
fn daemon_completion_calls_cover_every_capped_page_without_resetting_the_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let root = make_root(dir.path(), "large", 37);
    let roots = vec![root.clone()];
    let mut cursor = PrescanCursor::new();
    let mut seen = Vec::new();
    for _ in 0..13 {
        seen.extend(page(&mut cursor, &roots, &root, 3));
    }
    assert_eq!(seen, expected(&root, 0, 37));
    assert_eq!(cursor.position(), (Some(root.as_path()), None));
    assert!(cursor.continuations.is_empty());
}

#[test]
fn capped_roots_rotate_fairly_without_discarding_each_others_continuations() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_root(dir.path(), "a", 4);
    let b = make_root(dir.path(), "b", 4);
    let roots = vec![a.clone(), b.clone()];
    let mut cursor = PrescanCursor::new();
    assert_eq!(page(&mut cursor, &roots, &a, 2), expected(&a, 0, 2));
    assert_eq!(cursor.position().0, Some(b.as_path()));
    assert_eq!(page(&mut cursor, &roots, &b, 2), expected(&b, 0, 2));
    assert_eq!(
        cursor.position(),
        (Some(a.as_path()), Some(a.join("item-001").as_path()))
    );
    assert_eq!(page(&mut cursor, &roots, &a, 2), expected(&a, 2, 4));
    assert_eq!(page(&mut cursor, &roots, &b, 2), expected(&b, 2, 4));
    assert!(cursor.continuations.is_empty());
    assert_eq!(cursor.position(), (Some(a.as_path()), None));
}

#[test]
fn alternating_per_mount_requests_keep_the_other_mounts_position() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_root(dir.path(), "mount-a", 5);
    let b = make_root(dir.path(), "mount-b", 5);
    let mut cursor = PrescanCursor::new();
    assert_eq!(
        page(&mut cursor, std::slice::from_ref(&a), &a, 2),
        expected(&a, 0, 2)
    );
    assert_eq!(
        page(&mut cursor, std::slice::from_ref(&b), &b, 2),
        expected(&b, 0, 2)
    );
    assert_eq!(
        page(&mut cursor, std::slice::from_ref(&a), &a, 2),
        expected(&a, 2, 4)
    );
    assert_eq!(
        page(&mut cursor, std::slice::from_ref(&b), &b, 2),
        expected(&b, 2, 4)
    );
}

#[test]
fn every_unfinished_root_survives_checkpoint_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_root(dir.path(), "a", 5);
    let b = make_root(dir.path(), "b", 5);
    let roots = vec![a.clone(), b.clone()];
    let path = dir.path().join("checkpoint.json");
    let mut cursor = PrescanCursor::new();
    page(&mut cursor, &roots, &a, 2);
    page(&mut cursor, &roots, &b, 2);
    cursor.save(&path).unwrap();
    let mut restored = PrescanCursor::load(&path);
    assert_eq!(restored, cursor);
    assert_eq!(page(&mut restored, &roots, &a, 2), expected(&a, 2, 4));
    assert_eq!(page(&mut restored, &roots, &b, 2), expected(&b, 2, 4));
    restored.save(&path).unwrap();
    let mut restored = PrescanCursor::load(&path);
    assert_eq!(page(&mut restored, &roots, &a, 2), expected(&a, 4, 5));
    assert_eq!(page(&mut restored, &roots, &b, 2), expected(&b, 4, 5));
    assert!(restored.continuations.is_empty());
}

#[test]
fn a_read_error_invalidates_an_earlier_eof_observation_without_losing_progress() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_root(dir.path(), "a", 3);
    let b = make_root(dir.path(), "b", 1);
    let roots = vec![a.clone(), b.clone()];
    let mut cursor = PrescanCursor::new();
    let entries = cursor.entries_with_capacity(&a, 10).unwrap();
    cursor.advance(&a, &entries[0]);
    let away = dir.path().join("temporarily-unmounted");
    fs::rename(&a, &away).unwrap();
    assert!(cursor.entries_with_capacity(&a, 10).is_err());
    cursor.complete_root(&roots, &a);
    assert_eq!(cursor.position().0, Some(b.as_path()));
    assert_eq!(page(&mut cursor, &roots, &b, 2), expected(&b, 0, 1));
    fs::rename(&away, &a).unwrap();
    assert_eq!(page(&mut cursor, &roots, &a, 2), expected(&a, 1, 3));
}

#[test]
fn exactly_full_final_pages_rewind_without_an_extra_empty_pass() {
    let dir = tempfile::tempdir().unwrap();
    let root = make_root(dir.path(), "root", 4);
    let roots = vec![root.clone()];
    let mut cursor = PrescanCursor::new();
    assert_eq!(page(&mut cursor, &roots, &root, 2), expected(&root, 0, 2));
    assert!(cursor.position().1.is_some());
    assert_eq!(page(&mut cursor, &roots, &root, 2), expected(&root, 2, 4));
    assert!(cursor.position().1.is_none());
    assert!(cursor.continuations.is_empty());
    assert_eq!(page(&mut cursor, &roots, &root, 2), expected(&root, 0, 2));
}

#[test]
fn completing_a_partially_consumed_final_page_does_not_skip_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let root = make_root(dir.path(), "root", 5);
    let roots = vec![root.clone()];
    let mut cursor = PrescanCursor::new();
    let entries = cursor.entries_with_capacity(&root, 10).unwrap();
    cursor.advance(&root, &entries[0]);
    cursor.advance(&root, &entries[1]);
    cursor.complete_root(&roots, &root);
    assert_eq!(page(&mut cursor, &roots, &root, 10), expected(&root, 2, 5));
    assert!(cursor.continuations.is_empty());
}

#[test]
fn a_budget_rewind_clone_keeps_its_own_page_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let root = make_root(dir.path(), "root", 5);
    let roots = vec![root.clone()];
    let cursor = PrescanCursor::new();
    let first = cursor.entries_with_capacity(&root, 2).unwrap();
    let mut rewind = cursor.clone();
    // A later read on the original must not replace the saved clone's
    // non-final page proof with an EOF proof for another page.
    assert_eq!(cursor.entries_with_capacity(&root, 10).unwrap().len(), 5);
    for entry in first {
        rewind.advance(&root, &entry);
    }
    rewind.complete_root(&roots, &root);
    assert_eq!(page(&mut rewind, &roots, &root, 2), expected(&root, 2, 4));
}

#[test]
fn legacy_checkpoints_upgrade_without_forgetting_the_old_resume_point() {
    let dir = tempfile::tempdir().unwrap();
    let a = make_root(dir.path(), "a", 5);
    let b = make_root(dir.path(), "b", 5);
    let old = serde_json::json!({"root": a, "after": a.join("item-001")});
    let mut cursor: PrescanCursor = serde_json::from_value(old).unwrap();
    // Switch requests before returning to the old checkpoint's root.
    page(&mut cursor, std::slice::from_ref(&b), &b, 2);
    assert_eq!(
        page(&mut cursor, std::slice::from_ref(&a), &a, 2),
        expected(&a, 2, 4)
    );
    let encoded = serde_json::to_value(&cursor).unwrap();
    assert!(
        encoded.get("page").is_none(),
        "enumeration is not completed work"
    );
    assert_eq!(
        serde_json::from_value::<PrescanCursor>(encoded).unwrap(),
        cursor
    );
}

#[test]
fn page_reads_do_not_dirty_checkpoints_and_reset_clears_every_root() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PrescanCursor>();
    let dir = tempfile::tempdir().unwrap();
    let a = make_root(dir.path(), "a", 5);
    let b = make_root(dir.path(), "b", 5);
    let roots = vec![a.clone(), b.clone()];
    let mut cursor = PrescanCursor::new();
    let before = cursor.clone();
    cursor.entries_with_capacity(&a, 2).unwrap();
    assert_eq!(before, cursor);
    page(&mut cursor, &roots, &a, 2);
    page(&mut cursor, &roots, &b, 2);
    assert!(!cursor.continuations.is_empty());
    cursor.reset();
    assert_eq!(cursor, PrescanCursor::new());
    assert_eq!(page(&mut cursor, &roots, &a, 2), expected(&a, 0, 2));
    assert_eq!(page(&mut cursor, &roots, &b, 2), expected(&b, 0, 2));
}

#[test]
fn a_deleted_tail_completes_the_sweep_and_rearms_earlier_names() {
    let dir = tempfile::tempdir().unwrap();
    let root = make_root(dir.path(), "root", 3);
    let roots = vec![root.clone()];
    let mut cursor = PrescanCursor::new();
    page(&mut cursor, &roots, &root, 2);
    fs::remove_dir(root.join("item-002")).unwrap();
    assert!(page(&mut cursor, &roots, &root, 2).is_empty());
    assert!(cursor.continuations.is_empty());
    fs::create_dir(root.join("aaa-new")).unwrap();
    let next = cursor.entries_with_capacity(&root, 2).unwrap();
    assert_eq!(next[0], root.join("aaa-new"));
}

#[test]
fn tail_evidence_matches_eligible_cardinality_in_every_enumeration_order() {
    for count in 0..17 {
        for capacity in 0..19 {
            for reverse in [false, true] {
                let mut paths: Vec<PathBuf> = (0..count)
                    .map(|index| PathBuf::from(format!("/root/{index:03}")))
                    .collect();
                if reverse {
                    paths.reverse();
                }
                let after = Path::new("/root/005");
                let eligible = paths.iter().filter(|path| path.as_path() > after).count();
                let (selected, more) =
                    select_page_with_tail(paths.into_iter().map(Ok), Some(after), capacity)
                        .unwrap();
                assert_eq!(selected.len(), eligible.min(capacity));
                assert_eq!(more, eligible > capacity);
            }
        }
    }
}
