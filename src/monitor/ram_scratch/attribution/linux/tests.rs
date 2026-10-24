use super::*;
use std::os::unix::fs::symlink;
use std::time::Duration;

fn mount(root: &Path) -> ScratchMount {
    ScratchMount {
        path: root.to_str().unwrap().to_owned(),
        filesystem_id: fs::metadata(root).unwrap().dev(),
        total_bytes: 1_048_576,
        used_bytes: 8192,
        available_bytes: 1_040_384,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn attributes_blocks_owner_and_newest_change_without_reading_payload() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let child = root.join("old-agent");
    fs::create_dir(&child).unwrap();
    let file = child.join("output");
    fs::write(&file, vec![7_u8; 8192]).unwrap();
    let old = filetime::FileTime::from_unix_time(1, 0);
    filetime::set_file_mtime(&file, old).unwrap();
    filetime::set_file_mtime(&child, old).unwrap();
    let expected =
        fs::metadata(&child).unwrap().blocks() * 512 + fs::metadata(&file).unwrap().blocks() * 512;
    let report = inspect(&mount(&root), AttributionLimits::default(), 100, deadline());
    assert!(report.complete, "{report:?}");
    assert_eq!(report.entries.len(), 1);
    let entry = &report.entries[0];
    assert_eq!(entry.observed_allocated_bytes, expected);
    assert_eq!(entry.owner_uid, fs::metadata(&child).unwrap().uid());
    // Restoring an old mtime does not hide the recent ctime.
    assert_eq!(entry.idle_hours, Some(0));
    assert_eq!(fs::read(file).unwrap(), vec![7_u8; 8192]);
}

#[test]
fn symlink_targets_are_never_traversed_or_counted() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::write(outside.path().join("private"), vec![9_u8; 32_768]).unwrap();
    symlink(outside.path(), root.join("alias")).unwrap();
    let report = inspect(&mount(&root), AttributionLimits::default(), 100, deadline());
    assert_eq!(report.symlinks_skipped, 1);
    assert_eq!(report.entries[0].observed_allocated_bytes, 0);
    assert!(report.entries[0].idle_hours.is_none());
    assert!(!report.complete);
    assert_eq!(
        fs::read(outside.path().join("private")).unwrap().len(),
        32_768
    );
}

#[test]
fn budgets_leave_age_unknown_and_never_claim_complete_coverage() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::create_dir(root.join("agent")).unwrap();
    fs::write(root.join("agent/output"), b"keep").unwrap();
    let limits = AttributionLimits {
        max_depth: 0,
        ..Default::default()
    };
    let report = inspect(&mount(&root), limits, 100, deadline());
    assert!(!report.complete);
    assert!(report.entries[0].idle_hours.is_none());
    let report = inspect(&mount(&root), AttributionLimits::default(), 1, deadline());
    assert!(!report.complete);
    assert_eq!(report.entries_examined, 1);
    assert!(report.entries[0].idle_hours.is_none());
    let report = inspect(
        &mount(&root),
        AttributionLimits::default(),
        100,
        Instant::now(),
    );
    assert!(!report.complete);
    assert!(report.entries.is_empty());
}

#[test]
fn hard_links_are_not_double_counted_and_wrong_roots_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::write(root.join("one"), vec![1_u8; 8192]).unwrap();
    fs::hard_link(root.join("one"), root.join("two")).unwrap();
    let report = inspect(&mount(&root), AttributionLimits::default(), 100, deadline());
    assert_eq!(
        report
            .entries
            .iter()
            .map(|entry| entry.observed_allocated_bytes)
            .sum::<u64>(),
        fs::metadata(root.join("one")).unwrap().blocks() * 512
    );
    let mut wrong = mount(&root);
    wrong.filesystem_id = wrong.filesystem_id.wrapping_add(1);
    let report = inspect(&wrong, AttributionLimits::default(), 100, deadline());
    assert!(!report.complete);
    assert!(report.entries.is_empty());
}

#[test]
fn output_is_top_bounded_and_preserves_native_names() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let unusual = root.join(OsString::from_vec(b"large-\xff".to_vec()));
    fs::write(root.join("small"), vec![1_u8; 4096]).unwrap();
    fs::write(&unusual, vec![2_u8; 32_768]).unwrap();
    let report = inspect(
        &mount(&root),
        AttributionLimits {
            top: 1,
            ..Default::default()
        },
        100,
        deadline(),
    );
    assert!(report.complete, "{report:?}");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].native_path_hex,
        crate::core::hex_lower(unusual.as_os_str().as_encoded_bytes())
    );
}

#[test]
fn a_future_mtime_never_becomes_a_zero_hour_idle_claim() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = root.join("future");
    fs::write(&file, b"future").unwrap();
    let future = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    filetime::set_file_mtime(
        file,
        filetime::FileTime::from_unix_time(i64::try_from(future).unwrap(), 0),
    )
    .unwrap();
    let report = inspect(&mount(&root), AttributionLimits::default(), 100, deadline());
    assert!(report.complete);
    assert!(report.entries[0].idle_hours.is_none());
}

#[test]
fn the_fullest_mount_is_probed_last_and_gets_what_small_mounts_leave() {
    let small = tempfile::tempdir().unwrap();
    let large = tempfile::tempdir().unwrap();
    let small_root = small.path().canonicalize().unwrap();
    let large_root = large.path().canonicalize().unwrap();
    fs::write(small_root.join("runtime"), b"pid").unwrap();
    let tree = large_root.join("repacked");
    fs::create_dir(&tree).unwrap();
    for index in 0..300 {
        fs::write(tree.join(format!("lib{index}.rlib")), b"rlib").unwrap();
    }
    let mut fullest = mount(&large_root);
    fullest.used_bytes = 1 << 30;
    let mut runtime = mount(&small_root);
    runtime.used_bytes = 4096;
    // Callers pass mounts largest first. An even split of 310 entries would
    // give the 301-entry mount 155 and an incomplete, understated tree.
    let limits = AttributionLimits {
        max_entries: 310,
        ..Default::default()
    };
    let reports =
        crate::monitor::ram_scratch::attribution::inspect(&[fullest, runtime], limits, deadline())
            .unwrap();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].mount_path, large_root.to_str().unwrap());
    assert!(reports[0].complete, "{:?}", reports[0]);
    assert_eq!(reports[0].entries_examined, 301);
    assert_eq!(reports[1].mount_path, small_root.to_str().unwrap());
    assert!(reports[1].complete, "{:?}", reports[1]);
}

#[test]
fn an_exhausted_entry_budget_is_reported_once() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for name in ["a", "b", "c"] {
        fs::create_dir(root.join(name)).unwrap();
        fs::write(root.join(name).join("output"), b"keep").unwrap();
    }
    // The root's three names use the whole budget; each child then hits it.
    let report = inspect(&mount(&root), AttributionLimits::default(), 3, deadline());
    assert!(!report.complete);
    let exhausted = report
        .issues
        .iter()
        .filter(|issue| issue.contains("budget exhausted"))
        .count();
    assert_eq!(exhausted, 1, "{:?}", report.issues);
}
