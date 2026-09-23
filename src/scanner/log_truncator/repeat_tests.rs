//! Real-file coverage for repeat admission; no sleeps or permission assumptions.

#![cfg(unix)]

use super::*;
use std::cell::Cell;
use std::io::{Seek, SeekFrom, Write};

fn config(path: &Path) -> LogTruncationConfig {
    LogTruncationConfig {
        enabled: true,
        paths: vec![path.to_string_lossy().into_owned()],
        min_size_bytes: 16,
        pressure_free_pct_ceiling: 100,
        min_age_minutes: 0,
    }
}

fn run(
    path: &Path,
    config: &LogTruncationConfig,
    history: &Mutex<RecentTruncations>,
    now: Instant,
    dry_run: bool,
) -> Outcome {
    process_candidate_with_history(
        path,
        config,
        true,
        dry_run,
        open_candidate_for_truncate,
        history,
        || now,
    )
    .unwrap()
}

fn ambiguous_refill(path: &Path) {
    // The nonzero tail allocates at least one block even when the preceding
    // zero-filled range is represented as a hole.
    let mut bytes = vec![0; 4096];
    bytes.extend_from_slice(b"fresh");
    fs::write(path, bytes).unwrap();
}

#[test]
fn ambiguous_zero_prefix_regrowth_waits_without_sliding_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("active.log");
    fs::write(&path, vec![b'x'; 4096]).unwrap();
    let config = config(&path);
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
    ambiguous_refill(&path);
    for second in [0, 1, 30, 59] {
        let result = run(
            &path,
            &config,
            &history,
            now + Duration::from_secs(second),
            false,
        );
        assert!(matches!(
            result,
            Outcome::Skipped(SkipReason::RecentTruncation)
        ));
        assert_eq!(&fs::read(&path).unwrap()[4096..], b"fresh");
    }
    let result = run(&path, &config, &history, now + repeat::WINDOW, false);
    assert!(matches!(result, Outcome::Truncated(_)));
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
}

#[test]
fn genuinely_refilled_logs_can_reclaim_repeatedly_without_a_blind_cooldown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("busy.log");
    let config = config(&path);
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    for _ in 0..20 {
        fs::write(&path, vec![b'x'; 4096]).unwrap();
        assert!(matches!(
            run(&path, &config, &history, now, false),
            Outcome::Truncated(4096)
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }
}

#[test]
fn a_minimum_sized_new_tail_is_actionable_even_with_a_zero_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offset-writer.log");
    let mut writer = fs::File::create(&path).unwrap();
    writer.write_all(&vec![b'x'; 4096]).unwrap();
    writer.sync_all().unwrap();
    let mut config = config(&path);
    config.min_size_bytes = 1024;
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
    writer.write_all(&[b'y'; 1024]).unwrap();
    writer.sync_all().unwrap();
    assert_eq!(writer.stream_position().unwrap(), 5120);
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
    assert_eq!(writer.metadata().unwrap().len(), 0);
}

#[test]
fn dry_runs_do_not_consume_or_clear_post_truncation_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dry.log");
    fs::write(&path, vec![b'x'; 4096]).unwrap();
    let config = config(&path);
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    assert!(matches!(
        run(&path, &config, &history, now, true),
        Outcome::WouldTruncate(_)
    ));
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
    ambiguous_refill(&path);
    assert!(matches!(
        run(&path, &config, &history, now, true),
        Outcome::WouldTruncate(_)
    ));
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Skipped(SkipReason::RecentTruncation)
    ));
    assert_eq!(&fs::read(&path).unwrap()[4096..], b"fresh");
}

#[test]
fn an_in_flight_file_does_not_block_an_independent_log() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.log");
    let b = dir.path().join("b.log");
    fs::write(&a, vec![b'a'; 4096]).unwrap();
    fs::write(&b, vec![b'b'; 4096]).unwrap();
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    let held = RecentTruncations::acquire(&history, &a, &fs::metadata(&a).unwrap(), now).unwrap();
    assert!(matches!(
        run(&a, &config(&a), &history, now, false),
        Outcome::Skipped(SkipReason::RecentTruncation)
    ));
    assert!(matches!(
        run(&b, &config(&b), &history, now, false),
        Outcome::Truncated(_)
    ));
    assert_eq!(fs::metadata(&a).unwrap().len(), 4096);
    drop(held);
    assert!(matches!(
        run(&a, &config(&a), &history, now, false),
        Outcome::Truncated(_)
    ));
}

#[test]
fn a_replacement_file_does_not_inherit_the_old_inodes_recovery_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rotated.log");
    fs::write(&path, vec![b'x'; 4096]).unwrap();
    let config = config(&path);
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
    // Keep the old inode alive; do not depend on inode recycling behavior.
    fs::rename(&path, dir.path().join("previous.log")).unwrap();
    ambiguous_refill(&path);
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
}

#[test]
fn failed_truncation_releases_its_reservation_without_recording_success() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("read-only-fd.log");
    fs::write(&path, vec![b'x'; 4096]).unwrap();
    let config = config(&path);
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    // Root cannot bypass a read-only descriptor's access mode.
    let failed = process_candidate_with_history(
        &path,
        &config,
        true,
        false,
        |path| fs::File::open(path).map_err(|error| error.to_string()),
        &history,
        || now,
    );
    assert!(failed.is_err());
    assert_eq!(fs::metadata(&path).unwrap().len(), 4096);
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
}

#[test]
fn prefix_evidence_must_come_from_the_inspected_inode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.log");
    fs::write(&path, vec![b'x'; 4096]).unwrap();
    let meta = fs::metadata(&path).unwrap();
    fs::rename(&path, dir.path().join("held-original.log")).unwrap();
    fs::write(&path, vec![b'y'; 4096]).unwrap();
    assert!(!has_new_log_data(&path, &meta, 4096, 16));
    assert_eq!(fs::read(&path).unwrap(), vec![b'y'; 4096]);
}

#[test]
fn a_non_append_writer_keeps_its_offset_and_fresh_tail_during_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("non-append.log");
    let mut writer = fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    writer.write_all(&vec![b'x'; 4096]).unwrap();
    writer.sync_all().unwrap();
    let config = config(&path);
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    assert!(matches!(
        run(&path, &config, &history, now, false),
        Outcome::Truncated(_)
    ));
    writer.write_all(b"fresh").unwrap();
    writer.sync_all().unwrap();
    let result = run(&path, &config, &history, now, false);
    assert!(matches!(
        result,
        Outcome::Skipped(SkipReason::RecentTruncation)
    ));
    writer.seek(SeekFrom::Start(4096)).unwrap();
    let mut tail = String::new();
    writer.read_to_string(&mut tail).unwrap();
    assert_eq!(tail, "fresh");
}

#[test]
fn a_file_shrunk_before_reservation_is_rechecked_without_crediting_old_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.log");
    fs::write(&path, vec![b'x'; 4096]).unwrap();
    let config = config(&path);
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    let changed = Cell::new(false);
    let result = process_candidate_with_history(
        &path,
        &config,
        true,
        false,
        open_candidate_for_truncate,
        &history,
        || {
            if !changed.replace(true) {
                // Another sweep finished after metadata inspection, and its
                // writer has produced only one fresh byte since then.
                fs::write(&path, b"x").unwrap();
            }
            now
        },
    )
    .unwrap();
    assert!(matches!(result, Outcome::Skipped(SkipReason::BelowMinSize)));
    assert_eq!(fs::read(&path).unwrap(), b"x");
}

#[test]
fn a_file_refreshed_before_reservation_still_obeys_the_age_gate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("refreshed.log");
    fs::write(&path, vec![b'x'; 4096]).unwrap();
    let old = SystemTime::now() - Duration::from_secs(7200);
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(old)).unwrap();
    let mut config = config(&path);
    config.min_age_minutes = 60;
    let history = Mutex::new(RecentTruncations::default());
    let now = Instant::now();
    let result = process_candidate_with_history(
        &path,
        &config,
        false,
        false,
        open_candidate_for_truncate,
        &history,
        || {
            filetime::set_file_mtime(
                &path,
                filetime::FileTime::from_system_time(SystemTime::now()),
            )
            .unwrap();
            now
        },
    )
    .unwrap();
    assert!(matches!(
        result,
        Outcome::Skipped(SkipReason::YoungerThanMinAge)
    ));
    assert_eq!(fs::metadata(&path).unwrap().len(), 4096);
}
