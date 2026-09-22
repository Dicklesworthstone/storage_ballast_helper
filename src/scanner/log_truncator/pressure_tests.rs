//! Filesystem and injected-failure regressions for active-log reclamation.

#![cfg(unix)]

use super::*;
use std::cell::Cell;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;

fn config(paths: &[PathBuf]) -> LogTruncationConfig {
    LogTruncationConfig {
        enabled: true,
        paths: paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        min_size_bytes: 1024,
        pressure_free_pct_ceiling: 15,
        min_age_minutes: 0,
    }
}

fn log(path: &Path) {
    fs::write(path, vec![b'x'; 4096]).unwrap();
}

#[test]
fn failed_paths_back_off_but_independent_logs_keep_reclaiming() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.log");
    let good = dir.path().join("good.log");
    log(&bad);
    log(&good);
    let config = config(&[bad.clone(), good.clone()]);
    let backoff = Mutex::new(FailureBackoff::default());
    let now = Instant::now();
    let first = truncate_with_backoff(
        &config,
        1.0,
        false,
        &backoff,
        || now,
        |path, cfg, age, dry| {
            if path == bad.as_path() {
                Err("injected read-only filesystem".to_string())
            } else {
                process_candidate(path, cfg, age, dry)
            }
        },
    );
    assert_eq!(first.errors.len(), 1);
    assert_eq!(first.files_truncated, 1);
    assert_eq!(fs::metadata(&bad).unwrap().len(), 4096);
    for second in 1..60 {
        log(&good);
        let report = truncate_with_backoff(
            &config,
            0.0,
            false,
            &backoff,
            || now + Duration::from_secs(second),
            process_candidate,
        );
        assert!(report.errors.is_empty());
        assert_eq!(report.files_truncated, 1);
        assert_eq!(
            report.skipped_with_reason,
            vec![(bad.clone(), SkipReason::FailureBackoff)]
        );
        assert_eq!(fs::metadata(&bad).unwrap().len(), 4096);
    }
    let retry = truncate_with_backoff(
        &config,
        0.0,
        false,
        &backoff,
        || now + backoff::RETRY_INTERVAL,
        process_candidate,
    );
    assert_eq!(retry.files_truncated, 1);
    assert_eq!(fs::metadata(&bad).unwrap().len(), 0);
    assert!(retry.errors.is_empty());
}

#[test]
fn a_slow_failure_gets_a_full_cooldown_after_it_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slow.log");
    log(&path);
    let config = config(std::slice::from_ref(&path));
    let backoff = Mutex::new(FailureBackoff::default());
    let now = Instant::now();
    let clock = Cell::new(now);
    let report = truncate_with_backoff(
        &config,
        0.0,
        false,
        &backoff,
        || clock.get(),
        |_, _, _, _| {
            clock.set(now + Duration::from_secs(300));
            Err("injected slow I/O failure".to_string())
        },
    );
    assert_eq!(report.errors.len(), 1);
    let cooling = truncate_with_backoff(
        &config,
        0.0,
        false,
        &backoff,
        || now + Duration::from_secs(359),
        process_candidate,
    );
    assert_eq!(cooling.files_truncated, 0);
    assert!(cooling.errors.is_empty());
    let retry = truncate_with_backoff(
        &config,
        0.0,
        false,
        &backoff,
        || now + Duration::from_secs(360),
        process_candidate,
    );
    assert_eq!(retry.files_truncated, 1);
}

#[test]
fn dry_run_ignores_cooldown_without_clearing_or_creating_failures() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("held.log");
    log(&path);
    let config = config(std::slice::from_ref(&path));
    let backoff = Mutex::new(FailureBackoff::default());
    let now = Instant::now();
    let key = FailureKey::Candidate(path.clone());
    backoff.lock().failed(key.clone(), now);
    let dry = truncate_with_backoff(&config, 0.0, true, &backoff, || now, process_candidate);
    assert_eq!(dry.files_would_truncate, 1);
    assert_eq!(dry.bytes_would_reclaim, 4096);
    assert!(backoff.lock().blocked(&key, now));
    assert_eq!(fs::metadata(&path).unwrap().len(), 4096);

    let empty = Mutex::new(FailureBackoff::default());
    let failed_dry = truncate_with_backoff(
        &config,
        0.0,
        true,
        &empty,
        || now,
        |_, _, _, _| Err("injected inspection failure".to_string()),
    );
    assert_eq!(failed_dry.errors.len(), 1);
    assert!(!empty.lock().blocked(&key, now));
    let actual = truncate_with_backoff(&config, 0.0, false, &empty, || now, process_candidate);
    assert_eq!(actual.files_truncated, 1);
}

#[test]
fn invalid_patterns_back_off_without_suppressing_valid_patterns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("good.log");
    log(&path);
    let config = config(&[PathBuf::from("relative.log"), path.clone()]);
    let backoff = Mutex::new(FailureBackoff::default());
    let now = Instant::now();
    let first = truncate_with_backoff(&config, 0.0, false, &backoff, || now, process_candidate);
    assert_eq!(first.errors.len(), 1);
    assert_eq!(first.files_truncated, 1);
    log(&path);
    let second = truncate_with_backoff(&config, 0.0, false, &backoff, || now, process_candidate);
    assert!(second.errors.is_empty());
    assert_eq!(second.files_truncated, 1);
    assert_eq!(
        second.skipped_with_reason,
        vec![(PathBuf::from("relative.log"), SkipReason::FailureBackoff)]
    );
}

#[test]
fn overlapping_patterns_visit_each_path_once_including_dry_run_and_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("one.log");
    log(&path);
    let config = config(&[path.clone(), dir.path().join("*.log"), path]);
    let dry = truncate_oversized_logs(&config, 0.0, true);
    assert_eq!(dry.files_would_truncate, 1);
    assert_eq!(dry.bytes_would_reclaim, 4096);
    let backoff = Mutex::new(FailureBackoff::default());
    let calls = Cell::new(0);
    let report = truncate_with_backoff(
        &config,
        0.0,
        false,
        &backoff,
        Instant::now,
        |_, _, _, _| {
            calls.set(calls.get() + 1);
            Err("injected failure".to_string())
        },
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.files_skipped, 1);
}

#[test]
fn replaced_regular_file_is_never_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rotating.log");
    let old = dir.path().join("old.log");
    log(&path);
    let config = config(std::slice::from_ref(&path));
    let outcome = process_candidate_with_opener(&path, &config, true, false, |path| {
        fs::rename(path, &old).unwrap();
        fs::write(path, b"replacement data must survive").unwrap();
        open_candidate_for_truncate(path)
    })
    .unwrap();
    assert!(matches!(outcome, Outcome::Skipped(SkipReason::IdentityChanged)));
    assert_eq!(fs::read(&path).unwrap(), b"replacement data must survive");
    assert_eq!(fs::metadata(&old).unwrap().len(), 4096);
}

#[test]
fn a_replaced_parent_directory_cannot_redirect_the_open_to_another_inode() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("logs");
    let moved = dir.path().join("moved");
    fs::create_dir(&parent).unwrap();
    let path = parent.join("active.log");
    log(&path);
    let config = config(std::slice::from_ref(&path));
    let outcome = process_candidate_with_opener(&path, &config, true, false, |path| {
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        log(path);
        open_candidate_for_truncate(path)
    })
    .unwrap();
    assert!(matches!(outcome, Outcome::Skipped(SkipReason::IdentityChanged)));
    assert_eq!(fs::metadata(&path).unwrap().len(), 4096);
    assert_eq!(fs::metadata(moved.join("active.log")).unwrap().len(), 4096);
}

#[test]
fn a_log_that_shrinks_while_opening_is_rechecked_before_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shrinking.log");
    log(&path);
    let config = config(std::slice::from_ref(&path));
    let outcome = process_candidate_with_opener(&path, &config, true, false, |path| {
        let file = open_candidate_for_truncate(path)?;
        file.set_len(8).unwrap();
        Ok(file)
    })
    .unwrap();
    assert!(matches!(outcome, Outcome::Skipped(SkipReason::BelowMinSize)));
    assert_eq!(fs::read(&path).unwrap(), b"xxxxxxxx");
}

#[test]
fn the_age_gate_is_rechecked_on_the_opened_inode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("refreshing.log");
    log(&path);
    let old = SystemTime::now() - Duration::from_secs(7200);
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(old)).unwrap();
    let mut config = config(std::slice::from_ref(&path));
    config.min_age_minutes = 60;
    let outcome = process_candidate_with_opener(&path, &config, false, false, |path| {
        let updated = filetime::FileTime::from_system_time(SystemTime::now());
        filetime::set_file_mtime(path, updated).unwrap();
        open_candidate_for_truncate(path)
    })
    .unwrap();
    assert!(matches!(outcome, Outcome::Skipped(SkipReason::YoungerThanMinAge)));
    assert_eq!(fs::metadata(&path).unwrap().len(), 4096);
}

#[test]
fn future_mtime_is_not_mistaken_for_an_old_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.log");
    log(&path);
    let future = SystemTime::now() + Duration::from_secs(7200);
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(future)).unwrap();
    let mut config = config(std::slice::from_ref(&path));
    config.min_age_minutes = 60;
    let report = truncate_oversized_logs(&config, 80.0, false);
    assert_eq!(report.files_truncated, 0);
    assert_eq!(
        report.skipped_with_reason,
        vec![(path, SkipReason::YoungerThanMinAge)]
    );
}

#[test]
fn sparse_logs_are_gated_and_accounted_by_allocated_bytes_not_holes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sparse.log");
    let mut writer = fs::File::create(&path).unwrap();
    writer.seek(SeekFrom::Start(1 << 30)).unwrap();
    writer.write_all(&[b'x'; 4096]).unwrap();
    writer.sync_all().unwrap();
    let meta = writer.metadata().unwrap();
    let allocated = meta.blocks().saturating_mul(512);
    assert!(allocated < 1 << 20, "fixture must be sparse: {allocated}");
    let mut config = config(std::slice::from_ref(&path));
    config.min_size_bytes = 16 << 20;
    let report = truncate_oversized_logs(&config, 0.0, false);
    assert_eq!(report.files_truncated, 0);
    assert_eq!(report.bytes_reclaimed, 0);
    assert_eq!(fs::metadata(&path).unwrap().len(), meta.len());
    config.min_size_bytes = 1;
    let dry = truncate_oversized_logs(&config, 0.0, true);
    assert_eq!(dry.bytes_would_reclaim, allocated);
    let actual = truncate_oversized_logs(&config, 0.0, false);
    assert_eq!(actual.bytes_reclaimed, allocated);
    assert_eq!(writer.metadata().unwrap().len(), 0);
}

#[test]
fn a_live_non_append_writer_does_not_trigger_repeated_hole_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("active.log");
    let mut writer = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    writer.write_all(&vec![b'x'; 2 << 20]).unwrap();
    writer.sync_all().unwrap();
    let original = writer.metadata().unwrap();
    let mut config = config(std::slice::from_ref(&path));
    config.min_size_bytes = 1 << 20;
    let first = truncate_oversized_logs(&config, 0.0, false);
    assert_eq!(first.files_truncated, 1);
    assert_eq!(writer.metadata().unwrap().ino(), original.ino());
    writer.write_all(b"fresh").unwrap();
    writer.sync_all().unwrap();
    let second = truncate_oversized_logs(&config, 0.0, false);
    assert_eq!(second.files_truncated, 0);
    assert_eq!(second.bytes_reclaimed, 0);
    writer.seek(SeekFrom::Start(2 << 20)).unwrap();
    let mut fresh = String::new();
    writer.read_to_string(&mut fresh).unwrap();
    assert_eq!(fresh, "fresh");
}

#[test]
fn byte_estimates_saturate_instead_of_overflowing_the_report() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.log");
    let b = dir.path().join("b.log");
    log(&a);
    log(&b);
    let config = config(&[a, b]);
    let backoff = Mutex::new(FailureBackoff::default());
    let report = truncate_with_backoff(
        &config,
        0.0,
        true,
        &backoff,
        Instant::now,
        |_, _, _, _| Ok(Outcome::WouldTruncate(u64::MAX)),
    );
    assert_eq!(report.files_would_truncate, 2);
    assert_eq!(report.bytes_would_reclaim, u64::MAX);
}
