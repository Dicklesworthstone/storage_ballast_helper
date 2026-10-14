//! Opt-in integration tests for a disposable, uncompressed Btrfs mount.
//! Run as root with SBH_BTRFS_TEST_ROOT set and `cargo test -- --ignored`.
//! No existing file is overwritten: every fixture uses create_dir/create_new.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbh_btrfs::{
    FileStamp, IdleIoPriority, ZstdConsent, compress_range, inspect, is_btrfs, reclaim_evidence,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn fixture() -> (PathBuf, Vec<u8>, File) {
    let root = PathBuf::from(
        std::env::var_os("SBH_BTRFS_TEST_ROOT")
            .expect("set SBH_BTRFS_TEST_ROOT to a disposable Btrfs mount"),
    );
    let dir = root.join(format!(
        "sbh-compress-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("cold.bin");
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let bytes: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    assert!(is_btrfs(&file).unwrap(), "fixture must be Btrfs");
    (path, bytes, file)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(120)
}
fn consent() -> ZstdConsent {
    ZstdConsent::acknowledge_filesystem_compatibility_change()
}

#[test]
#[ignore = "requires an explicitly supplied disposable Btrfs mount and root"]
fn native_compression_preserves_every_byte_size_and_mtime() {
    let (path, bytes, file) = fixture();
    let stamp = FileStamp::read(&file).unwrap();
    let before = inspect(&file, deadline()).unwrap();
    assert_eq!(
        before.exclusion(),
        None,
        "mount must not enable automatic compression"
    );
    let priority = IdleIoPriority::enter().unwrap();
    compress_range(&file, 0, stamp.size, consent(), deadline()).unwrap();
    priority.restore().unwrap();
    let after = inspect(&file, deadline()).unwrap();
    assert!(stamp.same_contents_and_identity(after.stamp));
    assert!(after.physical_data_bytes < before.physical_data_bytes / 2);
    let mut actual = Vec::new();
    File::open(&path).unwrap().read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    let evidence = reclaim_evidence(&file, &before, &after, deadline()).unwrap();
    assert_eq!(
        evidence.referenced_bytes_saved,
        before.physical_data_bytes - after.physical_data_bytes
    );
    assert!(evidence.confirmed_data_bytes_reclaimed <= evidence.referenced_bytes_saved);
    // Keep the runner-owned fixture for diagnostics. CI unmounts its disposable
    // filesystem; this test never recursively deletes an operator-supplied path.
}

#[test]
#[ignore = "requires an explicitly supplied disposable Btrfs mount and root"]
fn reflinked_files_are_rejected_without_modifying_either_copy() {
    let (path, bytes, file) = fixture();
    let clone = path.with_file_name("reflink.bin");
    assert!(
        Command::new("cp")
            .arg("--reflink=always")
            .arg("--")
            .arg(&path)
            .arg(&clone)
            .status()
            .unwrap()
            .success()
    );
    file.sync_all().unwrap();
    let before = inspect(&file, deadline()).unwrap();
    assert_eq!(before.exclusion(), Some("shared_or_reflinked_extents"));
    assert!(compress_range(&file, 0, before.stamp.size, consent(), deadline()).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read(&clone).unwrap(), bytes);
    assert_eq!(
        inspect(&file, deadline()).unwrap().physical_data_bytes,
        before.physical_data_bytes
    );
}
