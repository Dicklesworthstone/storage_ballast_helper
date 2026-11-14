//! Opt-in integration tests for a disposable, uncompressed Btrfs mount.
//! Run as root with SBH_BTRFS_TEST_ROOT set and `cargo test -- --ignored`.
//! No existing file is overwritten: every fixture uses create_dir/create_new.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sbh_btrfs::{
    FileStamp, IdleIoPriority, ZstdConsent, compress_range, discovery_exclusion, inspect, is_btrfs,
    raw_ranges, reclaim_evidence,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn fixture() -> (PathBuf, Vec<u8>, File) {
    fixture_with((0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect())
}

fn fixture_with(bytes: Vec<u8>) -> (PathBuf, Vec<u8>, File) {
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
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    assert!(is_btrfs(&file).unwrap(), "fixture must be Btrfs");
    (path, bytes, file)
}

/// Each FIEMAP extent's (logical, length, flags) as `filefrag -v` sees it,
/// for failure messages: discovery reads FIEMAP, `inspect` the extent tree.
fn fiemap_now(path: &std::path::Path) -> String {
    let output = Command::new("filefrag").arg("-v").arg(path).output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(error) => format!("filefrag unavailable: {error}"),
    }
}

/// The longest run of raw (unencoded) bytes FIEMAP reports. Each lone block
/// btrfs leaves uncompressed is one sector; adjacent ones would merge here.
fn largest_raw_range(file: &File, size: u64) -> u64 {
    raw_ranges(file, 0, size, deadline())
        .unwrap()
        .iter()
        .map(|range| range.1)
        .max()
        .unwrap_or(0)
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
    assert_eq!(discovery_exclusion(&file, deadline()).unwrap(), None);
    let priority = IdleIoPriority::enter().unwrap();
    let mut admissions = 0;
    compress_range(
        &file,
        0,
        stamp.size,
        before.inode_flags,
        consent(),
        deadline(),
        &mut || {
            admissions += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(admissions, 1, "one admission starts the bounded range");
    priority.restore().unwrap();
    let after = inspect(&file, deadline()).unwrap();
    assert!(stamp.same_contents_and_identity(after.stamp));
    assert!(after.physical_data_bytes < before.physical_data_bytes / 2);
    assert_eq!(
        after.exclusion(),
        Some("already_encoded_or_compressed"),
        "{after:?}; FIEMAP now: {}",
        fiemap_now(&path)
    );
    // Discovery reads FIEMAP, which cannot tell a lone raw block (btrfs never
    // compresses one sector; each commit landing mid-defrag can split one off,
    // about 1 run in 80 under forced commits, twice in one run under a parallel
    // suite) from a bookend into a raw allocation. It may keep such a file for
    // the executor, whose inspection (asserted above) excludes it.
    let discovery = discovery_exclusion(&file, deadline()).unwrap();
    let largest_raw = largest_raw_range(&file, stamp.size);
    assert!(
        discovery == Some("already_compressed_extents")
            || (discovery.is_none() && largest_raw <= file.metadata().unwrap().blksize()),
        "discovery {discovery:?} with a {largest_raw}-byte raw range; FIEMAP now: {}",
        fiemap_now(&path)
    );
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
fn revoked_authority_after_native_preparation_leaves_every_extent_unchanged() {
    let (path, bytes, file) = fixture();
    let before = inspect(&file, deadline()).unwrap();
    assert_eq!(before.exclusion(), None);
    let mut admissions = 0;
    let error = compress_range(
        &file,
        0,
        before.stamp.size,
        before.inode_flags,
        consent(),
        deadline(),
        &mut || {
            admissions += 1;
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "the daemon revoked this range while native checks ran",
            ))
        },
    )
    .unwrap_err();
    assert_eq!(
        admissions, 1,
        "the final gate follows successful native checks"
    );
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    let after = inspect(&file, deadline()).unwrap();
    assert_eq!(after.stamp, before.stamp);
    assert_eq!(after.extents, before.extents);
    assert_eq!(after.physical_data_bytes, before.physical_data_bytes);
    assert_eq!(after.inode_flags, before.inode_flags);
    assert_eq!(fs::read(&path).unwrap(), bytes);
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
    assert_eq!(
        discovery_exclusion(&file, deadline()).unwrap(),
        Some("shared_or_reflinked_extents")
    );
    assert!(
        compress_range(
            &file,
            0,
            before.stamp.size,
            before.inode_flags,
            consent(),
            deadline(),
            &mut || panic!("shared extents must be refused before mutation admission"),
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read(&clone).unwrap(), bytes);
    assert_eq!(
        inspect(&file, deadline()).unwrap().physical_data_bytes,
        before.physical_data_bytes
    );
}

/// FS_NOCOMP_FL (`m` in lsattr).
const FS_NOCOMP_FL: u32 = 0x400;

#[test]
#[ignore = "requires an explicitly supplied disposable Btrfs mount and root"]
fn an_incompressible_range_marks_the_file_but_does_not_stop_the_rest() {
    // 1 MiB of xorshift noise (zstd cannot shrink it), then 3 MiB that it can.
    let noise: u64 = 1024 * 1024;
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut bytes: Vec<u8> = (0..noise)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();
    bytes.extend((0..3 * 1024 * 1024).map(|i| (i % 251) as u8));
    let (path, bytes, file) = fixture_with(bytes);
    let before = inspect(&file, deadline()).unwrap();
    assert_eq!(before.exclusion(), None);
    compress_range(
        &file,
        0,
        noise,
        before.inode_flags,
        consent(),
        deadline(),
        &mut || Ok(()),
    )
    .unwrap();
    let marked = inspect(&file, deadline()).unwrap();
    assert_ne!(
        marked.inode_flags & FS_NOCOMP_FL,
        0,
        "btrfs marks an inode whose range came out no smaller"
    );
    let rest = before.stamp.size - noise;
    // A flag the file already had when inspected is respected...
    assert!(
        compress_range(
            &file,
            noise,
            rest,
            marked.inode_flags,
            consent(),
            deadline(),
            &mut || Ok(()),
        )
        .is_err()
    );
    // ...one its own earlier range set is not: the rest is still compressed.
    compress_range(
        &file,
        noise,
        rest,
        before.inode_flags,
        consent(),
        deadline(),
        &mut || Ok(()),
    )
    .unwrap();
    let after = inspect(&file, deadline()).unwrap();
    assert!(after.encoded, "the compressible remainder was compressed");
    assert!(after.physical_data_bytes < before.physical_data_bytes);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(before.stamp.same_contents_and_identity(after.stamp));
    // The flag stays, so later passes skip the file instead of rewriting the
    // incompressible megabyte again.
    assert_eq!(
        after.exclusion(),
        Some("nocow_nocompress_immutable_or_append_only")
    );
    assert_eq!(
        discovery_exclusion(&file, deadline()).unwrap(),
        Some("nocow_nocompress_immutable_or_append_only")
    );
}

#[test]
#[ignore = "requires an explicitly supplied disposable Btrfs mount and root"]
fn a_committed_large_extent_is_compressed_completely() {
    // 3110b29: on a large raw extent that a transaction had already
    // committed, one DEFRAG_RANGE per 16 MiB chunk compressed only the first
    // 256 KiB. The raw remainder kept the whole original allocation, so the
    // file used more space than before. fsync goes through the log tree and
    // hides this, so commit the transaction before compressing.
    let (path, bytes, file) =
        fixture_with((0..24 * 1024 * 1024).map(|i| (i % 251) as u8).collect());
    let committed = Command::new("btrfs")
        .args(["filesystem", "sync"])
        .arg(path.parent().unwrap())
        .status()
        .unwrap();
    assert!(committed.success(), "btrfs filesystem sync: {committed}");
    let before = inspect(&file, deadline()).unwrap();
    assert_eq!(before.exclusion(), None);
    assert!(before.raw && !before.encoded, "{before:?}");
    // The executor's chunking: at most 16 MiB per range.
    let chunk = 16 * 1024 * 1024;
    let mut offset = 0;
    while offset < before.stamp.size {
        let length = chunk.min(before.stamp.size - offset);
        compress_range(
            &file,
            offset,
            length,
            before.inode_flags,
            consent(),
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
        offset += length;
    }
    let after = inspect(&file, deadline()).unwrap();
    assert!(after.encoded && !after.raw, "raw ranges remain: {after:?}");
    assert!(
        after.physical_data_bytes < before.physical_data_bytes / 4,
        "{} -> {} bytes",
        before.physical_data_bytes,
        after.physical_data_bytes
    );
    assert!(before.stamp.same_contents_and_identity(after.stamp));
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
#[ignore = "requires an explicitly supplied disposable Btrfs mount and root"]
fn a_lone_raw_tail_block_leaves_a_compressed_file_excluded() {
    // Btrfs compresses in 128 KiB chunks and never compresses a final chunk
    // of one sector or less, so these files keep their last block raw. That
    // block kept them eligible, and every pass re-hashed them and rewrote it
    // for nothing (bd-rxq5).
    for tail in [1_u64, 4096] {
        let size = 4 * 1024 * 1024 + tail;
        let (path, bytes, file) = fixture_with((0..size).map(|i| (i % 251) as u8).collect());
        let before = inspect(&file, deadline()).unwrap();
        assert_eq!(before.exclusion(), None);
        compress_range(
            &file,
            0,
            size,
            before.inode_flags,
            consent(),
            deadline(),
            &mut || Ok(()),
        )
        .unwrap();
        let after = inspect(&file, deadline()).unwrap();
        let largest_raw = largest_raw_range(&file, size);
        assert!(
            largest_raw <= file.metadata().unwrap().blksize(),
            "tail {tail}: a {largest_raw}-byte raw range; FIEMAP: {}",
            fiemap_now(&path)
        );
        assert!(after.encoded && !after.raw, "tail {tail}: {after:?}");
        assert_eq!(
            after.exclusion(),
            Some("already_encoded_or_compressed"),
            "tail {tail}"
        );
        assert!(after.physical_data_bytes < before.physical_data_bytes / 4);
        assert!(before.stamp.same_contents_and_identity(after.stamp));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}
