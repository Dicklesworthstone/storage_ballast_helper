use super::*;
use std::time::Duration;

fn regular_item(bytenr: u64, disk_bytes: u64, logical_bytes: u64, compression: u8) -> Vec<u8> {
    let mut item = vec![0; 53];
    item[8..16].copy_from_slice(&logical_bytes.to_le_bytes());
    item[16] = compression;
    item[20] = 1;
    item[21..29].copy_from_slice(&bytenr.to_le_bytes());
    item[29..37].copy_from_slice(&disk_bytes.to_le_bytes());
    item[45..53].copy_from_slice(&logical_bytes.to_le_bytes());
    item
}

fn eligible_map() -> ExtentMap {
    ExtentMap {
        stamp: FileStamp {
            device: 1,
            inode: 256,
            size: 131_072,
            mtime: 1,
            mtime_nsec: 2,
            ctime: 3,
            ctime_nsec: 4,
            links: 1,
        },
        extents: vec![DataExtent {
            bytenr: 1_048_576,
            disk_num_bytes: 131_072,
        }],
        physical_data_bytes: 131_072,
        inline_bytes: 0,
        fiemap_flags: ioctl::FIEMAP_EXTENT_LAST,
        inode_flags: 0,
        encoded: false,
        raw: true,
        foreign_encoding: false,
        preallocated: false,
    }
}

#[test]
fn compressed_disk_length_is_not_the_logical_or_ram_length() {
    let parsed = parse_file_extent(&regular_item(1_048_576, 4096, 131_072, 3)).unwrap();
    assert_eq!(
        parsed.extent,
        Some(DataExtent {
            bytenr: 1_048_576,
            disk_num_bytes: 4096
        })
    );
    assert!(parsed.encoded);
    assert_eq!(parsed.inline_bytes, 0);
}

#[test]
fn holes_and_inline_items_are_distinct_from_data_allocations() {
    assert_eq!(
        parse_file_extent(&regular_item(0, 0, 131_072, 0))
            .unwrap()
            .extent,
        None
    );
    let mut inline = vec![0; 21 + 37];
    inline[16] = 3;
    let parsed = parse_file_extent(&inline).unwrap();
    assert_eq!(parsed.inline_bytes, 37);
    assert_eq!(parsed.extent, None);
    assert!(parsed.encoded);
}

#[test]
fn truncated_unknown_and_overflowing_extent_items_are_rejected() {
    let item = regular_item(1_048_576, 4096, 131_072, 0);
    for length in 0..item.len() {
        assert!(
            parse_file_extent(&item[..length]).is_err(),
            "length={length}"
        );
    }
    let mut unknown = item.clone();
    unknown[20] = 9;
    assert!(parse_file_extent(&unknown).is_err());
    assert!(parse_file_extent(&regular_item(1, 0, 131_072, 0)).is_err());
    assert!(parse_file_extent(&regular_item(0, 4096, 131_072, 0)).is_err());
    assert!(parse_file_extent(&regular_item(u64::MAX, 4096, 131_072, 0)).is_err());
}

#[test]
fn all_unknown_or_unsafe_fiemap_bits_fail_closed() {
    assert_eq!(eligible_map().exclusion(), None);
    // ENCODED is the one bit with a rule of its own, below.
    for bit in (1..32).filter(|&bit| 1 << bit != ioctl::FIEMAP_EXTENT_ENCODED) {
        let mut map = eligible_map();
        map.fiemap_flags |= 1 << bit;
        assert!(map.exclusion().is_some(), "bit {bit} was accepted");
    }
    let mut shared = eligible_map();
    shared.fiemap_flags |= ioctl::FIEMAP_EXTENT_SHARED;
    assert_eq!(shared.exclusion(), Some("shared_or_reflinked_extents"));
}

/// A file compressed in full is done. One a pass stopped inside still holds
/// raw data next to compressed ranges, and stays eligible so a later pass
/// finishes it: left alone, it uses more space than before (bd-rxq5).
#[test]
fn a_part_compressed_file_stays_eligible_and_a_compressed_one_does_not() {
    let mut partial = eligible_map();
    partial.encoded = true;
    partial.fiemap_flags |= ioctl::FIEMAP_EXTENT_ENCODED;
    assert_eq!(partial.exclusion(), None);

    let mut done = partial.clone();
    done.raw = false;
    assert_eq!(done.exclusion(), Some("already_encoded_or_compressed"));
    // FIEMAP alone saying ENCODED, with no raw extent, is done too.
    let mut flagged = eligible_map();
    flagged.raw = false;
    flagged.fiemap_flags |= ioctl::FIEMAP_EXTENT_ENCODED;
    assert_eq!(flagged.exclusion(), Some("already_encoded_or_compressed"));

    // Encryption or another encoding is never touched, raw data or not.
    let mut foreign = partial;
    foreign.foreign_encoding = true;
    assert_eq!(foreign.exclusion(), Some("encrypted_or_foreign_encoding"));
}

#[test]
fn encryption_and_other_encodings_are_told_apart_from_compression() {
    let compressed = parse_file_extent(&regular_item(1_048_576, 4096, 131_072, 3)).unwrap();
    assert!(compressed.encoded && !compressed.foreign_encoding);
    let mut encrypted = regular_item(1_048_576, 131_072, 131_072, 0);
    encrypted[17] = 1;
    let encrypted = parse_file_extent(&encrypted).unwrap();
    assert!(encrypted.encoded && encrypted.foreign_encoding);
    let raw = parse_file_extent(&regular_item(1_048_576, 131_072, 131_072, 0)).unwrap();
    assert!(!raw.encoded && !raw.foreign_encoding);
}

#[test]
fn policy_never_overrides_nocow_hardlinks_or_preallocation() {
    for flag in [0x10, 0x20, 0x400, 0x0080_0000] {
        let mut map = eligible_map();
        map.inode_flags = flag;
        assert!(map.exclusion().is_some());
    }
    for links in [0, 2, 10] {
        let mut map = eligible_map();
        map.stamp.links = links;
        assert!(map.exclusion().is_some());
    }
    let mut map = eligible_map();
    map.preallocated = true;
    assert_eq!(map.exclusion(), Some("preallocated_extents"));
}

#[test]
fn compression_requests_are_finite_aligned_and_inside_the_file() {
    assert!(validate_range(0, MAX_CHUNK_BYTES, MAX_CHUNK_BYTES).is_ok());
    assert!(validate_range(4096, 123, 4219).is_ok());
    for (start, length, size) in [
        (0, 0, 1),
        (0, MAX_CHUNK_BYTES + 1, u64::MAX),
        (1, 4096, 8192),
        (4096, 4096, 5000),
        (u64::MAX - 4095, 4096, u64::MAX),
    ] {
        assert!(validate_range(start, length, size).is_err());
    }
}

#[test]
fn size_and_mtime_changes_invalidate_reclaim_attribution() {
    let before = eligible_map().stamp;
    let mut after = before;
    after.ctime += 1;
    assert!(before.same_contents_and_identity(after));
    after.size += 1;
    assert!(!before.same_contents_and_identity(after));
    after = before;
    after.mtime_nsec += 1;
    assert!(!before.same_contents_and_identity(after));
    after = before;
    after.inode += 1;
    assert!(!before.same_contents_and_identity(after));
}

#[test]
fn budgets_and_byte_sums_cannot_wrap() {
    assert!(check_deadline(Instant::now()).is_err());
    assert!(check_deadline(Instant::now() + Duration::from_secs(10)).is_ok());
    assert_eq!(checked_sum([4096, 8192].into_iter()).unwrap(), 12_288);
    assert!(checked_sum([u64::MAX, 1].into_iter()).is_err());
}
