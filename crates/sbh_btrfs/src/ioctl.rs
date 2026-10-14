//! The complete unsafe boundary: fixed, initialized Linux UAPI buffers only.
//! Keep layouts in sync with linux/{btrfs,fiemap,fs}.h. No borrowed pointer is
//! retained by these ioctls, and no kernel-returned count is trusted unchecked.

use std::ffi::{c_int, c_long, c_ulong};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::time::Instant;

use crate::{MAX_EXTENTS, check_deadline, invalid};

pub(super) const FIEMAP_EXTENT_LAST: u32 = 0x0001;
pub(super) const FIEMAP_EXTENT_ENCODED: u32 = 0x0008;
pub(super) const FIEMAP_EXTENT_SHARED: u32 = 0x2000;
// FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NOCOMP_FL | FS_NOCOW_FL.
pub(super) const EXCLUDED_INODE_FLAGS: u32 = 0x10 | 0x20 | 0x400 | 0x0080_0000;

const fn request(direction: u32, kind: u8, number: u8, size: u32) -> c_ulong {
    ((direction << 30) | (size << 16) | ((kind as u32) << 8) | number as u32) as c_ulong
}

const GET_FEATURES: c_ulong = request(2, 0x94, 57, 24);
const GET_FLAGS: c_ulong = request(2, b'f', 1, 8);
const FIEMAP: c_ulong = request(3, b'f', 11, 32);
const TREE_SEARCH: c_ulong = request(3, 0x94, 17, 4096);
const DEFRAG_RANGE: c_ulong = request(1, 0x94, 16, 48);

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
}

// Private: every call below passes exactly the initialized UAPI structure for
// this request. For FIEMAP the structure includes the advertised trailing array.
fn call<T>(file: &File, operation: c_ulong, buffer: &mut T) -> io::Result<()> {
    // SAFETY: the descriptor is borrowed for the call, the exclusive buffer is
    // correctly sized/aligned for the request at each private call site, and
    // these synchronous ioctls do not retain its pointer after returning.
    let result = unsafe { ioctl(file.as_raw_fd(), operation, std::ptr::from_mut(buffer)) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn features(file: &File) -> io::Result<u64> {
    // compat_flags, compat_ro_flags, incompat_flags.
    let mut flags = [0_u64; 3];
    call(file, GET_FEATURES, &mut flags)?;
    Ok(flags[2])
}

pub(super) fn inode_flags(file: &File) -> io::Result<u32> {
    let mut flags: c_long = 0;
    call(file, GET_FLAGS, &mut flags)?;
    u32::try_from(flags).map_err(|_| invalid("unsupported inode flags"))
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FiemapExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}

const FIEMAP_BATCH: usize = 128;
#[repr(C)]
struct FiemapBuffer {
    start: u64,
    length: u64,
    flags: u32,
    mapped_extents: u32,
    extent_count: u32,
    reserved: u32,
    extents: [FiemapExtent; FIEMAP_BATCH],
}

pub(super) fn fiemap_flags(
    file: &File,
    start: u64,
    length: u64,
    deadline: Instant,
) -> io::Result<u32> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| invalid("FIEMAP range overflow"))?;
    let mut cursor = start;
    let mut total = 0_usize;
    let mut flags = 0_u32;
    while cursor < end {
        check_deadline(deadline)?;
        let mut buffer = FiemapBuffer {
            start: cursor,
            length: end - cursor,
            // No SYNC: an eligibility preview must not force dirty writes.
            // DELALLOC/UNKNOWN flags then conservatively exclude busy files.
            flags: 0,
            mapped_extents: 0,
            extent_count: FIEMAP_BATCH as u32,
            reserved: 0,
            extents: [FiemapExtent::default(); FIEMAP_BATCH],
        };
        call(file, FIEMAP, &mut buffer)?;
        let count = buffer.mapped_extents as usize;
        if count > FIEMAP_BATCH {
            return Err(invalid("kernel FIEMAP count exceeds buffer"));
        }
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| invalid("FIEMAP count overflow"))?;
        if total > MAX_EXTENTS {
            return Err(invalid("FIEMAP extent budget exceeded"));
        }
        let mut next = cursor;
        for (index, extent) in buffer.extents[..count].iter().enumerate() {
            let extent_end = extent
                .logical
                .checked_add(extent.length)
                .ok_or_else(|| invalid("FIEMAP extent offset overflow"))?;
            if extent.length == 0
                || extent.logical >= end
                || extent_end <= next
                || (index != 0 && extent.logical < next)
            {
                return Err(invalid("unordered or non-progressing FIEMAP"));
            }
            if extent.flags & FIEMAP_EXTENT_LAST != 0 && index + 1 != count {
                return Err(invalid("FIEMAP LAST precedes remaining entries"));
            }
            next = extent_end;
            flags |= extent.flags;
        }
        cursor = next;
        if flags & FIEMAP_EXTENT_LAST != 0 {
            break;
        }
    }
    Ok(flags)
}

#[repr(C)]
#[derive(Default)]
struct SearchKey {
    tree_id: u64,
    min_objectid: u64,
    max_objectid: u64,
    min_offset: u64,
    max_offset: u64,
    min_transid: u64,
    max_transid: u64,
    min_type: u32,
    max_type: u32,
    nr_items: u32,
    unused: u32,
    unused64: [u64; 4],
}

#[repr(C)]
struct SearchBuffer {
    key: SearchKey,
    bytes: [u8; 3992],
}

pub(super) fn visit_items(
    file: &File,
    tree: u64,
    object: u64,
    kind: u32,
    deadline: Instant,
    mut visit: impl FnMut(u64, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut cursor = 0_u64;
    let mut total = 0_usize;
    loop {
        check_deadline(deadline)?;
        let mut buffer = SearchBuffer {
            key: SearchKey {
                tree_id: tree,
                min_objectid: object,
                max_objectid: object,
                min_offset: cursor,
                max_offset: u64::MAX,
                max_transid: u64::MAX,
                min_type: kind,
                max_type: kind,
                nr_items: 128,
                ..SearchKey::default()
            },
            bytes: [0; 3992],
        };
        call(file, TREE_SEARCH, &mut buffer)?;
        let count = buffer.key.nr_items as usize;
        if count == 0 {
            return Ok(());
        }
        if count > 128 {
            return Err(invalid("kernel TREE_SEARCH count exceeds request"));
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| invalid("tree item count overflow"))?;
        if total > MAX_EXTENTS {
            return Err(invalid("tree item budget exceeded"));
        }
        let last = parse_search_page(&buffer.bytes, count, object, kind, cursor, &mut visit)?;
        let Some(next) = last.checked_add(1) else {
            return Ok(());
        };
        cursor = next;
    }
}

fn parse_search_page(
    bytes: &[u8],
    count: usize,
    object: u64,
    kind: u32,
    minimum_offset: u64,
    visit: &mut impl FnMut(u64, &[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let mut position = 0_usize;
    let mut last = None;
    for _ in 0..count {
        let header_end = position
            .checked_add(32)
            .ok_or_else(|| invalid("tree header overflow"))?;
        let header = bytes
            .get(position..header_end)
            .ok_or_else(|| invalid("truncated search header"))?;
        // The ioctl header is NATIVE endian. Its packed on-disk payload is not.
        let returned_object = u64::from_ne_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| invalid("search object"))?,
        );
        let offset = u64::from_ne_bytes(
            header[16..24]
                .try_into()
                .map_err(|_| invalid("search offset"))?,
        );
        let returned_kind = u32::from_ne_bytes(
            header[24..28]
                .try_into()
                .map_err(|_| invalid("search type"))?,
        );
        let length = u32::from_ne_bytes(
            header[28..32]
                .try_into()
                .map_err(|_| invalid("search length"))?,
        ) as usize;
        if returned_object != object
            || returned_kind != kind
            || offset < minimum_offset
            || last.is_some_and(|previous| offset <= previous)
        {
            return Err(invalid(
                "TREE_SEARCH returned an out-of-range or unordered key",
            ));
        }
        // A zero-length item can be V1's signal that an item did not fit.
        // Neither file extent items nor allocation items are legitimately empty.
        if length == 0 {
            return Err(invalid("empty or oversized tree item"));
        }
        let payload_end = header_end
            .checked_add(length)
            .ok_or_else(|| invalid("tree payload overflow"))?;
        let payload = bytes
            .get(header_end..payload_end)
            .ok_or_else(|| invalid("truncated tree item"))?;
        visit(offset, payload)?;
        last = Some(offset);
        position = payload_end;
    }
    last.ok_or_else(|| invalid("empty search page"))
}

#[repr(C)]
#[derive(Default)]
struct DefragRange {
    start: u64,
    length: u64,
    flags: u64,
    extent_thresh: u32,
    compress_type: u32,
    unused: [u32; 4],
}

pub(super) fn defrag_zstd(file: &File, start: u64, length: u64) -> io::Result<()> {
    let mut range = DefragRange {
        start,
        length,
        flags: 1 | 2,     // COMPRESS | START_IO
        compress_type: 3, // BTRFS_COMPRESS_ZSTD, not zlib's zero/default
        ..DefragRange::default()
    };
    call(file, DEFRAG_RANGE, &mut range)
}

#[cfg(target_arch = "x86_64")]
const IOPRIO_SET: c_long = 251;
#[cfg(target_arch = "x86_64")]
const IOPRIO_GET: c_long = 252;
#[cfg(target_arch = "aarch64")]
const IOPRIO_SET: c_long = 30;
#[cfg(target_arch = "aarch64")]
const IOPRIO_GET: c_long = 31;

pub(super) fn get_ioprio() -> io::Result<i32> {
    // SAFETY: ioprio_get accepts integer values only; PROCESS + who=0 selects
    // the calling thread, not every thread of the daemon or a process group.
    let result = unsafe { syscall(IOPRIO_GET, 1 as c_long, 0 as c_long) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        i32::try_from(result).map_err(|_| invalid("I/O priority exceeds i32"))
    }
}

pub(super) fn set_ioprio(priority: i32) -> io::Result<()> {
    // SAFETY: integer-only syscall, operating on the calling thread (who=0).
    let result = unsafe { syscall(IOPRIO_SET, 1 as c_long, 0 as c_long, c_long::from(priority)) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// Compile-time ABI checks for both supported LP64/asm-generic ioctl targets.
const _: [(); 56] = [(); std::mem::size_of::<FiemapExtent>()];
const _: [(); 7200] = [(); std::mem::size_of::<FiemapBuffer>()];
const _: [(); 104] = [(); std::mem::size_of::<SearchKey>()];
const _: [(); 4096] = [(); std::mem::size_of::<SearchBuffer>()];
const _: [(); 48] = [(); std::mem::size_of::<DefragRange>()];

#[cfg(test)]
mod tests {
    use super::*;

    fn page(object: u64, kind: u32, offsets: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for offset in offsets {
            bytes.extend_from_slice(&0_u64.to_ne_bytes());
            bytes.extend_from_slice(&object.to_ne_bytes());
            bytes.extend_from_slice(&offset.to_ne_bytes());
            bytes.extend_from_slice(&kind.to_ne_bytes());
            bytes.extend_from_slice(&3_u32.to_ne_bytes());
            bytes.extend_from_slice(&[1, 2, 3]);
        }
        bytes
    }

    #[test]
    fn uapi_requests_match_linux_headers() {
        assert_eq!(GET_FEATURES, 0x8018_9439);
        assert_eq!(GET_FLAGS, 0x8008_6601);
        assert_eq!(FIEMAP, 0xc020_660b);
        assert_eq!(TREE_SEARCH, 0xd000_9411);
        assert_eq!(DEFRAG_RANGE, 0x4030_9410);
        assert_eq!(std::mem::offset_of!(FiemapBuffer, extents), 32);
        assert_eq!(std::mem::offset_of!(SearchBuffer, bytes), 104);
    }

    #[test]
    fn packed_search_pages_advance_exactly_once() {
        let bytes = page(42, 108, &[0, 4096, 8192]);
        let mut visited = Vec::new();
        let last = parse_search_page(&bytes, 3, 42, 108, 0, &mut |offset, data| {
            visited.push(offset);
            assert_eq!(data, &[1, 2, 3]);
            Ok(())
        })
        .unwrap();
        assert_eq!(visited, [0, 4096, 8192]);
        assert_eq!(last, 8192);
    }

    #[test]
    fn truncated_search_headers_and_payloads_fail_closed() {
        let bytes = page(42, 108, &[0]);
        for length in 0..bytes.len() {
            assert!(
                parse_search_page(&bytes[..length], 1, 42, 108, 0, &mut |_, _| Ok(())).is_err()
            );
        }
    }

    #[test]
    fn wrong_keys_repeated_offsets_and_empty_items_fail_closed() {
        for (bytes, count, minimum) in [
            (page(41, 108, &[0]), 1, 0),
            (page(42, 107, &[0]), 1, 0),
            (page(42, 108, &[0, 0]), 2, 0),
            (page(42, 108, &[4096, 0]), 2, 0),
            (page(42, 108, &[0]), 1, 1),
        ] {
            assert!(
                parse_search_page(&bytes, count, 42, 108, minimum, &mut |_, _| Ok(())).is_err()
            );
        }
        let mut bytes = page(42, 108, &[0]);
        bytes[28..32].fill(0);
        assert!(parse_search_page(&bytes, 1, 42, 108, 0, &mut |_, _| Ok(())).is_err());
    }

    #[test]
    fn idle_priority_is_restored() {
        let previous = get_ioprio().unwrap();
        {
            let priority = crate::IdleIoPriority::enter().unwrap();
            assert_eq!(get_ioprio().unwrap(), 3 << 13);
            priority.restore().unwrap();
        }
        assert_eq!(get_ioprio().unwrap(), previous);
    }
}
