//! Descriptor-only Btrfs compression primitives (bd-rxq5).
//!
//! The application must select cold, unprotected, inactive files, retain the
//! verified descriptor, check free-space headroom, and enforce its byte/time
//! budget. This crate never opens a pathname or changes file contents with
//! `write`, `truncate`, `rename`, or `unlink`. Its only mutating filesystem
//! operation is a bounded `BTRFS_IOC_DEFRAG_RANGE` with zstd compression.
//!
//! FIEMAP is used ONLY for exclusion (including conservative SHARED flags).
//! Physical data accounting comes from EXTENT_DATA.disk_num_bytes, deduplicated
//! by allocation, not from st_blocks, FIEMAP length, or logical file size.
//! Referenced-byte savings are not the same as immediately reusable free space:
//! relocation roots, snapshots, transaction commits, and metadata can delay or
//! reduce the latter. [`reclaim_evidence`] reports that distinction explicitly.
//!
//! Supported syscall ABIs are Linux x86-64 and AArch64. Other targets compile
//! this crate to nothing; the application's compression command is a no-op.
//!
//! A FIEMAP preflight is not a filesystem-wide snapshot lock. Operators must
//! avoid concurrent snapshot/reflink creation during a compression pass. The
//! application must recheck active references and headroom between chunks.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![deny(unsafe_op_in_unsafe_fn)]

mod ioctl;

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;
use std::time::Instant;

/// Upper bound on a single defrag request. A kernel ioctl can still block;
/// deadlines are cooperative checks BETWEEN ioctls, not a hard time guarantee.
pub const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
/// Bound the memory and work used to inspect a highly fragmented file.
pub const MAX_EXTENTS: usize = 262_144;

/// Stable identity and content-change indicators sampled from one descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    /// Filesystem device identifier.
    pub device: u64,
    /// Inode within this filesystem/subvolume.
    pub inode: u64,
    /// Logical file length, not disk consumption.
    pub size: u64,
    /// Modification time seconds.
    pub mtime: i64,
    /// Modification time nanoseconds.
    pub mtime_nsec: i64,
    /// Change time seconds.
    pub ctime: i64,
    /// Change time nanoseconds.
    pub ctime_nsec: i64,
    /// Hard-link count; application policy should require one.
    pub links: u64,
}

impl FileStamp {
    /// Read from the pinned descriptor, rejecting anything but a regular file.
    pub fn read(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid("compression requires a regular file"));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            links: metadata.nlink(),
        })
    }

    /// Compare fields that defrag itself must preserve. ctime may change.
    #[must_use]
    pub fn same_contents_and_identity(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.size == other.size
            && self.mtime == other.mtime
            && self.mtime_nsec == other.mtime_nsec
            && self.links == other.links
    }
}

/// A unique data allocation as recorded in Btrfs file extent items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DataExtent {
    /// Btrfs logical disk address (not a physical device sector).
    pub bytenr: u64,
    /// Compressed on-disk allocation size, not the decompressed FIEMAP length.
    pub disk_num_bytes: u64,
}

/// Read-only, bounded inspection of a file's current extents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentMap {
    /// Descriptor identity at the time of inspection.
    pub stamp: FileStamp,
    /// Unique data allocations. Split references to one allocation count once.
    pub extents: Vec<DataExtent>,
    /// Total referenced data allocation bytes; metadata is not attributed.
    pub physical_data_bytes: u64,
    /// Inline payload bytes stored inside metadata, reported separately.
    pub inline_bytes: u64,
    /// OR of all FIEMAP extent flags.
    pub fiemap_flags: u32,
    /// FS_IOC_GETFLAGS flags for the inode.
    pub inode_flags: u32,
    /// At least one extent uses compression or another encoding.
    pub encoded: bool,
    /// At least one extent is preallocated rather than written data.
    pub preallocated: bool,
}

impl ExtentMap {
    /// Explain why an inspection is ineligible. Unknown flags fail closed.
    #[must_use]
    pub fn exclusion(&self) -> Option<&'static str> {
        if self.stamp.links != 1 {
            Some("hard_linked_or_unlinked")
        } else if self.inode_flags & ioctl::EXCLUDED_INODE_FLAGS != 0 {
            Some("nocow_nocompress_immutable_or_append_only")
        } else if self.fiemap_flags & ioctl::FIEMAP_EXTENT_SHARED != 0 {
            Some("shared_or_reflinked_extents")
        } else if self.encoded || self.fiemap_flags & ioctl::FIEMAP_EXTENT_ENCODED != 0 {
            Some("already_encoded_or_compressed")
        } else if self.preallocated {
            Some("preallocated_extents")
        } else if self.inline_bytes != 0 {
            Some("inline_data")
        } else if self.fiemap_flags & !ioctl::FIEMAP_EXTENT_LAST != 0 {
            Some("unknown_delayed_or_unsupported_extent_layout")
        } else if self.physical_data_bytes == 0 {
            Some("no_allocated_data")
        } else {
            None
        }
    }
}

/// Explicit consent to the filesystem-wide compatibility consequence of the
/// first zstd write (COMPRESS_ZSTD requires Linux 4.14 or later).
#[derive(Debug, Clone, Copy)]
pub struct ZstdConsent(());

impl ZstdConsent {
    /// Call only after the operator explicitly opted into the incompat flag.
    #[must_use]
    pub fn acknowledge_filesystem_compatibility_change() -> Self {
        Self(())
    }
}

/// Determine whether this descriptor supports Btrfs feature inspection.
/// An unsupported filesystem returns false; permission/I/O failures propagate.
pub fn is_btrfs(file: &File) -> io::Result<bool> {
    match ioctl::features(file) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(25) => Ok(false), // ENOTTY
        Err(error) => Err(error),
    }
}

/// Whether zstd's on-disk incompat feature is already enabled.
pub fn zstd_feature_enabled(file: &File) -> io::Result<bool> {
    Ok(ioctl::features(file)? & (1 << 4) != 0)
}

/// Inspect a pinned, regular Btrfs file. TREE_SEARCH requires appropriate
/// privileges; incomplete or denied queries are errors, never zero-byte maps.
pub fn inspect(file: &File, deadline: Instant) -> io::Result<ExtentMap> {
    check_deadline(deadline)?;
    let stamp = FileStamp::read(file)?;
    if !is_btrfs(file)? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a Btrfs file",
        ));
    }
    let inode_flags = ioctl::inode_flags(file)?;
    let fiemap_flags = ioctl::fiemap_flags(file, 0, stamp.size, deadline)?;
    let mut allocations = BTreeMap::new();
    let mut inline_bytes = 0_u64;
    let mut encoded = false;
    let mut preallocated = false;
    ioctl::visit_items(file, 0, stamp.inode, 108, deadline, |_, item| {
        let parsed = parse_file_extent(item)?;
        encoded |= parsed.encoded;
        preallocated |= parsed.preallocated;
        inline_bytes = inline_bytes
            .checked_add(parsed.inline_bytes)
            .ok_or_else(|| invalid("inline byte count overflow"))?;
        if let Some(extent) = parsed.extent
            && let Some(previous) = allocations.insert(extent.bytenr, extent.disk_num_bytes)
            && previous != extent.disk_num_bytes
        {
            return Err(invalid("inconsistent physical extent lengths"));
        }
        Ok(())
    })?;
    // A write during the two different mapping operations invalidates the
    // combined snapshot. Never use a partly observed view as deletion/reclaim
    // evidence. Later execution performs an additional fresh preflight.
    if FileStamp::read(file)? != stamp {
        return Err(io::Error::other("file changed during extent inspection"));
    }
    let physical_data_bytes = checked_sum(allocations.values().copied())?;
    let extents = allocations
        .into_iter()
        .map(|(bytenr, disk_num_bytes)| DataExtent {
            bytenr,
            disk_num_bytes,
        })
        .collect();
    Ok(ExtentMap {
        stamp,
        extents,
        physical_data_bytes,
        inline_bytes,
        fiemap_flags,
        inode_flags,
        encoded,
        preallocated,
    })
}

/// Compress a bounded range of an already-open file in place.
///
/// The caller must also enforce age, protection/lease rules, active references,
/// free-space headroom, and unchanged identity. This function independently
/// refuses unsafe inode flags and ANY FIEMAP flags other than LAST immediately
/// before the mutating ioctl. It never unshares an extent intentionally.
///
/// Only the requested range is inspected here: previously compressed chunks
/// must not make the remainder of a large file unreachable. Zero-length and
/// unbounded requests are rejected. START_IO plus fsync prevents unbounded
/// dirty-page accumulation across chunks.
pub fn compress_range(
    file: &File,
    start: u64,
    length: u64,
    _consent: ZstdConsent,
    deadline: Instant,
) -> io::Result<()> {
    check_deadline(deadline)?;
    let stamp = FileStamp::read(file)?;
    validate_range(start, length, stamp.size)?;
    if stamp.links != 1 {
        return Err(invalid("refusing a hard-linked or unlinked file"));
    }
    if !is_btrfs(file)? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a Btrfs file",
        ));
    }
    if ioctl::inode_flags(file)? & ioctl::EXCLUDED_INODE_FLAGS != 0 {
        return Err(invalid("inode flags forbid compression"));
    }
    let flags = ioctl::fiemap_flags(file, start, length, deadline)?;
    if flags & !ioctl::FIEMAP_EXTENT_LAST != 0 {
        return Err(invalid(
            "range is shared, encoded, delayed, or otherwise unsupported",
        ));
    }
    if FileStamp::read(file)? != stamp {
        return Err(io::Error::other("file changed before compression"));
    }
    check_deadline(deadline)?;
    ioctl::defrag_zstd(file, start, length)?;
    file.sync_all()?;
    if !stamp.same_contents_and_identity(FileStamp::read(file)?) {
        return Err(io::Error::other(
            "file identity, size, or mtime changed during compression",
        ));
    }
    Ok(())
}

/// Evidence for one compression operation, excluding metadata overhead and
/// unrelated filesystem activity. No optimistic free-space estimate is used.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReclaimEvidence {
    /// Reduction in this file's referenced data bytes (not yet proof of reuse).
    pub referenced_bytes_saved: u64,
    /// Growth in this file's referenced data bytes; never hidden by saturation.
    pub referenced_bytes_added: u64,
    /// Retired allocations no longer found in the extent tree.
    pub old_data_bytes_released: u64,
    /// Retired allocations still present, e.g. transaction or relocation delay.
    pub old_data_bytes_pending: u64,
    /// New allocations referenced by the compressed file.
    pub new_data_bytes_allocated: u64,
    /// Conservative net data-only reclaim: released old bytes minus new bytes.
    /// This is NOT an assertion about the mount's immediately available bytes.
    pub confirmed_data_bytes_reclaimed: u64,
}

/// Check whether retired data extents are actually gone from the extent tree.
/// A failed or incomplete tree query is an error, not evidence of reclamation.
pub fn reclaim_evidence(
    file: &File,
    before: &ExtentMap,
    after: &ExtentMap,
    deadline: Instant,
) -> io::Result<ReclaimEvidence> {
    if !before.stamp.same_contents_and_identity(after.stamp)
        || !after
            .stamp
            .same_contents_and_identity(FileStamp::read(file)?)
    {
        return Err(io::Error::other(
            "file changed; reclaim attribution is invalid",
        ));
    }
    let mut evidence = ReclaimEvidence {
        referenced_bytes_saved: before
            .physical_data_bytes
            .saturating_sub(after.physical_data_bytes),
        referenced_bytes_added: after
            .physical_data_bytes
            .saturating_sub(before.physical_data_bytes),
        ..ReclaimEvidence::default()
    };
    for extent in &after.extents {
        if before.extents.binary_search(extent).is_err() {
            evidence.new_data_bytes_allocated = evidence
                .new_data_bytes_allocated
                .checked_add(extent.disk_num_bytes)
                .ok_or_else(|| invalid("allocation sum overflow"))?;
        }
    }
    for extent in &before.extents {
        if after.extents.binary_search(extent).is_ok() {
            continue;
        }
        let mut present = false;
        // Extent tree (2), EXTENT_ITEM (168). Search every offset for this
        // bytenr rather than treating a changed length as disappearance.
        ioctl::visit_items(file, 2, extent.bytenr, 168, deadline, |_, _| {
            present = true;
            Ok(())
        })?;
        let sum = if present {
            &mut evidence.old_data_bytes_pending
        } else {
            &mut evidence.old_data_bytes_released
        };
        *sum = sum
            .checked_add(extent.disk_num_bytes)
            .ok_or_else(|| invalid("retired allocation sum overflow"))?;
    }
    evidence.confirmed_data_bytes_reclaimed = evidence
        .old_data_bytes_released
        .saturating_sub(evidence.new_data_bytes_allocated);
    Ok(evidence)
}

/// Temporarily lower only the calling thread's I/O priority to IDLE.
/// Not Send/Sync: restoration must happen on the same thread that acquired it.
#[derive(Debug)]
pub struct IdleIoPriority {
    previous: i32,
    restored: bool,
    same_thread: PhantomData<Rc<()>>,
}

impl IdleIoPriority {
    /// Enter idle I/O priority. Failure must abort an apply pass, not silently
    /// run a multi-gigabyte rewrite at ordinary priority.
    pub fn enter() -> io::Result<Self> {
        let previous = ioctl::get_ioprio()?;
        ioctl::set_ioprio(3 << 13)?; // IOPRIO_CLASS_IDLE
        Ok(Self {
            previous,
            restored: false,
            same_thread: PhantomData,
        })
    }

    /// Restore the previous priority and surface restoration errors explicitly.
    pub fn restore(mut self) -> io::Result<()> {
        ioctl::set_ioprio(self.previous)?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for IdleIoPriority {
    fn drop(&mut self) {
        if !self.restored {
            let _ = ioctl::set_ioprio(self.previous);
        }
    }
}

fn validate_range(start: u64, length: u64, size: u64) -> io::Result<()> {
    if length == 0
        || length > MAX_CHUNK_BYTES
        || !start.is_multiple_of(4096)
        || start.checked_add(length).is_none_or(|end| end > size)
    {
        return Err(invalid(
            "invalid, unaligned, or oversized compression range",
        ));
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "compression inspection budget exhausted",
        ))
    } else {
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checked_sum(mut values: impl Iterator<Item = u64>) -> io::Result<u64> {
    values.try_fold(0_u64, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| invalid("physical byte count overflow"))
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedExtent {
    extent: Option<DataExtent>,
    inline_bytes: u64,
    encoded: bool,
    preallocated: bool,
}

fn parse_file_extent(item: &[u8]) -> io::Result<ParsedExtent> {
    // On-disk extent items are packed LITTLE endian, unlike ioctl headers.
    if item.len() < 21 {
        return Err(invalid("truncated file extent item"));
    }
    let encoded = item[16..20].iter().any(|byte| *byte != 0);
    match item[20] {
        0 => Ok(ParsedExtent {
            inline_bytes: (item.len() - 21) as u64,
            encoded,
            ..ParsedExtent::default()
        }),
        kind @ (1 | 2) => {
            if item.len() != 53 {
                return Err(invalid("unsupported regular file extent item length"));
            }
            let bytenr = u64::from_le_bytes(
                item[21..29]
                    .try_into()
                    .map_err(|_| invalid("extent address"))?,
            );
            let disk_num_bytes = u64::from_le_bytes(
                item[29..37]
                    .try_into()
                    .map_err(|_| invalid("extent length"))?,
            );
            if (bytenr == 0) != (disk_num_bytes == 0) {
                return Err(invalid("inconsistent hole or data allocation"));
            }
            if bytenr.checked_add(disk_num_bytes).is_none() {
                return Err(invalid("extent address overflow"));
            }
            Ok(ParsedExtent {
                extent: (bytenr != 0).then_some(DataExtent {
                    bytenr,
                    disk_num_bytes,
                }),
                encoded,
                preallocated: kind == 2,
                ..ParsedExtent::default()
            })
        }
        _ => Err(invalid("unknown file extent type")),
    }
}

#[cfg(test)]
mod tests;
