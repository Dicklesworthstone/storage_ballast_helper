//! Linux collection is bounded and read-only; all thresholds live in assess().
//!
//! Mounts come from `/proc/self/mountinfo`. A tmpfs is measured only through a
//! descriptor whose mount ID and device identify that tmpfs. Identity and
//! capacity are read through the same descriptor; pathname replacement cannot
//! substitute another filesystem's counters. When lookup reaches another
//! mount, the mount IDs and parent links explain why: a mount attached at or
//! above the mount point covers it (GitHub #40). A covered tmpfs still
//! occupies memory, so its usage is reported as unknown.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Mode, OFlags, StatxFlags, fstatfs, open, statx};

use crate::platform::pal::{MemoryInfo, Platform};

use super::{
    CoveringMount, ProcessSwap, ScratchIssue, ScratchLimits, ScratchMount, ScratchReport, assess,
    invalid,
};

const MAX_STATUS_BYTES: u64 = 64 * 1024;
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Container hosts can list tens of thousands of mounts; this bounds one read.
const MAX_MOUNTINFO_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FDINFO_BYTES: u64 = 64 * 1024;

/// Whether a mount ID is still listed, from one fresh mount-table read.
type StillListed<'a> = &'a mut dyn FnMut(u64) -> Result<bool, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct MountStats {
    tmpfs: bool,
    block_size: u64,
    blocks: u64,
    free_blocks: u64,
    available_blocks: u64,
}

/// Capacity reads refer only to the retained handle. A second open verifies
/// pathname identity after sampling without borrowing its filesystem counters.
trait MountReader {
    type Handle;

    fn open(&self, path: &Path) -> io::Result<Self::Handle>;
    fn identity(&self, handle: &Self::Handle) -> io::Result<MountIdentity>;
    fn stats(&self, handle: &Self::Handle) -> io::Result<MountStats>;
}

struct NativeMountReader;

impl MountReader for NativeMountReader {
    type Handle = File;

    fn open(&self, path: &Path) -> io::Result<File> {
        // O_PATH does not read payloads, trigger device opens or require read
        // permission on the final object. File bind mounts are valid too.
        Ok(File::from(open(
            path,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?))
    }

    fn identity(&self, handle: &File) -> io::Result<MountIdentity> {
        let metadata = handle.metadata()?;
        let mount_id = descriptor_mount_id(handle)?;
        Ok(MountIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            mount_id,
        })
    }

    fn stats(&self, handle: &File) -> io::Result<MountStats> {
        let stats = fstatfs(handle)?;
        let fragment = if stats.f_frsize == 0 {
            stats.f_bsize
        } else {
            stats.f_frsize
        };
        let block_size = u64::try_from(fragment)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| invalid("invalid filesystem block size"))?;
        Ok(MountStats {
            tmpfs: i128::from(stats.f_type) == i128::from(libc::TMPFS_MAGIC),
            block_size,
            blocks: stats.f_blocks,
            free_blocks: stats.f_bfree,
            available_blocks: stats.f_bavail,
        })
    }
}

fn descriptor_mount_id(handle: &File) -> io::Result<u64> {
    let observed = statx(handle, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID);
    if let Ok(identity) = &observed
        && identity.stx_mask & StatxFlags::MNT_ID.bits() != 0
    {
        return Ok(identity.stx_mnt_id);
    }
    // Older kernels, or sandboxes which block statx, can still expose the
    // ordinary mountinfo ID through fdinfo. Never invent one from st_dev.
    let fallback = File::open(format!("/proc/self/fdinfo/{}", handle.as_raw_fd()))
        .and_then(|input| read_bounded(input, MAX_FDINFO_BYTES))
        .and_then(|raw| parse_fdinfo_mount_id(&raw));
    fallback.map_err(|error| match observed {
        Err(native) if native != rustix::io::Errno::NOSYS => io::Error::from(native),
        _ => error,
    })
}

fn parse_fdinfo_mount_id(raw: &[u8]) -> io::Result<u64> {
    let mut id = None;
    for line in raw.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"mnt_id:") {
            let mut fields = value
                .split(u8::is_ascii_whitespace)
                .filter(|v| !v.is_empty());
            let parsed = mountinfo_number(fields.next())?;
            if fields.next().is_some() || id.replace(parsed).is_some() {
                return Err(invalid("ambiguous descriptor mount ID"));
            }
        }
    }
    id.ok_or_else(|| invalid("descriptor mount ID is unavailable"))
}

fn read_bounded(input: impl Read, maximum: u64) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    input
        .take(maximum.saturating_add(1))
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "kernel metadata exceeds its inspection byte budget",
        ));
    }
    Ok(raw)
}

pub(super) fn inspect(platform: &dyn Platform, limits: ScratchLimits) -> ScratchReport {
    let deadline = Instant::now() + Duration::from_secs(limits.timeout_secs);
    let memory = platform
        .memory_info()
        .map_err(|error| io::Error::other(error.to_string()));
    let (mounts, mut issues) = match read_mountinfo() {
        Ok(table) => observe_mounts(
            &table,
            limits.max_mounts,
            deadline,
            &NativeMountReader,
            &read_mountinfo,
        ),
        Err(error) => (Vec::new(), vec![mount_table_issue(&error)]),
    };
    let process_swap =
        match collect_process_swap(Path::new("/proc"), limits.max_processes, deadline) {
            Ok(observation) => observation,
            Err(error) => {
                issues.push(ScratchIssue {
                    os_error: error.raw_os_error(),
                    ..ScratchIssue::new(
                        "process_swap_failed",
                        format!("process swap collection failed: {error}"),
                    )
                });
                ProcessSwap::default()
            }
        };
    if !process_swap.complete {
        issues.push(ScratchIssue::new(
            "process_swap_incomplete",
            format!(
                "process swap observation incomplete: {} statuses inspected, {} unreadable or malformed",
                process_swap.inspected, process_swap.unreadable
            ),
        ));
    }
    finish_report(memory, mounts, process_swap, issues)
}

fn finish_report(
    memory: io::Result<MemoryInfo>,
    mounts: Vec<ScratchMount>,
    process_swap: ProcessSwap,
    mut issues: Vec<ScratchIssue>,
) -> ScratchReport {
    let (assessment, operation) = match memory {
        Ok(memory) => (assess(memory, mounts, process_swap), "assessment"),
        Err(error) => (Err(error), "memory_info"),
    };
    let assessment = match assessment {
        Ok(assessment) => Some(assessment),
        Err(error) => {
            issues.push(ScratchIssue {
                operation: Some(operation),
                os_error: error.raw_os_error(),
                ..ScratchIssue::new(
                    "collection_failed",
                    format!(
                        "RAM scratch {operation} failed: {error}; resource accounting is incomplete"
                    ),
                )
            });
            None
        }
    };
    let complete = issues.is_empty() && assessment.is_some();
    let exit_code = if complete {
        i32::from(
            assessment
                .as_ref()
                .is_some_and(super::ScratchAssessment::warning),
        )
    } else {
        4
    };
    ScratchReport {
        schema: "sbh.ram_scratch.v1",
        read_only: true,
        supported: true,
        complete,
        scope: "visible mount and process namespaces; host meminfo; not cgroup headroom or swap attribution",
        assessment,
        issues: issues.iter().map(|issue| issue.message.clone()).collect(),
        issue_details: issues,
        exit_code,
    }
}

/// One `/proc/self/mountinfo` record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountRecord {
    id: u64,
    parent: u64,
    major: u32,
    minor: u32,
    mount_point: PathBuf,
    fs_type: String,
}

impl MountRecord {
    /// Whether an `st_dev` value names this mount's filesystem.
    fn has_device(&self, device: u64) -> bool {
        (libc::major(device), libc::minor(device)) == (self.major, self.minor)
    }
}

fn read_mountinfo() -> io::Result<Vec<MountRecord>> {
    let raw = read_bounded(File::open(MOUNTINFO)?, MAX_MOUNTINFO_BYTES)?;
    parse_mountinfo(&raw)
}

fn mount_table_issue(error: &io::Error) -> ScratchIssue {
    ScratchIssue {
        path: Some(MOUNTINFO.into()),
        operation: Some("mount_table"),
        os_error: error.raw_os_error(),
        ..ScratchIssue::new(
            if error.kind() == io::ErrorKind::FileTooLarge {
                "mount_table_budget_exhausted"
            } else if error.kind() == io::ErrorKind::PermissionDenied {
                "permission_denied"
            } else {
                "mount_table_failed"
            },
            format!("{MOUNTINFO}: {error}; tmpfs occupancy is unknown"),
        )
    }
}

/// Every record, or an error: a record skipped here would go missing silently.
fn parse_mountinfo(raw: &[u8]) -> io::Result<Vec<MountRecord>> {
    let Some(body) = raw.strip_suffix(b"\n") else {
        return Err(invalid("mount table is empty or truncated"));
    };
    let mut records = Vec::new();
    let mut ids = BTreeSet::new();
    for line in body.split(|byte| *byte == b'\n') {
        // Paths are escaped and no other field before the separator can be a
        // lone "-", so the first " - " ends the per-mount fields.
        let separator = line
            .windows(3)
            .position(|part| part == b" - ")
            .ok_or_else(|| invalid("invalid mountinfo record"))?;
        let mut fields = line[..separator].split(|byte| *byte == b' ');
        let id = mountinfo_number(fields.next())?;
        let parent = mountinfo_number(fields.next())?;
        let (major, minor) = fields
            .next()
            .and_then(|field| std::str::from_utf8(field).ok()?.split_once(':'))
            .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
            .ok_or_else(|| invalid("invalid mountinfo device"))?;
        fields
            .next()
            .ok_or_else(|| invalid("missing mountinfo root"))?;
        let mount_point = unescape(
            fields
                .next()
                .ok_or_else(|| invalid("missing mountinfo mount point"))?,
        )?;
        if !mount_point.is_absolute() {
            return Err(invalid("relative mountinfo mount point"));
        }
        let fs_type = line[separator + 3..]
            .split(|byte| *byte == b' ')
            .next()
            .filter(|kind| !kind.is_empty())
            .ok_or_else(|| invalid("missing mountinfo filesystem type"))?;
        let fs_type = unescape(fs_type)?.to_string_lossy().into_owned();
        if !ids.insert(id) {
            return Err(invalid("duplicate mountinfo mount ID"));
        }
        records.push(MountRecord {
            id,
            parent,
            major,
            minor,
            mount_point,
            fs_type,
        });
    }
    Ok(records)
}

fn mountinfo_number(field: Option<&[u8]>) -> io::Result<u64> {
    field
        .and_then(|field| std::str::from_utf8(field).ok())
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| invalid("invalid mountinfo mount ID"))
}

/// Undo procfs octal escaping (`\040` is a space) without assuming UTF-8.
fn unescape(raw: &[u8]) -> io::Result<PathBuf> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut position = 0;
    while let Some(&byte) = raw.get(position) {
        if byte == b'\\' {
            let value = raw
                .get(position + 1..position + 4)
                .filter(|digits| digits.iter().all(|digit| (b'0'..=b'7').contains(digit)))
                .map(|digits| {
                    digits
                        .iter()
                        .fold(0_u32, |value, digit| value * 8 + u32::from(digit - b'0'))
                })
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| invalid("invalid mountinfo escape"))?;
            decoded.push(value);
            position += 4;
        } else {
            decoded.push(byte);
            position += 1;
        }
    }
    Ok(PathBuf::from(OsString::from_vec(decoded)))
}

/// Where path lookup of a listed mount point leads.
#[derive(Debug, PartialEq, Eq)]
enum Reach<'a> {
    /// Nothing listed hides the mount.
    Reachable,
    /// Lookup reaches this other mount at or above the mount point instead.
    Covered(&'a MountRecord),
    /// The parent links loop, so the route cannot be determined.
    Unresolved,
}

/// Mount IDs and mount points of one mount-table read.
struct Topology<'a> {
    by_id: BTreeMap<u64, &'a MountRecord>,
    by_point: BTreeMap<&'a Path, Vec<&'a MountRecord>>,
}

impl<'a> Topology<'a> {
    fn new(table: &'a [MountRecord]) -> Self {
        let mut by_point = BTreeMap::<&Path, Vec<&MountRecord>>::new();
        for record in table {
            by_point
                .entry(record.mount_point.as_path())
                .or_default()
                .push(record);
        }
        Self {
            by_id: table.iter().map(|record| (record.id, record)).collect(),
            by_point,
        }
    }

    /// Lookup reaches a mount only through its ancestors, crossing each one
    /// from where it is mounted to where the next one down is mounted.
    /// Mounting on a directory attaches to whichever mount lookup reaches
    /// there, so a mount that existed first would be an ancestor. A mount that
    /// is not an ancestor, but is attached to one within the stretch lookup
    /// crosses (or is stacked on this mount), came later and hides it. The
    /// hidden mount stays listed and keeps its memory.
    fn reach(&self, record: &MountRecord) -> Reach<'a> {
        // Each mount on the route, with the point where lookup leaves it.
        let mut leaves_at = BTreeMap::from([(record.id, record.mount_point.as_path())]);
        let mut current = record;
        // A namespace root's parent is unlisted, or is the root itself.
        while current.parent != current.id {
            let Some(&ancestor) = self.by_id.get(&current.parent) else {
                break;
            };
            if leaves_at
                .insert(ancestor.id, current.mount_point.as_path())
                .is_some()
            {
                return Reach::Unresolved;
            }
            current = ancestor;
        }
        // Report the outermost cover, where lookup leaves the route first:
        // ancestors run from the mount point up, so that is the last match.
        record
            .mount_point
            .ancestors()
            .filter_map(|point| {
                self.by_point.get(point)?.iter().copied().find(|other| {
                    !leaves_at.contains_key(&other.id)
                        && leaves_at
                            .get(&other.parent)
                            .is_some_and(|leaves| leaves.starts_with(point))
                })
            })
            .last()
            .map_or(Reach::Reachable, Reach::Covered)
    }
}

/// Usage of each listed tmpfs, or why it is unknown.
fn observe_mounts<R: MountReader>(
    table: &[MountRecord],
    max_mounts: usize,
    deadline: Instant,
    reader: &R,
    relist: &dyn Fn() -> io::Result<Vec<MountRecord>>,
) -> (Vec<ScratchMount>, Vec<ScratchIssue>) {
    let topology = Topology::new(table);
    let mut relisted: Option<Result<BTreeSet<u64>, String>> = None;
    let mut still_listed = |id: u64| {
        relisted
            .get_or_insert_with(|| {
                relist()
                    .map(|records| records.iter().map(|record| record.id).collect())
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map(|ids| ids.contains(&id))
            .map_err(Clone::clone)
    };
    let mut issues = Vec::new();
    let mut covered = Vec::new();
    // Keep each sample with its handle until alias deduplication finishes, so
    // an unmount cannot recycle a sampled device number during this report.
    let mut measured = Vec::new();
    let mut considered = 0;
    for record in table {
        let tmpfs = record.fs_type.eq_ignore_ascii_case("tmpfs");
        if !tmpfs && !record.fs_type.eq_ignore_ascii_case("ramfs") {
            continue;
        }
        if considered >= max_mounts || Instant::now() >= deadline {
            issues.push(ScratchIssue::new(
                "mount_budget_exhausted",
                "tmpfs mount enumeration budget exhausted".into(),
            ));
            break;
        }
        considered += 1;
        let shown = record.mount_point.display();
        if !tmpfs {
            issues.push(mount_issue(
                "ramfs_unmeasurable",
                record,
                None,
                format!("{shown}: ramfs occupancy is not measurable with tmpfs block accounting"),
            ));
            continue;
        }
        // A topology snapshot can establish coverage without resolving a
        // pathname which belongs to another mount. Even a same-device cover
        // is handled explicitly as an alias, never mistaken for this mount.
        match topology.reach(record) {
            Reach::Covered(cover) => {
                covered.push((record, cover));
                continue;
            }
            Reach::Unresolved => {
                issues.push(mount_issue(
                    "mount_topology_unresolved",
                    record,
                    None,
                    format!(
                        "{shown}: the parent links of mount {} loop in the mount table, so whether its path reaches it is unknown",
                        record.id
                    ),
                ));
                continue;
            }
            Reach::Reachable => {}
        }
        match observe_reachable(record, reader, &mut still_listed) {
            Ok(sample) => measured.push(sample),
            Err(issue) => issues.push(*issue),
        }
    }
    let mut mounts: Vec<_> = measured.iter().map(|(mount, _)| mount.clone()).collect();
    // A covered copy of a filesystem measured through another listed path
    // (a bind or propagated mount) is an alias, not missing evidence.
    for (record, cover) in covered {
        if let Some(alias) = mounts
            .iter()
            .find(|mount| record.has_device(mount.filesystem_id))
            .cloned()
        {
            mounts.push(ScratchMount {
                path: record.mount_point.to_string_lossy().into_owned(),
                ..alias
            });
        } else {
            issues.push(covered_issue(record, cover));
        }
    }
    drop(measured);
    (mounts, issues)
}

/// Retain the verified descriptor alongside the sample through deduplication.
fn observe_reachable<R: MountReader>(
    record: &MountRecord,
    reader: &R,
    still_listed: StillListed<'_>,
) -> Result<(ScratchMount, R::Handle), Box<ScratchIssue>> {
    let handle = reader
        .open(&record.mount_point)
        .map_err(|error| Box::new(inspection_failed(record, &error, "open", still_listed)))?;
    let before = reader
        .identity(&handle)
        .map_err(|error| Box::new(inspection_failed(record, &error, "identity", still_listed)))?;
    if before.mount_id != record.id || !record.has_device(before.device) {
        return Err(Box::new(ScratchIssue {
            operation: Some("identity"),
            observed_mount_id: Some(before.mount_id),
            ..mount_issue(
                "mount_replaced",
                record,
                None,
                format!(
                    "{}: opened mount {} on device {}:{}, not listed mount {} on {}:{}; mount identity changed since enumeration",
                    record.mount_point.display(),
                    before.mount_id,
                    libc::major(before.device),
                    libc::minor(before.device),
                    record.id,
                    record.major,
                    record.minor
                ),
            )
        }));
    }
    let usage = measure(record, before, &handle, reader, still_listed)?;
    Ok((usage, handle))
}

fn covered_issue(record: &MountRecord, cover: &MountRecord) -> ScratchIssue {
    ScratchIssue {
        operation: Some("topology"),
        covered_by: Some(CoveringMount {
            mount_id: cover.id,
            path: cover.mount_point.to_string_lossy().into_owned(),
            fs_type: cover.fs_type.clone(),
        }),
        ..mount_issue(
            "mount_covered",
            record,
            None,
            format!(
                "{}: tmpfs mount {} ({}:{}) is covered in the observed mount table by mount {} ({}) at {}; its occupancy is unknown unless measured through a verified alias",
                record.mount_point.display(),
                record.id,
                record.major,
                record.minor,
                cover.id,
                cover.fs_type,
                cover.mount_point.display()
            ),
        )
    }
}

/// Capacity of the same opened object whose identity was checked as `before`.
fn measure<R: MountReader>(
    record: &MountRecord,
    before: MountIdentity,
    handle: &R::Handle,
    reader: &R,
    still_listed: StillListed<'_>,
) -> Result<ScratchMount, Box<ScratchIssue>> {
    let shown = record.mount_point.display();
    let stats = reader
        .stats(handle)
        .map_err(|error| Box::new(inspection_failed(record, &error, "capacity", still_listed)))?;
    let verified = reader.open(&record.mount_point).map_err(|error| {
        Box::new(inspection_failed(
            record,
            &error,
            "verify_path",
            still_listed,
        ))
    })?;
    let after = reader
        .identity(&verified)
        .map_err(|error| Box::new(inspection_failed(record, &error, "identity", still_listed)))?;
    if after != before || !stats.tmpfs {
        return Err(Box::new(ScratchIssue {
            operation: Some(if stats.tmpfs {
                "verify_path"
            } else {
                "capacity"
            }),
            observed_mount_id: Some(after.mount_id),
            ..mount_issue(
                "mount_replaced",
                record,
                None,
                format!("{shown}: mount changed during inspection or descriptor is not tmpfs"),
            )
        }));
    }
    let inconsistent = || {
        Box::new(ScratchIssue {
            operation: Some("capacity"),
            observed_mount_id: Some(before.mount_id),
            ..mount_issue(
                "mount_counters_inconsistent",
                record,
                None,
                format!("{shown}: tmpfs block counters are inconsistent or overflow bytes"),
            )
        })
    };
    if stats.block_size == 0
        || stats.free_blocks > stats.blocks
        || stats.available_blocks > stats.free_blocks
    {
        return Err(inconsistent());
    }
    let total_bytes = stats
        .blocks
        .checked_mul(stats.block_size)
        .ok_or_else(inconsistent)?;
    let used_bytes = (stats.blocks - stats.free_blocks)
        .checked_mul(stats.block_size)
        .ok_or_else(inconsistent)?;
    let available_bytes = stats
        .available_blocks
        .checked_mul(stats.block_size)
        .ok_or_else(inconsistent)?;
    Ok(ScratchMount {
        path: record.mount_point.to_string_lossy().into_owned(),
        filesystem_id: before.device,
        total_bytes,
        used_bytes,
        available_bytes,
    })
}

fn inspection_failed(
    record: &MountRecord,
    error: &io::Error,
    operation: &'static str,
    still_listed: StillListed<'_>,
) -> ScratchIssue {
    let mut issue = if operation == "identity" && error.kind() != io::ErrorKind::PermissionDenied {
        mount_issue(
            "mount_identity_unavailable",
            record,
            Some(error),
            format!(
                "{}: descriptor mount identity is unavailable: {error}",
                record.mount_point.display()
            ),
        )
    } else {
        lookup_failed(record, error, still_listed)
    };
    issue.operation = Some(operation);
    issue
}

/// Classify a failed lookup of a mount point that no listed mount covers.
fn lookup_failed(
    record: &MountRecord,
    error: &io::Error,
    still_listed: StillListed<'_>,
) -> ScratchIssue {
    let shown = record.mount_point.display();
    let id = record.id;
    let (kind, message) = match error.kind() {
        io::ErrorKind::NotFound => match still_listed(id) {
            Ok(false) => (
                "mount_vanished",
                format!("{shown}: {error}; mount {id} was unmounted during inspection"),
            ),
            Ok(true) => (
                "mount_not_addressable",
                format!(
                    "{shown}: {error}; mount {id} is still listed and no listed mount covers it (its mount point may have been deleted from another mount namespace)"
                ),
            ),
            Err(relist) => (
                "mount_not_addressable",
                format!(
                    "{shown}: {error}; mount {id} is listed, and re-reading the mount table to check whether it was unmounted failed: {relist}"
                ),
            ),
        },
        io::ErrorKind::PermissionDenied => ("permission_denied", format!("{shown}: {error}")),
        _ => ("mount_inspection_failed", format!("{shown}: {error}")),
    };
    mount_issue(kind, record, Some(error), message)
}

fn mount_issue(
    kind: &'static str,
    record: &MountRecord,
    error: Option<&io::Error>,
    message: String,
) -> ScratchIssue {
    ScratchIssue {
        path: Some(record.mount_point.to_string_lossy().into_owned()),
        mount_id: Some(record.id),
        os_error: error.and_then(io::Error::raw_os_error),
        ..ScratchIssue::new(kind, message)
    }
}

fn collect_process_swap(root: &Path, maximum: usize, deadline: Instant) -> io::Result<ProcessSwap> {
    let mut observation = ProcessSwap {
        complete: true,
        ..Default::default()
    };
    let mut attempted = 0;
    for entry in fs::read_dir(root)? {
        if Instant::now() >= deadline {
            observation.complete = false;
            break;
        }
        let Ok(entry) = entry else {
            observation.unreadable += 1;
            observation.complete = false;
            continue;
        };
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        if attempted >= maximum {
            observation.complete = false;
            break;
        }
        attempted += 1;
        let value = (|| -> io::Result<u64> {
            let mut text = String::new();
            File::open(entry.path().join("status"))?
                .take(MAX_STATUS_BYTES + 1)
                .read_to_string(&mut text)?;
            if text.len() as u64 > MAX_STATUS_BYTES {
                return Err(invalid("process status exceeds inspection budget"));
            }
            parse_vm_swap(&text)
        })();
        match value {
            Ok(bytes) => {
                observation.bytes = observation
                    .bytes
                    .checked_add(bytes)
                    .ok_or_else(|| invalid("process swap sum overflow"))?;
                observation.inspected += 1;
            }
            // A process may exit between enumeration and its status read.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                observation.unreadable += 1;
                observation.complete = false;
            }
        }
    }
    Ok(observation)
}

fn parse_vm_swap(status: &str) -> io::Result<u64> {
    let mut swap = None;
    let mut has_address_space = false;
    for line in status.lines() {
        has_address_space |= line.starts_with("VmSize:");
        if let Some(value) = line.strip_prefix("VmSwap:") {
            if swap.is_some() {
                return Err(invalid("duplicate process VmSwap counter"));
            }
            let mut words = value.split_whitespace();
            let kib = words
                .next()
                .and_then(|word| word.parse::<u64>().ok())
                .ok_or_else(|| invalid("invalid process VmSwap counter"))?;
            if words.next() != Some("kB") || words.next().is_some() {
                return Err(invalid("invalid process VmSwap units"));
            }
            swap = Some(
                kib.checked_mul(1024)
                    .ok_or_else(|| invalid("process VmSwap byte overflow"))?,
            );
        }
    }
    match swap {
        Some(value) => Ok(value),
        None if !has_address_space && status.lines().any(|line| line.starts_with("Name:")) => Ok(0),
        None => Err(invalid("process status lacks VmSwap evidence")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parser_distinguishes_zero_missing_malformed_and_overflow() {
        assert_eq!(
            parse_vm_swap("Name:\tbuild\nVmSize:\t10 kB\nVmSwap:\t4 kB\n").unwrap(),
            4096
        );
        assert_eq!(parse_vm_swap("Name:\tkworker\nState:\tS\n").unwrap(), 0);
        for text in [
            "",
            "Name:\tbuild\nVmSize:\t10 kB",
            "VmSwap: 1 MB",
            "VmSwap: -1 kB",
            "VmSwap: 18446744073709551615 kB",
            "VmSwap: 1 kB\nVmSwap: 1 kB",
            "VmSwap: 1 kB garbage",
        ] {
            assert!(parse_vm_swap(text).is_err(), "{text}");
        }
    }

    fn record(id: u64, parent: u64, minor: u32, point: &str, fs_type: &str) -> MountRecord {
        MountRecord {
            id,
            parent,
            major: 0,
            minor,
            mount_point: PathBuf::from(point),
            fs_type: fs_type.into(),
        }
    }

    /// `/` on ext4 with a tmpfs `/tmp`, as mountinfo lists a typical host.
    fn host() -> Vec<MountRecord> {
        vec![
            record(25, 1, 2, "/", "ext4"),
            record(26, 25, 30, "/tmp", "tmpfs"),
            record(27, 25, 31, "/run", "tmpfs"),
            record(28, 27, 32, "/run/user/1000", "tmpfs"),
        ]
    }

    /// Path lookups of a fake mount namespace: the minor device reached, or
    /// an errno. Unlisted paths do not exist.
    struct Lookups(BTreeMap<PathBuf, Result<u32, i32>>);

    impl Lookups {
        fn new(entries: &[(&str, Result<u32, i32>)]) -> Self {
            Self(
                entries
                    .iter()
                    .map(|(path, outcome)| (PathBuf::from(path), *outcome))
                    .collect(),
            )
        }

        fn identity(&self, path: &Path) -> io::Result<(u64, u64)> {
            match self.0.get(path).copied().unwrap_or(Err(libc::ENOENT)) {
                Ok(minor) => Ok((libc::makedev(0, minor), 1)),
                Err(errno) => Err(io::Error::from_raw_os_error(errno)),
            }
        }
    }

    /// Capacity counters every fake tmpfs reports.
    fn tmpfs_stats() -> MountStats {
        MountStats {
            tmpfs: true,
            block_size: 1,
            blocks: 100,
            free_blocks: 60,
            available_blocks: 50,
        }
    }

    struct LookupReader<'a> {
        table: &'a [MountRecord],
        lookups: &'a Lookups,
    }

    impl MountReader for LookupReader<'_> {
        type Handle = MountIdentity;

        fn open(&self, path: &Path) -> io::Result<MountIdentity> {
            let (device, inode) = self.lookups.identity(path)?;
            let topology = Topology::new(self.table);
            let mount_id = self
                .table
                .iter()
                .find(|record| {
                    record.mount_point == path
                        && record.has_device(device)
                        && topology.reach(record) == Reach::Reachable
                })
                .map_or(u64::MAX, |record| record.id);
            Ok(MountIdentity {
                device,
                inode,
                mount_id,
            })
        }

        fn identity(&self, handle: &MountIdentity) -> io::Result<MountIdentity> {
            Ok(*handle)
        }

        fn stats(&self, _handle: &MountIdentity) -> io::Result<MountStats> {
            Ok(tmpfs_stats())
        }
    }

    fn observe(
        table: &[MountRecord],
        lookups: &Lookups,
        relist: &dyn Fn() -> io::Result<Vec<MountRecord>>,
    ) -> (Vec<ScratchMount>, Vec<ScratchIssue>) {
        observe_mounts(
            table,
            64,
            Instant::now() + Duration::from_secs(60),
            &LookupReader { table, lookups },
            relist,
        )
    }

    fn kinds(issues: &[ScratchIssue]) -> Vec<&'static str> {
        issues.iter().map(|issue| issue.kind).collect()
    }

    struct ScriptedReader<'a> {
        open: &'a dyn Fn(&Path) -> io::Result<MountIdentity>,
        identity: &'a dyn Fn(&MountIdentity) -> io::Result<MountIdentity>,
        stats: &'a dyn Fn(&MountIdentity) -> io::Result<MountStats>,
    }

    impl MountReader for ScriptedReader<'_> {
        type Handle = MountIdentity;

        fn open(&self, path: &Path) -> io::Result<MountIdentity> {
            (self.open)(path)
        }
        fn identity(&self, handle: &MountIdentity) -> io::Result<MountIdentity> {
            (self.identity)(handle)
        }
        fn stats(&self, handle: &MountIdentity) -> io::Result<MountStats> {
            (self.stats)(handle)
        }
    }

    fn tmp_identity() -> MountIdentity {
        MountIdentity {
            device: libc::makedev(0, 30),
            inode: 1,
            mount_id: 26,
        }
    }

    fn finish_fixture(mounts: Vec<ScratchMount>, issues: Vec<ScratchIssue>) -> ScratchReport {
        finish_report(
            Ok(MemoryInfo {
                total_bytes: 1000,
                available_bytes: 900,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            }),
            mounts,
            ProcessSwap {
                complete: true,
                ..ProcessSwap::default()
            },
            issues,
        )
    }

    #[test]
    fn host_collection_failures_keep_structured_incomplete_reports() {
        let report = finish_report(
            Err(io::Error::from_raw_os_error(libc::EACCES)),
            Vec::new(),
            ProcessSwap::default(),
            vec![ScratchIssue::new("mount_covered", "covered fixture".into())],
        );
        assert!(report.supported);
        assert!(!report.complete);
        assert!(report.assessment.is_none());
        assert_eq!(report.exit_code, 4);
        assert_eq!(
            kinds(&report.issue_details),
            ["mount_covered", "collection_failed"]
        );
        assert_eq!(report.issue_details[1].operation, Some("memory_info"));
        assert_eq!(report.issue_details[1].os_error, Some(libc::EACCES));
        let json = serde_json::to_value(&report).unwrap();
        assert!(
            json["assessment"].is_null(),
            "unknown counters are not zero"
        );
        assert_eq!(json["issues"][1], json["issue_details"][1]["message"]);
    }

    #[test]
    fn invalid_host_counters_and_overflow_are_incomplete_assessments() {
        for memory in [
            MemoryInfo {
                total_bytes: 100,
                available_bytes: 101,
                swap_total_bytes: 0,
                swap_free_bytes: 0,
            },
            MemoryInfo {
                total_bytes: u64::MAX,
                available_bytes: 1,
                swap_total_bytes: 1,
                swap_free_bytes: 0,
            },
        ] {
            let report = finish_report(Ok(memory), Vec::new(), ProcessSwap::default(), Vec::new());
            assert!(report.supported);
            assert!(!report.complete);
            assert!(report.assessment.is_none());
            assert_eq!(report.exit_code, 4);
            assert_eq!(kinds(&report.issue_details), ["collection_failed"]);
            assert_eq!(report.issue_details[0].operation, Some("assessment"));
        }
    }

    #[test]
    fn capacity_sampling_keeps_the_opened_mount_across_an_a_b_a_path_change() {
        let original = tmp_identity();
        let replacement = MountIdentity {
            mount_id: 99,
            device: libc::makedev(0, 99),
            ..original
        };
        let path_identity = std::cell::Cell::new(original);
        let opens = std::cell::Cell::new(0);
        let open = |_: &Path| {
            opens.set(opens.get() + 1);
            Ok(path_identity.get())
        };
        let stats = |handle: &MountIdentity| {
            assert_eq!(opens.get(), 1, "capacity must use the retained descriptor");
            path_identity.set(replacement);
            // The temporary cover has different occupancy. A new pathname
            // lookup would return it, although before/after identities agree.
            let measured = if *handle == original {
                tmpfs_stats()
            } else {
                MountStats {
                    free_blocks: 1,
                    available_blocks: 1,
                    ..tmpfs_stats()
                }
            };
            assert_ne!(*handle, path_identity.get());
            path_identity.set(original);
            Ok(measured)
        };
        let reader = ScriptedReader {
            open: &open,
            identity: &|handle| Ok(*handle),
            stats: &stats,
        };
        let (mounts, issues) = observe_mounts(
            &host()[..2],
            64,
            Instant::now() + Duration::from_secs(60),
            &reader,
            &|| panic!("no failed lookup"),
        );
        let report = finish_fixture(mounts, issues);
        assert!(report.complete);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.assessment.unwrap().tmpfs_used_bytes, 40);
        assert_eq!(
            opens.get(),
            2,
            "the second open only verifies final identity"
        );
        assert_eq!(path_identity.get(), original);
    }

    #[test]
    fn a_persistent_overmount_during_sampling_keeps_the_report_incomplete() {
        let original = tmp_identity();
        let replacement = MountIdentity {
            mount_id: 99,
            device: libc::makedev(0, 99),
            ..original
        };
        let path_identity = std::cell::Cell::new(original);
        let reader = ScriptedReader {
            open: &|_| Ok(path_identity.get()),
            identity: &|handle| Ok(*handle),
            stats: &|handle| {
                assert_eq!(*handle, original);
                path_identity.set(replacement);
                Ok(tmpfs_stats())
            },
        };
        let (mounts, issues) = observe_mounts(
            &host()[..2],
            64,
            Instant::now() + Duration::from_secs(60),
            &reader,
            &|| panic!("identity mismatch is explicit"),
        );
        assert!(mounts.is_empty());
        assert_eq!(kinds(&issues), ["mount_replaced"]);
        assert_eq!(issues[0].operation, Some("verify_path"));
        assert_eq!(issues[0].observed_mount_id, Some(99));
        let report = finish_fixture(mounts, issues);
        assert!(!report.complete);
        assert_eq!(report.exit_code, 4);
    }

    #[test]
    fn a_same_device_replacement_requires_the_listed_mount_identity() {
        let other = MountIdentity {
            mount_id: 99,
            ..tmp_identity()
        };
        let reader = ScriptedReader {
            open: &|_| Ok(other),
            identity: &|handle| Ok(*handle),
            stats: &|_| panic!("a replaced mount must not supply counters"),
        };
        let (mounts, issues) = observe_mounts(
            &host()[..2],
            64,
            Instant::now() + Duration::from_secs(60),
            &reader,
            &|| panic!("identity mismatch is explicit"),
        );
        assert!(mounts.is_empty());
        assert_eq!(kinds(&issues), ["mount_replaced"]);
        assert_eq!(issues[0].mount_id, Some(26));
        assert_eq!(issues[0].observed_mount_id, Some(99));
        let report = finish_fixture(mounts, issues);
        assert!(!report.complete);
        assert_eq!(report.exit_code, 4);
    }

    #[test]
    fn every_measurement_stage_preserves_permission_denial_and_errno() {
        for operation in ["open", "identity", "capacity", "verify_path"] {
            let opens = std::cell::Cell::new(0);
            let open = |_: &Path| {
                opens.set(opens.get() + 1);
                if operation == "open" || (operation == "verify_path" && opens.get() == 2) {
                    Err(io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    Ok(tmp_identity())
                }
            };
            let identity = |handle: &MountIdentity| {
                if operation == "identity" {
                    Err(io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    Ok(*handle)
                }
            };
            let stats = |_: &MountIdentity| {
                if operation == "capacity" {
                    Err(io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    Ok(tmpfs_stats())
                }
            };
            let reader = ScriptedReader {
                open: &open,
                identity: &identity,
                stats: &stats,
            };
            let (mounts, issues) = observe_mounts(
                &host()[..2],
                64,
                Instant::now() + Duration::from_secs(60),
                &reader,
                &|| panic!("permission failure is not disappearance"),
            );
            assert!(mounts.is_empty());
            assert_eq!(kinds(&issues), ["permission_denied"], "{operation}");
            assert_eq!(issues[0].os_error, Some(libc::EACCES));
            assert_eq!(issues[0].operation, Some(operation));
            let report = finish_fixture(mounts, issues);
            assert!(!report.complete);
            assert_eq!(report.exit_code, 4);
        }
    }

    #[test]
    fn capacity_failures_distinguish_disappearance_and_io_errors() {
        for (errno, expected) in [
            (libc::ENOENT, "mount_vanished"),
            (libc::EIO, "mount_inspection_failed"),
        ] {
            let stats = |_: &MountIdentity| Err(io::Error::from_raw_os_error(errno));
            let reader = ScriptedReader {
                open: &|_| Ok(tmp_identity()),
                identity: &|handle| Ok(*handle),
                stats: &stats,
            };
            let (mounts, issues) = observe_mounts(
                &host()[..2],
                64,
                Instant::now() + Duration::from_secs(60),
                &reader,
                &|| Ok(vec![host()[0].clone()]),
            );
            assert!(mounts.is_empty());
            assert_eq!(kinds(&issues), [expected]);
            assert_eq!(issues[0].os_error, Some(errno));
            assert_eq!(issues[0].operation, Some("capacity"));
            assert_eq!(finish_fixture(mounts, issues).exit_code, 4);
        }
    }

    #[test]
    fn unavailable_descriptor_identity_never_falls_back_to_device_only() {
        let reader = ScriptedReader {
            open: &|_| Ok(tmp_identity()),
            identity: &|_| Err(io::Error::from_raw_os_error(libc::ENOSYS)),
            stats: &|_| panic!("unknown mount identity cannot supply counters"),
        };
        let (mounts, issues) = observe_mounts(
            &host()[..2],
            64,
            Instant::now() + Duration::from_secs(60),
            &reader,
            &|| Ok(host()),
        );
        assert!(mounts.is_empty());
        assert_eq!(kinds(&issues), ["mount_identity_unavailable"]);
        assert_eq!(issues[0].os_error, Some(libc::ENOSYS));
        assert_eq!(finish_fixture(mounts, issues).exit_code, 4);
    }

    #[test]
    fn descriptor_fallback_and_metadata_byte_budgets_are_explicit() {
        assert_eq!(
            parse_fdinfo_mount_id(b"pos:\t0\nflags:\t012000000\nmnt_id:\t26\nino:\t1\n").unwrap(),
            26
        );
        for raw in [
            b"".as_slice(),
            b"mnt_id: x\n",
            b"mnt_id: 1 extra\n",
            b"mnt_id: 1\nmnt_id: 2\n",
        ] {
            assert!(parse_fdinfo_mount_id(raw).is_err());
        }
        assert_eq!(read_bounded(b"1234".as_slice(), 4).unwrap(), b"1234");
        let error = read_bounded(b"12345".as_slice(), 4).unwrap_err();
        let issue = mount_table_issue(&error);
        assert_eq!(issue.kind, "mount_table_budget_exhausted");
        assert_eq!(issue.operation, Some("mount_table"));
        let report = finish_fixture(Vec::new(), vec![issue]);
        assert!(!report.complete);
        assert_eq!(report.exit_code, 4);
        assert_eq!(report.issue_details.len(), report.issues.len());
    }

    #[test]
    fn inconsistent_or_overflowing_descriptor_counters_are_unknown() {
        for stats in [
            MountStats {
                block_size: 0,
                ..tmpfs_stats()
            },
            MountStats {
                free_blocks: 101,
                ..tmpfs_stats()
            },
            MountStats {
                available_blocks: 61,
                ..tmpfs_stats()
            },
            MountStats {
                block_size: u64::MAX,
                ..tmpfs_stats()
            },
        ] {
            let reader = ScriptedReader {
                open: &|_| Ok(tmp_identity()),
                identity: &|handle| Ok(*handle),
                stats: &|_| Ok(stats),
            };
            let (mounts, issues) = observe_mounts(
                &host()[..2],
                64,
                Instant::now() + Duration::from_secs(60),
                &reader,
                &|| Ok(host()),
            );
            assert!(mounts.is_empty());
            assert_eq!(kinds(&issues), ["mount_counters_inconsistent"]);
            assert_eq!(finish_fixture(mounts, issues).exit_code, 4);
        }
    }

    #[test]
    fn native_descriptor_identity_matches_its_mountinfo_record_read_only() {
        let reader = NativeMountReader;
        let handle = reader.open(Path::new("/")).unwrap();
        let identity = reader.identity(&handle).unwrap();
        let table = read_mountinfo().unwrap();
        let record = table
            .iter()
            .find(|record| record.id == identity.mount_id)
            .unwrap();
        assert!(record.has_device(identity.device));
        assert_eq!(reader.identity(&handle).unwrap(), identity);
        let stats = reader.stats(&handle).unwrap();
        assert_eq!(stats.tmpfs, record.fs_type == "tmpfs");
        // This directly exercises O_PATH + fstatfs without mount manipulation.
        assert!(stats.block_size > 0);
    }

    #[test]
    fn mountinfo_records_keep_ids_devices_and_escaped_paths() {
        let raw = b"25 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
            30 25 0:26 / /run rw,nosuid shared:5 master:2 - tmpfs tmpfs rw,size=1g\n\
            41 30 0:52 /sub /run/a\\040b\\134c\\377 rw - tmpfs none rw\n";
        let records = parse_mountinfo(raw).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(
            (
                records[1].id,
                records[1].parent,
                records[1].major,
                records[1].minor
            ),
            (30, 25, 0, 26)
        );
        assert_eq!(records[0].fs_type, "ext4");
        assert_eq!(
            records[2].mount_point,
            PathBuf::from(OsString::from_vec(b"/run/a b\\c\xff".to_vec()))
        );
        assert!(records[1].has_device(libc::makedev(0, 26)));
        assert!(!records[1].has_device(libc::makedev(0, 27)));
        assert!(!records[1].has_device(libc::makedev(1, 26)));
        for raw in [
            &b""[..],
            b"25 1 8:2 / / rw - ext4 /dev/sda2 rw",
            b"25 1 8:2 / / rw ext4 /dev/sda2 rw\n",
            b"25 1 8-2 / / rw - ext4 /dev/sda2 rw\n",
            b"x 1 8:2 / / rw - ext4 /dev/sda2 rw\n",
            b"25 1 8:2 / relative rw - ext4 /dev/sda2 rw\n",
            b"25 1 8:2 / /a\\09x rw - ext4 /dev/sda2 rw\n",
            b"25 1 8:2 / /a\\000 rw - ext4 /dev/sda2 rw\n",
            b"25 1 8:2 / / rw - \n",
            b"25 1 8:2 / / rw - ext4 a rw\n25 1 0:3 / /x rw - tmpfs b rw\n",
        ] {
            assert!(
                parse_mountinfo(raw).is_err(),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn covers_are_found_from_the_route_not_from_table_order() {
        let mut table = host();
        table.extend([
            // The reported fixture: a bind over /tmp/w/parent hides a tmpfs
            // that was mounted beneath it first.
            record(50, 26, 50, "/tmp/w/parent/covered", "tmpfs"),
            record(51, 26, 30, "/tmp/w/parent", "tmpfs"),
            // Two tmpfs stacked on one mount point: the later one is a child.
            record(60, 25, 60, "/x", "tmpfs"),
            record(61, 60, 61, "/x", "tmpfs"),
            // A mount stacked on an ancestor of a tmpfs.
            record(70, 25, 70, "/a", "ext4"),
            record(71, 70, 71, "/a/b", "tmpfs"),
            record(72, 70, 72, "/a", "tmpfs"),
            // A submount of a tmpfs does not hide it.
            record(80, 25, 80, "/y", "tmpfs"),
            record(81, 80, 81, "/y/z", "tmpfs"),
            // Of two covers, the outermost is where lookup leaves the route.
            record(90, 25, 90, "/p/q/r", "tmpfs"),
            record(91, 25, 91, "/p/q", "ext4"),
            record(92, 25, 92, "/p", "ext4"),
            // Looping parent links.
            record(100, 101, 100, "/l", "tmpfs"),
            record(101, 100, 101, "/l/m", "tmpfs"),
            // A copy attached to "/" below "/k", where lookup has already left
            // "/" for 110, is hidden itself and hides nothing.
            record(110, 25, 110, "/k", "ext4"),
            record(111, 25, 111, "/k/s", "tmpfs"),
            record(112, 110, 111, "/k/s", "tmpfs"),
        ]);
        let topology = Topology::new(&table);
        let reach = |id: u64| topology.reach(table.iter().find(|r| r.id == id).unwrap());
        let cover = |id: u64| match reach(id) {
            Reach::Covered(cover) => Some(cover.id),
            Reach::Reachable => None,
            Reach::Unresolved => panic!("{id} unresolved"),
        };
        for id in [25, 26, 27, 28, 51, 61, 80, 81, 112] {
            assert_eq!(cover(id), None, "{id}");
        }
        assert_eq!(cover(111), Some(110));
        assert_eq!(cover(50), Some(51));
        assert_eq!(cover(60), Some(61));
        assert_eq!(cover(71), Some(72));
        assert_eq!(cover(90), Some(92));
        assert_eq!(reach(100), Reach::Unresolved);
        // A namespace root may name itself as its parent.
        let root = [record(1, 1, 5, "/", "tmpfs")];
        assert_eq!(Topology::new(&root).reach(&root[0]), Reach::Reachable);
    }

    #[test]
    fn a_normal_host_report_is_complete_and_counts_each_mount() {
        let table = host();
        let lookups = Lookups::new(&[
            ("/tmp", Ok(30)),
            ("/run", Ok(31)),
            ("/run/user/1000", Ok(32)),
        ]);
        let (mounts, issues) = observe(&table, &lookups, &|| panic!("no re-read needed"));
        assert!(issues.is_empty(), "{issues:?}");
        let paths: Vec<_> = mounts.iter().map(|mount| mount.path.as_str()).collect();
        assert_eq!(paths, ["/tmp", "/run", "/run/user/1000"]);
        assert_eq!(mounts[0].filesystem_id, libc::makedev(0, 30));
        assert_eq!(mounts[0].used_bytes, 40);
    }

    #[test]
    fn a_covered_tmpfs_is_reported_with_its_cover_and_never_measured() {
        let mut table = host();
        table.extend([
            record(50, 26, 50, "/tmp/w/parent/covered", "tmpfs"),
            record(51, 26, 30, "/tmp/w/parent", "tmpfs"),
        ]);
        let lookups = Lookups::new(&[
            ("/tmp", Ok(30)),
            ("/run", Ok(31)),
            ("/run/user/1000", Ok(32)),
            ("/tmp/w/parent", Ok(30)),
        ]);
        let (mounts, issues) = observe(&table, &lookups, &|| panic!("a cover needs no re-read"));
        assert_eq!(kinds(&issues), ["mount_covered"]);
        let issue = &issues[0];
        assert_eq!(issue.path.as_deref(), Some("/tmp/w/parent/covered"));
        assert_eq!(issue.mount_id, Some(50));
        assert_eq!(
            issue.os_error, None,
            "topology does not invent a failed syscall"
        );
        assert_eq!(issue.operation, Some("topology"));
        assert_eq!(
            issue.covered_by,
            Some(CoveringMount {
                mount_id: 51,
                path: "/tmp/w/parent".into(),
                fs_type: "tmpfs".into(),
            })
        );
        assert!(
            issue
                .message
                .contains("covered in the observed mount table by mount 51"),
            "{}",
            issue.message
        );
        assert!(
            mounts
                .iter()
                .all(|mount| mount.path != "/tmp/w/parent/covered"),
            "{mounts:?}"
        );
        let report = finish_fixture(mounts, issues);
        assert!(!report.complete);
        assert_eq!(report.exit_code, 4);
        assert_eq!(report.assessment.as_ref().unwrap().tmpfs_used_bytes, 120);
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }

    /// Lookup of a stacked mount point succeeds, but reaches the upper tmpfs.
    /// Counting the lower one through it hid the lower one's memory.
    #[test]
    fn a_tmpfs_stacked_under_another_is_unknown_not_counted_as_the_upper_one() {
        let mut table = host();
        table.extend([
            record(60, 25, 60, "/x", "tmpfs"),
            record(61, 60, 61, "/x", "tmpfs"),
        ]);
        let lookups = Lookups::new(&[
            ("/tmp", Ok(30)),
            ("/run", Ok(31)),
            ("/run/user/1000", Ok(32)),
            ("/x", Ok(61)),
        ]);
        let (mounts, issues) = observe(&table, &lookups, &|| panic!("a cover needs no re-read"));
        assert_eq!(kinds(&issues), ["mount_covered"]);
        assert_eq!(issues[0].mount_id, Some(60));
        assert_eq!(issues[0].os_error, None);
        assert_eq!(
            issues[0].covered_by.as_ref().map(|cover| cover.mount_id),
            Some(61)
        );
        let upper: Vec<_> = mounts.iter().filter(|mount| mount.path == "/x").collect();
        assert_eq!(upper.len(), 1, "{mounts:?}");
        assert_eq!(upper[0].filesystem_id, libc::makedev(0, 61));
    }

    /// A propagated or bind copy hidden under a mount is the same filesystem
    /// as a copy that was measured, so nothing is missing.
    #[test]
    fn a_covered_copy_of_a_measured_filesystem_is_an_alias() {
        let mut table = host();
        table.extend([
            record(70, 25, 70, "/k", "ext4"),
            record(71, 25, 40, "/k/pods/secret", "tmpfs"),
            record(72, 70, 40, "/k/pods/secret", "tmpfs"),
            record(73, 25, 40, "/k/other/secret", "tmpfs"),
        ]);
        let lookups = Lookups::new(&[
            ("/tmp", Ok(30)),
            ("/run", Ok(31)),
            ("/run/user/1000", Ok(32)),
            ("/k/pods/secret", Ok(40)),
        ]);
        let (mounts, issues) = observe(&table, &lookups, &|| panic!("a cover needs no re-read"));
        assert!(issues.is_empty(), "{issues:?}");
        let copies: Vec<_> = mounts
            .iter()
            .filter(|mount| mount.filesystem_id == libc::makedev(0, 40))
            .map(|mount| mount.path.as_str())
            .collect();
        assert_eq!(
            copies,
            ["/k/pods/secret", "/k/pods/secret", "/k/other/secret"]
        );
    }

    #[test]
    fn uncovered_failures_say_whether_the_mount_vanished_or_was_denied() {
        let table = host();
        let lookups = Lookups::new(&[
            ("/tmp", Err(libc::ENOENT)),
            ("/run", Err(libc::EACCES)),
            ("/run/user/1000", Err(libc::EIO)),
        ]);
        let without_tmp = || {
            Ok(host()
                .into_iter()
                .filter(|record| record.id != 26)
                .collect())
        };
        let (mounts, issues) = observe(&table, &lookups, &without_tmp);
        assert!(mounts.is_empty());
        assert_eq!(
            kinds(&issues),
            [
                "mount_vanished",
                "permission_denied",
                "mount_inspection_failed"
            ]
        );
        assert_eq!(issues[1].os_error, Some(libc::EACCES));
        assert_eq!(issues[2].os_error, Some(libc::EIO));

        let lookups = Lookups::new(&[
            ("/tmp", Err(libc::ENOENT)),
            ("/run", Ok(31)),
            ("/run/user/1000", Ok(32)),
        ]);
        let (_, issues) = observe(&table, &lookups, &|| Ok(host()));
        assert_eq!(kinds(&issues), ["mount_not_addressable"]);
        let (_, issues) = observe(&table, &lookups, &|| Err(invalid("unreadable")));
        assert_eq!(kinds(&issues), ["mount_not_addressable"]);
        assert!(
            issues[0].message.contains("unreadable"),
            "{}",
            issues[0].message
        );
    }

    #[test]
    fn a_path_reaching_another_device_is_a_replaced_mount() {
        let table = host();
        let lookups = Lookups::new(&[
            ("/tmp", Ok(99)),
            ("/run", Ok(31)),
            ("/run/user/1000", Ok(32)),
        ]);
        let (mounts, issues) = observe(&table, &lookups, &|| Ok(host()));
        assert_eq!(kinds(&issues), ["mount_replaced"]);
        assert!(
            issues[0].message.contains("device 0:99"),
            "{}",
            issues[0].message
        );
        assert_eq!(mounts.len(), 2);

        // A descriptor identity which changes cannot certify any counters.
        let changed = std::cell::Cell::new(false);
        let reader = ScriptedReader {
            open: &|_| Ok(tmp_identity()),
            identity: &|_| {
                Ok(MountIdentity {
                    device: libc::makedev(0, if changed.replace(true) { 98 } else { 30 }),
                    ..tmp_identity()
                })
            },
            stats: &|_| Ok(tmpfs_stats()),
        };
        let (_, issues) = observe_mounts(
            &table[..2],
            64,
            Instant::now() + Duration::from_secs(60),
            &reader,
            &|| Ok(host()),
        );
        assert_eq!(kinds(&issues), ["mount_replaced"]);
        assert!(issues[0].message.contains("changed during inspection"));
    }

    #[test]
    fn ramfs_and_the_mount_budget_stay_incomplete() {
        let mut table = host();
        table.push(record(29, 27, 33, "/run/credentials/a.service", "ramfs"));
        let lookups = Lookups::new(&[
            ("/tmp", Ok(30)),
            ("/run", Ok(31)),
            ("/run/user/1000", Ok(32)),
        ]);
        let (_, issues) = observe(&table, &lookups, &|| Ok(host()));
        assert_eq!(kinds(&issues), ["ramfs_unmeasurable"]);
        let (mounts, issues) = observe_mounts(
            &table,
            1,
            Instant::now() + Duration::from_secs(60),
            &LookupReader {
                table: &table,
                lookups: &lookups,
            },
            &|| Ok(host()),
        );
        assert_eq!(mounts.len(), 1);
        assert_eq!(kinds(&issues), ["mount_budget_exhausted"]);
    }
}
