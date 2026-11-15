//! Read-only allocation evidence for unlinked files retained by visible FDs.
//!
//! Only procfs metadata (`stat`, `fdinfo`, `mountinfo`) is opened for reading.
//! The descriptor targets themselves are never opened, truncated or signalled.
//! PID start ticks bracket each process sweep and inode identity brackets each
//! descriptor observation. This is diagnostic evidence, never deletion consent.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

use crate::core::errors::{Result, SbhError};
use crate::platform::types::{
    DeletedOpenFile, DeletedOpenFileHolder, DeletedOpenFilesLimits, DeletedOpenFilesReport,
};

const MAX_STAT_BYTES: u64 = 16 * 1024;
const MAX_FDINFO_BYTES: u64 = 16 * 1024;
const MAX_MOUNTINFO_BYTES: u64 = 4 * 1024 * 1024;

type FileKey = (u64, u64);
type MountTable = BTreeMap<u64, MountRecord>;

struct ProcessIdentity {
    start_ticks: u64,
    name: String,
}

struct MountRecord {
    device: u64,
    point: Vec<u8>,
    filesystem_type: String,
}

struct Observation {
    allocated_bytes: u64,
    logical_bytes: u64,
    holder: DeletedOpenFileHolder,
}

struct Sweep {
    deadline: Instant,
    limits: DeletedOpenFilesLimits,
    report: DeletedOpenFilesReport,
    files: BTreeMap<FileKey, DeletedOpenFile>,
    holders: usize,
    stopped: bool,
}

impl Sweep {
    fn new(deadline: Instant, limits: DeletedOpenFilesLimits) -> Self {
        Self {
            deadline,
            limits,
            report: DeletedOpenFilesReport {
                supported: true,
                complete: true,
                observed_allocated_bytes: Some(0),
                processes_scanned: 0,
                descriptors_scanned: 0,
                issues: BTreeMap::new(),
                files: Vec::new(),
            },
            files: BTreeMap::new(),
            holders: 0,
            stopped: false,
        }
    }

    fn issue(&mut self, reason: &'static str) {
        self.report.complete = false;
        let count = self.report.issues.entry(reason.to_string()).or_default();
        *count = count.saturating_add(1);
    }

    fn stop(&mut self, reason: &'static str) {
        self.issue(reason);
        self.stopped = true;
    }

    fn expired(&mut self) -> bool {
        if Instant::now() < self.deadline {
            return false;
        }
        if !self.report.issues.contains_key("deadline_reached") {
            self.stop("deadline_reached");
        }
        true
    }

    fn process(
        &mut self,
        directory: &Path,
        pid: i32,
        before_verification: &mut impl FnMut(i32, Option<u32>),
    ) {
        if self.expired() {
            return;
        }
        self.report.processes_scanned += 1;
        let before = match read_identity(directory, pid, self.deadline) {
            Ok(identity) => identity,
            Err(error) => {
                self.issue(process_read_issue(&error));
                self.expired();
                return;
            }
        };
        let observations = self.descriptors(directory, pid, &before, before_verification);
        // No unverified partial process may survive a deadline, exit or PID
        // reuse. Earlier independently verified processes remain reportable.
        if self.expired() {
            return;
        }
        before_verification(pid, None);
        let after = match read_identity(directory, pid, self.deadline) {
            Ok(identity) => identity,
            Err(error) => {
                self.issue(process_read_issue(&error));
                self.expired();
                return;
            }
        };
        if before.start_ticks != after.start_ticks {
            self.issue("process_identity_changed");
            return;
        }
        for ((device_id, inode), mut observation) in observations {
            // comm can change across exec without recycling the process. Its
            // final name describes the identity that still held these FDs.
            observation.holder.name.clone_from(&after.name);
            let file = self
                .files
                .entry((device_id, inode))
                .or_insert_with(|| DeletedOpenFile {
                    device_id,
                    inode,
                    allocated_bytes: 0,
                    logical_bytes: 0,
                    holders: Vec::new(),
                });
            // Use the latest verified allocation, never a sum of references or
            // a historical maximum after a live file was truncated.
            file.allocated_bytes = observation.allocated_bytes;
            file.logical_bytes = observation.logical_bytes;
            file.holders.push(observation.holder);
            self.holders += 1;
        }
    }

    fn descriptors(
        &mut self,
        directory: &Path,
        pid: i32,
        identity: &ProcessIdentity,
        before_verification: &mut impl FnMut(i32, Option<u32>),
    ) -> BTreeMap<FileKey, Observation> {
        let mut observations: BTreeMap<FileKey, Observation> = BTreeMap::new();
        if self.expired() {
            return observations;
        }
        let descriptors = match fs::read_dir(directory.join("fd")) {
            Ok(entries) => entries,
            Err(error) => {
                self.issue(process_read_issue(&error));
                return observations;
            }
        };
        let mut new_files = 0;
        // Only a process with a discovered unlinked regular file needs its
        // mount table. A failed table is not repeatedly retried for every FD.
        let mut mounts: Option<Option<MountTable>> = None;
        for entry in descriptors {
            if self.expired() {
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    self.issue("descriptor_inventory_unreadable");
                    break;
                }
            };
            let Some(fd) =
                decimal(entry.file_name().as_bytes()).and_then(|n| u32::try_from(n).ok())
            else {
                continue;
            };
            if self.report.descriptors_scanned >= self.limits.max_descriptors {
                self.stop("descriptor_limit_reached");
                break;
            }
            self.report.descriptors_scanned += 1;
            let path = entry.path();
            let before_meta = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    self.issue(descriptor_read_issue(&error));
                    continue;
                }
            };
            if !unlinked_regular(&before_meta) {
                continue;
            }
            let key = (before_meta.dev(), before_meta.ino());
            if !observations.contains_key(&key) {
                if self.holders + observations.len() >= self.limits.max_holders {
                    self.stop("holder_limit_reached");
                    break;
                }
                if !self.files.contains_key(&key)
                    && self.files.len() + new_files >= self.limits.max_files
                {
                    self.stop("file_limit_reached");
                    break;
                }
            }
            let Some(observation) = self.descriptor(
                directory,
                &path,
                pid,
                fd,
                identity,
                &before_meta,
                &mut mounts,
                before_verification,
            ) else {
                continue;
            };
            if let Some(existing) = observations.get_mut(&key) {
                existing.allocated_bytes = observation.allocated_bytes;
                existing.logical_bytes = observation.logical_bytes;
                let count = existing.holder.descriptor_count + 1;
                if observation.holder.fd < existing.holder.fd {
                    existing.holder = observation.holder;
                }
                existing.holder.descriptor_count = count;
            } else {
                new_files += usize::from(!self.files.contains_key(&key));
                observations.insert(key, observation);
            }
        }
        observations
    }

    #[allow(clippy::too_many_arguments)]
    fn descriptor(
        &mut self,
        directory: &Path,
        path: &Path,
        pid: i32,
        fd: u32,
        identity: &ProcessIdentity,
        before: &fs::Metadata,
        mounts: &mut Option<Option<MountTable>>,
        before_verification: &mut impl FnMut(i32, Option<u32>),
    ) -> Option<Observation> {
        if self.expired() {
            return None;
        }
        let target = match fs::read_link(path) {
            Ok(target) => target,
            Err(error) => {
                self.issue(descriptor_read_issue(&error));
                return None;
            }
        };
        if self.expired() {
            return None;
        }
        let mount_id = match read_bounded(
            &directory.join("fdinfo").join(fd.to_string()),
            MAX_FDINFO_BYTES,
            self.deadline,
        ) {
            Ok(raw) => match parse_fdinfo(&raw, before.ino()) {
                Ok(mount_id) => Some(mount_id),
                Err(_) => {
                    self.issue("descriptor_metadata_changed");
                    return None;
                }
            },
            Err(_) => {
                self.issue("descriptor_mount_unavailable");
                None
            }
        };
        if self.expired() {
            return None;
        }
        let mount = self.mount(directory, mount_id, before.dev(), mounts);
        if self.expired() {
            return None;
        }
        before_verification(pid, Some(fd));
        let after = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.issue(descriptor_read_issue(&error));
                return None;
            }
        };
        if self.expired() {
            return None;
        }
        if !unlinked_regular(&after) || (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            self.issue("descriptor_identity_changed");
            return None;
        }
        let Some(allocated_bytes) = after.blocks().checked_mul(512) else {
            self.issue("allocated_bytes_overflow");
            return None;
        };
        Some(Observation {
            allocated_bytes,
            logical_bytes: after.len(),
            holder: DeletedOpenFileHolder {
                pid,
                start_time_ticks: identity.start_ticks,
                name: identity.name.clone(),
                fd,
                descriptor_count: 1,
                fd_target: target.to_string_lossy().into_owned(),
                fd_target_bytes_hex: crate::core::hex_lower(target.as_os_str().as_bytes()),
                mount_id,
                mount_point: mount.map(|mount| String::from_utf8_lossy(&mount.point).into_owned()),
                mount_point_bytes_hex: mount.map(|mount| crate::core::hex_lower(&mount.point)),
                filesystem_type: mount.map(|mount| mount.filesystem_type.clone()),
            },
        })
    }

    fn mount<'a>(
        &mut self,
        directory: &Path,
        mount_id: Option<u64>,
        device: u64,
        mounts: &'a mut Option<Option<MountTable>>,
    ) -> Option<&'a MountRecord> {
        let mount_id = mount_id?;
        if mounts.is_none() {
            let table = read_bounded(
                &directory.join("mountinfo"),
                MAX_MOUNTINFO_BYTES,
                self.deadline,
            )
            .and_then(|raw| parse_mountinfo(&raw, self.deadline));
            if table.is_err() {
                self.issue("mount_table_unavailable");
            }
            *mounts = Some(table.ok());
        }
        let table = mounts.as_ref()?.as_ref()?;
        match table.get(&mount_id) {
            Some(mount) if mount.device == device => Some(mount),
            Some(_) => {
                self.issue("mount_device_mismatch");
                None
            }
            None => {
                self.issue("mount_not_visible");
                None
            }
        }
    }

    fn finish(mut self) -> DeletedOpenFilesReport {
        self.report.files = std::mem::take(&mut self.files).into_values().collect();
        for file in &mut self.report.files {
            file.holders
                .sort_by_key(|holder| (holder.pid, holder.start_time_ticks));
        }
        self.report.files.sort_by(|left, right| {
            right
                .allocated_bytes
                .cmp(&left.allocated_bytes)
                .then_with(|| left.device_id.cmp(&right.device_id))
                .then_with(|| left.inode.cmp(&right.inode))
        });
        self.report.observed_allocated_bytes = self
            .report
            .files
            .iter()
            .try_fold(0_u64, |total, file| total.checked_add(file.allocated_bytes));
        if self.report.observed_allocated_bytes.is_none() {
            self.issue("allocated_bytes_overflow");
        }
        self.report
    }
}

pub(super) fn collect(
    proc_root: &Path,
    deadline: Instant,
    limits: DeletedOpenFilesLimits,
) -> Result<DeletedOpenFilesReport> {
    collect_with(proc_root, deadline, limits, &mut |_, _| {})
}

fn collect_with(
    proc_root: &Path,
    deadline: Instant,
    limits: DeletedOpenFilesLimits,
    before_verification: &mut impl FnMut(i32, Option<u32>),
) -> Result<DeletedOpenFilesReport> {
    let mut sweep = Sweep::new(deadline, limits);
    if sweep.expired() {
        return Ok(sweep.finish());
    }
    let entries = fs::read_dir(proc_root).map_err(|error| SbhError::io(proc_root, error))?;
    for entry in entries {
        if sweep.stopped || sweep.expired() {
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                sweep.issue("process_inventory_unreadable");
                break;
            }
        };
        let Some(pid) = decimal(entry.file_name().as_bytes())
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
        else {
            continue;
        };
        if sweep.report.processes_scanned >= limits.max_processes {
            sweep.stop("process_limit_reached");
            break;
        }
        sweep.process(&entry.path(), pid, before_verification);
    }
    sweep.expired();
    Ok(sweep.finish())
}

fn unlinked_regular(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && metadata.nlink() == 0
}

fn process_read_issue(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::NotFound => "process_disappeared",
        io::ErrorKind::PermissionDenied => "process_inaccessible",
        _ => "process_unreadable",
    }
}

fn descriptor_read_issue(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::NotFound => "descriptor_disappeared",
        io::ErrorKind::PermissionDenied => "descriptor_inaccessible",
        _ => "descriptor_unreadable",
    }
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "inventory deadline reached",
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64, deadline: Instant) -> io::Result<Vec<u8>> {
    check_deadline(deadline)?;
    let file = fs::File::open(path)?;
    check_deadline(deadline)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    check_deadline(deadline)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(invalid_metadata());
    }
    Ok(bytes)
}

fn read_identity(directory: &Path, pid: i32, deadline: Instant) -> io::Result<ProcessIdentity> {
    let raw = read_bounded(&directory.join("stat"), MAX_STAT_BYTES, deadline)?;
    let open = raw
        .iter()
        .position(|byte| *byte == b'(')
        .ok_or_else(invalid_metadata)?;
    let close = raw
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(invalid_metadata)?;
    if close <= open || decimal(raw[..open].trim_ascii()) != u64::try_from(pid).ok() {
        return Err(invalid_metadata());
    }
    let start_ticks = raw[close + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .nth(19)
        .and_then(decimal)
        .ok_or_else(invalid_metadata)?;
    Ok(ProcessIdentity {
        start_ticks,
        name: String::from_utf8_lossy(&raw[open + 1..close]).into_owned(),
    })
}

fn parse_fdinfo(raw: &[u8], expected_inode: u64) -> io::Result<u64> {
    let mut mount_id = None;
    for line in raw.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"mnt_id:") {
            if mount_id.is_some() {
                return Err(invalid_metadata());
            }
            mount_id = Some(decimal(value.trim_ascii()).ok_or_else(invalid_metadata)?);
        } else if let Some(value) = line.strip_prefix(b"ino:")
            && decimal(value.trim_ascii()) != Some(expected_inode)
        {
            return Err(invalid_metadata());
        }
    }
    mount_id.ok_or_else(invalid_metadata)
}

fn parse_mountinfo(raw: &[u8], deadline: Instant) -> io::Result<MountTable> {
    let mut mounts = BTreeMap::new();
    for line in raw
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        check_deadline(deadline)?;
        if line.contains(&0) {
            return Err(invalid_metadata());
        }
        let mut fields = line
            .split(|byte| matches!(byte, b' ' | b'\t'))
            .filter(|field| !field.is_empty());
        let id = fields
            .next()
            .and_then(decimal)
            .ok_or_else(invalid_metadata)?;
        let _parent = fields
            .next()
            .and_then(decimal)
            .ok_or_else(invalid_metadata)?;
        let device = fields.next().ok_or_else(invalid_metadata)?;
        let colon = device
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(invalid_metadata)?;
        let major = decimal(&device[..colon])
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(invalid_metadata)?;
        let minor = decimal(&device[colon + 1..])
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(invalid_metadata)?;
        let _root = fields.next().ok_or_else(invalid_metadata)?;
        let point = unescape_mount_point(fields.next().ok_or_else(invalid_metadata)?)?;
        let _options = fields.next().ok_or_else(invalid_metadata)?;
        if !fields.any(|field| field == b"-") {
            return Err(invalid_metadata());
        }
        let filesystem_type =
            String::from_utf8_lossy(fields.next().ok_or_else(invalid_metadata)?).into_owned();
        if mounts
            .insert(
                id,
                MountRecord {
                    device: libc::makedev(major, minor),
                    point,
                    filesystem_type,
                },
            )
            .is_some()
        {
            return Err(invalid_metadata());
        }
    }
    Ok(mounts)
}

fn unescape_mount_point(raw: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut offset = 0;
    while offset < raw.len() {
        if raw[offset] == b'\\' {
            let escaped = raw
                .get(offset + 1..offset + 4)
                .ok_or_else(invalid_metadata)?;
            out.push(match escaped {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid_metadata()),
            });
            offset += 4;
        } else {
            out.push(raw[offset]);
            offset += 1;
        }
    }
    if !out.starts_with(b"/") || out.contains(&0) {
        return Err(invalid_metadata());
    }
    Ok(out)
}

fn decimal(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() {
        return None;
    }
    raw.iter().try_fold(0_u64, |number, byte| {
        byte.is_ascii_digit()
            .then(|| number.checked_mul(10)?.checked_add(u64::from(byte - b'0')))
            .flatten()
    })
}

fn invalid_metadata() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or oversized procfs metadata",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::Duration;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn stat(directory: &Path, pid: i32, ticks: u64) {
        let mut fields = vec!["0".to_string(); 20];
        fields[0] = "S".to_string();
        fields[19] = ticks.to_string();
        fs::write(
            directory.join("stat"),
            format!("{pid} (fixture worker) {}\n", fields.join(" ")),
        )
        .unwrap();
    }

    fn process(root: &Path, pid: i32) -> PathBuf {
        let directory = root.join(pid.to_string());
        fs::create_dir_all(directory.join("fd")).unwrap();
        fs::create_dir_all(directory.join("fdinfo")).unwrap();
        stat(&directory, pid, 123);
        directory
    }

    fn add_fd(directory: &Path, descriptor: u32, file: &fs::File) {
        let source = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let meta = file.metadata().unwrap();
        symlink(source, directory.join("fd").join(descriptor.to_string())).unwrap();
        fs::write(
            directory.join("fdinfo").join(descriptor.to_string()),
            format!(
                "pos:\t0\nflags:\t0100002\nmnt_id:\t7\nino:\t{}\n",
                meta.ino()
            ),
        )
        .unwrap();
        fs::write(
            directory.join("mountinfo"),
            format!(
                "7 1 {}:{} / /fixture\\040mount rw - ext4 fixture rw\n",
                libc::major(meta.dev()),
                libc::minor(meta.dev())
            ),
        )
        .unwrap();
    }

    fn anonymous_file() -> fs::File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&[b'x'; 8192]).unwrap();
        file.sync_all().unwrap();
        assert_eq!(file.metadata().unwrap().nlink(), 0);
        file
    }

    fn scan(root: &Path) -> DeletedOpenFilesReport {
        collect(root, deadline(), DeletedOpenFilesLimits::default()).unwrap()
    }

    #[test]
    fn duplicates_across_descriptors_and_processes_count_one_allocation() {
        let root = tempfile::tempdir().unwrap();
        let mut file = anonymous_file();
        let first = process(root.path(), 41);
        let second = process(root.path(), 42);
        add_fd(&first, 17, &file);
        add_fd(&first, 3, &file);
        add_fd(&second, 9, &file);

        let report = scan(root.path());
        assert!(report.supported);
        assert!(report.complete, "{:?}", report.issues);
        assert_eq!(report.processes_scanned, 2);
        assert_eq!(report.descriptors_scanned, 3);
        assert_eq!(report.files.len(), 1);
        let observed = &report.files[0];
        assert_eq!(observed.inode, file.metadata().unwrap().ino());
        assert_eq!(
            observed.allocated_bytes,
            file.metadata().unwrap().blocks() * 512
        );
        assert_eq!(
            report.observed_allocated_bytes,
            Some(observed.allocated_bytes)
        );
        assert_eq!(observed.holders.len(), 2);
        assert_eq!(observed.holders[0].pid, 41);
        assert_eq!(observed.holders[0].fd, 3);
        assert_eq!(observed.holders[0].descriptor_count, 2);
        assert_eq!(observed.holders[1].descriptor_count, 1);
        assert_eq!(observed.holders[0].start_time_ticks, 123);
        assert_eq!(
            observed.holders[0].mount_point.as_deref(),
            Some("/fixture mount")
        );
        assert_eq!(observed.holders[0].filesystem_type.as_deref(), Some("ext4"));

        file.seek(SeekFrom::Start(0)).unwrap();
        let mut payload = Vec::new();
        file.read_to_end(&mut payload).unwrap();
        assert_eq!(
            payload,
            vec![b'x'; 8192],
            "the diagnostic never changes its subject"
        );
    }

    #[test]
    fn linked_file_with_deleted_suffix_is_not_a_retained_unlinked_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let mut file = fs::File::create(root.path().join("still here (deleted)")).unwrap();
        file.write_all(&[0; 4096]).unwrap();
        add_fd(&directory, 3, &file);
        let report = scan(root.path());
        assert!(report.complete);
        assert_eq!(report.observed_allocated_bytes, Some(0));
        assert!(report.files.is_empty());
        assert_eq!(file.metadata().unwrap().nlink(), 1);
    }

    #[test]
    fn sparse_file_uses_allocated_blocks_and_preserves_native_target_bytes() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let file = anonymous_file();
        file.set_len(1 << 30).unwrap();
        add_fd(&directory, 3, &file);
        let alias = root
            .path()
            .join(std::ffi::OsString::from_vec(b"alias-\xff".to_vec()));
        symlink(format!("/proc/self/fd/{}", file.as_raw_fd()), &alias).unwrap();
        fs::rename(directory.join("fd/3"), directory.join("old-fd")).unwrap();
        symlink(&alias, directory.join("fd/3")).unwrap();

        let report = scan(root.path());
        assert!(report.complete, "{:?}", report.issues);
        let observed = &report.files[0];
        assert_eq!(observed.logical_bytes, 1 << 30);
        assert_eq!(
            observed.allocated_bytes,
            file.metadata().unwrap().blocks() * 512
        );
        assert!(observed.allocated_bytes < observed.logical_bytes);
        assert_eq!(
            observed.holders[0].fd_target_bytes_hex,
            crate::core::hex_lower(alias.as_os_str().as_bytes())
        );
        serde_json::to_string(&report).expect("native bytes never make JSON serialization fail");
    }

    #[test]
    fn pid_reuse_discards_every_observation_from_that_process() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let file = anonymous_file();
        add_fd(&directory, 3, &file);
        let report = collect_with(
            root.path(),
            deadline(),
            DeletedOpenFilesLimits::default(),
            &mut |pid, fd| {
                if fd.is_none() {
                    stat(&directory, pid, 124);
                }
            },
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.issues["process_identity_changed"], 1);
        assert!(report.files.is_empty());
    }

    #[test]
    fn descriptor_replacement_discards_the_unverified_target() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let first = anonymous_file();
        let replacement = anonymous_file();
        add_fd(&directory, 3, &first);
        let report = collect_with(
            root.path(),
            deadline(),
            DeletedOpenFilesLimits::default(),
            &mut |_, fd| {
                if fd == Some(3) {
                    fs::rename(directory.join("fd/3"), directory.join("retired-fd")).unwrap();
                    symlink(
                        format!("/proc/self/fd/{}", replacement.as_raw_fd()),
                        directory.join("fd/3"),
                    )
                    .unwrap();
                }
            },
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.issues["descriptor_identity_changed"], 1);
        assert!(report.files.is_empty());
    }

    #[test]
    fn mismatched_fdinfo_inode_cannot_be_associated_with_the_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let file = anonymous_file();
        add_fd(&directory, 3, &file);
        fs::write(directory.join("fdinfo/3"), "mnt_id:\t7\nino:\t0\n").unwrap();
        let report = scan(root.path());
        assert!(!report.complete);
        assert!(report.files.is_empty());
        assert_eq!(report.issues["descriptor_metadata_changed"], 1);
    }

    #[test]
    fn deadlines_and_every_resource_limit_report_partial_coverage() {
        let root = tempfile::tempdir().unwrap();
        let first = anonymous_file();
        let second = anonymous_file();
        let directory = process(root.path(), 41);
        add_fd(&directory, 3, &first);
        add_fd(&directory, 4, &second);
        let expired = collect(
            root.path(),
            Instant::now(),
            DeletedOpenFilesLimits::default(),
        )
        .unwrap();
        assert!(!expired.complete);
        assert_eq!(expired.processes_scanned, 0);
        assert_eq!(expired.issues["deadline_reached"], 1);
        for (reason, limits) in [
            (
                "process_limit_reached",
                DeletedOpenFilesLimits {
                    max_processes: 0,
                    ..DeletedOpenFilesLimits::default()
                },
            ),
            (
                "descriptor_limit_reached",
                DeletedOpenFilesLimits {
                    max_descriptors: 1,
                    ..DeletedOpenFilesLimits::default()
                },
            ),
            (
                "file_limit_reached",
                DeletedOpenFilesLimits {
                    max_files: 1,
                    ..DeletedOpenFilesLimits::default()
                },
            ),
            (
                "holder_limit_reached",
                DeletedOpenFilesLimits {
                    max_holders: 1,
                    ..DeletedOpenFilesLimits::default()
                },
            ),
        ] {
            let report = collect(root.path(), deadline(), limits).unwrap();
            assert!(!report.complete, "{reason}");
            assert_eq!(report.issues[reason], 1);
            assert!(report.files.len() <= 1);
            assert!(report.descriptors_scanned <= limits.max_descriptors);
            assert!(report.processes_scanned <= limits.max_processes);
        }
    }

    #[test]
    fn missing_or_wrong_mount_evidence_retains_known_allocation_as_partial() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let file = anonymous_file();
        add_fd(&directory, 3, &file);
        fs::rename(
            directory.join("mountinfo"),
            directory.join("retired-mountinfo"),
        )
        .unwrap();
        let missing = scan(root.path());
        assert!(!missing.complete);
        assert_eq!(missing.issues["mount_table_unavailable"], 1);
        assert_eq!(missing.files.len(), 1);
        assert!(missing.files[0].holders[0].mount_point.is_none());
        fs::write(
            directory.join("mountinfo"),
            "7 1 4294967295:4294967295 / /wrong rw - ext4 fixture rw\n",
        )
        .unwrap();
        let wrong = scan(root.path());
        assert!(!wrong.complete);
        assert_eq!(wrong.issues["mount_device_mismatch"], 1);
        assert_eq!(wrong.files.len(), 1);
        assert!(wrong.files[0].holders[0].mount_point.is_none());
    }

    #[test]
    fn unavailable_processes_cannot_be_reported_as_an_empty_complete_inventory() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        fs::rename(directory.join("fd"), directory.join("retired-fds")).unwrap();
        let report = scan(root.path());
        assert!(!report.complete);
        assert_eq!(report.issues["process_disappeared"], 1);
        assert!(report.files.is_empty());
    }

    #[test]
    fn denied_descriptor_inventory_is_partial_and_preserves_the_file() {
        use std::os::unix::fs::PermissionsExt;

        if crate::platform::running_as_root() {
            eprintln!("SKIP: root bypasses descriptor-directory permission denial");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let file = anonymous_file();
        add_fd(&directory, 3, &file);
        fs::set_permissions(directory.join("fd"), fs::Permissions::from_mode(0)).unwrap();
        let report = scan(root.path());
        fs::set_permissions(directory.join("fd"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!report.complete);
        assert!(report.files.is_empty());
        assert_eq!(report.issues["process_inaccessible"], 1);
        assert_eq!(file.metadata().unwrap().len(), 8192);
        assert_eq!(scan(root.path()).files.len(), 1);
    }

    #[test]
    fn process_identity_preserves_native_ticks_despite_unusual_comm_bytes() {
        let root = tempfile::tempdir().unwrap();
        let directory = process(root.path(), 41);
        let original = fs::read(directory.join("stat")).unwrap();
        let tail = original.split(|byte| *byte == b')').next_back().unwrap();
        let mut raw = b"41 (worker (\xff)\n)".to_vec();
        raw.extend_from_slice(tail);
        fs::write(directory.join("stat"), &raw).unwrap();
        let identity = read_identity(&directory, 41, deadline()).unwrap();
        assert_eq!(identity.start_ticks, 123);
        assert!(identity.name.contains('\u{fffd}'));
        assert!(read_identity(&directory, 42, deadline()).is_err());
    }

    #[test]
    fn total_allocation_overflow_is_unknown_and_explicit() {
        let mut sweep = Sweep::new(deadline(), DeletedOpenFilesLimits::default());
        for (inode, allocated_bytes) in [(1, u64::MAX), (2, 1)] {
            sweep.files.insert(
                (1, inode),
                DeletedOpenFile {
                    device_id: 1,
                    inode,
                    allocated_bytes,
                    logical_bytes: allocated_bytes,
                    holders: Vec::new(),
                },
            );
        }
        let report = sweep.finish();
        assert_eq!(report.observed_allocated_bytes, None);
        assert!(!report.complete);
        assert_eq!(report.issues["allocated_bytes_overflow"], 1);
    }

    #[test]
    fn mount_parser_preserves_bytes_and_rejects_ambiguous_records() {
        let raw = b"7 1 8:2 / /path\\040with\\134slash-\xff rw - ext4 fixture rw\n";
        let table = parse_mountinfo(raw, deadline()).unwrap();
        assert_eq!(table[&7].point, b"/path with\\slash-\xff");
        assert_eq!(table[&7].device, libc::makedev(8, 2));
        for invalid in [
            b"7 1 8:2 / /bad\\000path rw - ext4 fixture rw\n".as_slice(),
            b"7 1 8:2 / relative rw - ext4 fixture rw\n",
            b"7 1 8:2 / /path rw ext4 fixture rw\n",
            b"7 1 8:2 / /first rw - ext4 fixture rw\n7 1 8:2 / /second rw - ext4 fixture rw\n",
        ] {
            assert!(parse_mountinfo(invalid, deadline()).is_err());
        }
        assert!(parse_fdinfo(b"mnt_id: 7\nmnt_id: 8\nino: 3\n", 3).is_err());
    }

    #[test]
    fn unsupported_inventory_has_no_zero_byte_claim() {
        let report = DeletedOpenFilesReport::unsupported();
        assert!(!report.supported);
        assert!(!report.complete);
        assert_eq!(report.observed_allocated_bytes, None);
        let json = serde_json::to_value(report).unwrap();
        assert!(json["observed_allocated_bytes"].is_null());
    }
}
