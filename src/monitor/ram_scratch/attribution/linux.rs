//! Descriptor-relative metadata traversal for report-only scratch attribution.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

use super::{AttributionLimits, MountAttribution, ScratchEntry, ScratchMount, unavailable};

const MAX_ISSUES: usize = 8;

struct Probe {
    root: File,
    device: u64,
    maximum: usize,
    examined: usize,
    deadline: Instant,
    max_depth: usize,
    seen: BTreeSet<(u64, u64)>,
    mount_boundaries: usize,
    symlinks: usize,
    issues: Vec<String>,
}

impl Probe {
    fn issue(&mut self, message: impl Into<String>) {
        let message = message.into();
        // An exhausted budget is hit by every later directory; say it once
        // so the bounded list keeps room for distinct evidence.
        if self.issues.len() < MAX_ISSUES && !self.issues.contains(&message) {
            self.issues.push(message);
        }
    }

    fn budget(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "scratch attribution deadline exhausted",
            ));
        }
        Ok(())
    }

    fn open(&self, relative: &Path, directory: bool) -> io::Result<File> {
        self.budget()?;
        let flags = if directory {
            OFlags::RDONLY | OFlags::DIRECTORY
        } else {
            OFlags::PATH
        };
        Ok(File::from(openat2(
            &self.root,
            relative,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?))
    }

    // Every name consumes the shared work budget, including later exclusions.
    // A partial enumeration is retained as partial evidence, never a complete
    // ordered prefix or authority for pagination/deletion.
    fn names(&mut self, directory: &File) -> io::Result<(Vec<OsString>, bool)> {
        let mut names = Vec::new();
        let mut complete = true;
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            if self.budget().is_err() || self.examined >= self.maximum {
                complete = false;
                self.issue("directory enumeration entry/time budget exhausted");
                break;
            }
            self.examined += 1;
            match entry {
                Ok(entry) => names.push(entry.file_name()),
                Err(error) => {
                    complete = false;
                    self.issue(format!("directory entry unavailable: {error}"));
                }
            }
        }
        names.sort();
        Ok((names, complete))
    }

    #[allow(clippy::too_many_lines)] // one budgeted metadata traversal
    fn entry(&mut self, relative: &Path, metadata: &Metadata) -> (u64, bool, Option<u64>) {
        let mut allocated = 0_u64;
        let mut complete = true;
        let mut newest = newest_time(metadata);
        let initial = (metadata.dev(), metadata.ino());
        let mut pending = vec![(relative.to_path_buf(), 0_usize)];
        while let Some((relative, depth)) = pending.pop() {
            if let Err(error) = self.budget() {
                self.issue(error.to_string());
                complete = false;
                break;
            }
            let observed = self.open(&relative, false).and_then(|file| file.metadata());
            let metadata = match observed {
                Ok(metadata) if metadata.dev() == self.device => metadata,
                Ok(_) => {
                    self.mount_boundaries += 1;
                    complete = false;
                    continue;
                }
                Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                    self.mount_boundaries += 1;
                    // Descendant mounts have their own reports. Their data is
                    // excluded from this filesystem, so age is not inferred.
                    complete = false;
                    continue;
                }
                Err(error) => {
                    complete = false;
                    self.issue(format!("{}: {error}", relative.display()));
                    continue;
                }
            };
            if depth == 0 && (metadata.dev(), metadata.ino()) != initial {
                complete = false;
                self.issue(format!(
                    "{}: entry replaced before attribution",
                    relative.display()
                ));
                break;
            }
            if metadata.file_type().is_symlink() {
                self.symlinks += 1;
                complete = false;
                continue;
            }
            newest = newest.max(newest_time(&metadata));
            if !self.seen.insert((metadata.dev(), metadata.ino())) {
                // An alias observed elsewhere is not a second allocation and
                // cannot establish this path's complete descendant history.
                complete = false;
                continue;
            }
            let Some(total) = metadata
                .blocks()
                .checked_mul(512)
                .and_then(|bytes| allocated.checked_add(bytes))
            else {
                complete = false;
                self.issue("allocated-byte accounting overflow");
                break;
            };
            allocated = total;
            if !metadata.is_dir() {
                continue;
            }
            if depth >= self.max_depth {
                complete = false;
                self.issue("directory depth budget exhausted; age remains unknown");
                continue;
            }
            let directory = match self.open(&relative, true) {
                Ok(file) => file,
                Err(error) => {
                    complete = false;
                    self.issue(format!("{}: {error}", relative.display()));
                    continue;
                }
            };
            let verified = directory.metadata();
            if !verified
                .as_ref()
                .is_ok_and(|other| same_stamp(&metadata, other))
            {
                complete = false;
                self.issue(format!(
                    "{}: directory changed before enumeration",
                    relative.display()
                ));
                continue;
            }
            match self.names(&directory) {
                Ok((names, all_names)) => {
                    complete &= all_names;
                    pending.extend(
                        names
                            .into_iter()
                            .rev()
                            .map(|name| (relative.join(name), depth + 1)),
                    );
                }
                Err(error) => {
                    complete = false;
                    self.issue(format!("{}: {error}", relative.display()));
                }
            }
            if !directory
                .metadata()
                .as_ref()
                .is_ok_and(|other| same_stamp(&metadata, other))
            {
                complete = false;
                self.issue(format!(
                    "{}: directory changed during enumeration",
                    relative.display()
                ));
            }
        }
        let idle = if complete {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|now| i128::try_from(now.as_nanos()).ok())
                .and_then(|now| now.checked_sub(newest))
                .filter(|age| *age >= 0)
                .and_then(|age| u64::try_from(age / 3_600_000_000_000).ok())
        } else {
            None
        };
        (allocated, complete, idle)
    }
}

fn newest_time(metadata: &Metadata) -> i128 {
    let mtime = i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec());
    let ctime = i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec());
    mtime.max(ctime)
}

fn same_stamp(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[allow(clippy::too_many_lines)] // ordered read-only scope and per-entry evidence
pub(super) fn inspect(
    mount: &ScratchMount,
    limits: AttributionLimits,
    maximum: usize,
    deadline: Instant,
) -> MountAttribution {
    if maximum == 0 || Instant::now() >= deadline {
        return unavailable(mount, "no attribution entry/time budget remains");
    }
    let path = Path::new(&mount.path);
    // A lossy mount spelling must never accidentally inspect a different path.
    // Native mount names which cannot be represented here are reported unknown.
    if !path.is_absolute() || mount.path.contains('\u{fffd}') {
        return unavailable(
            mount,
            "mount path is not an unambiguous absolute native spelling",
        );
    }
    let root = match openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => File::from(fd),
        Err(error) => return unavailable(mount, &format!("cannot pin mount: {error}")),
    };
    let root_stamp = match root.metadata() {
        Ok(metadata) if metadata.dev() == mount.filesystem_id => metadata,
        _ => return unavailable(mount, "mount identity changed since capacity collection"),
    };
    let mut probe = Probe {
        root,
        device: mount.filesystem_id,
        maximum,
        examined: 0,
        deadline,
        max_depth: limits.max_depth,
        seen: BTreeSet::new(),
        mount_boundaries: 0,
        symlinks: 0,
        issues: Vec::new(),
    };
    let directory = match probe.root.try_clone() {
        Ok(file) => file,
        Err(error) => return unavailable(mount, &error.to_string()),
    };
    let (names, mut complete) = match probe.names(&directory) {
        Ok(result) => result,
        Err(error) => return unavailable(mount, &format!("cannot enumerate mount: {error}")),
    };
    let mut entries = Vec::new();
    for name in names {
        if probe.budget().is_err() {
            complete = false;
            probe.issue("attribution deadline exhausted before remaining children");
            break;
        }
        let relative = PathBuf::from(name);
        let metadata = match probe
            .open(&relative, false)
            .and_then(|file| file.metadata())
        {
            Ok(metadata) => metadata,
            Err(error) => {
                complete = false;
                if error.raw_os_error() == Some(libc::EXDEV) {
                    probe.mount_boundaries += 1;
                } else {
                    probe.issue(format!("{}: {error}", relative.display()));
                }
                continue;
            }
        };
        let owner_uid = metadata.uid();
        let (bytes, entry_complete, idle_hours) = probe.entry(&relative, &metadata);
        complete &= entry_complete;
        let full = path.join(&relative);
        entries.push(ScratchEntry {
            path: full.to_string_lossy().into_owned(),
            native_path_hex: crate::core::hex_lower(full.as_os_str().as_encoded_bytes()),
            owner_uid,
            observed_allocated_bytes: bytes,
            complete: entry_complete,
            idle_hours,
        });
        // Output stays bounded even if a mount has many immediate children.
        entries.sort_by(|a, b| {
            b.observed_allocated_bytes
                .cmp(&a.observed_allocated_bytes)
                .then_with(|| a.native_path_hex.cmp(&b.native_path_hex))
        });
        entries.truncate(limits.top);
    }
    if !probe
        .root
        .metadata()
        .as_ref()
        .is_ok_and(|other| same_stamp(&root_stamp, other))
    {
        complete = false;
        probe.issue("mount root changed during attribution");
    }
    MountAttribution {
        mount_path: mount.path.clone(),
        complete,
        entries_examined: probe.examined,
        mount_boundaries_skipped: probe.mount_boundaries,
        symlinks_skipped: probe.symlinks,
        entries,
        issues: probe.issues,
    }
}

#[cfg(test)]
mod tests;
