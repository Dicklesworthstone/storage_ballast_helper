//! Move a dormant unit to the target, and bring one back.
//!
//! Order of operations, each step a precondition of the next:
//! 1. rsync the unit to `<target>[/<host>]/<run stamp>/<original path>/`.
//! 2. Verify with a checksum dry run: any itemized difference aborts.
//! 3. Upload the relocation record next to the copy.
//! 4. Rename the unit aside (`.<name>.sbh-relocating`), so a writer that
//!    opens by path fails loudly instead of writing into a doomed tree.
//! 5. Re-survey the renamed tree and re-sweep processes: nothing below it
//!    may have changed since step 1, and nothing may hold it. Otherwise the
//!    rename is undone and the unit stays.
//! 6. Put a stub at the original path (RELOCATED.md, the record, and the
//!    marker when the unit was the marked tree itself).
//! 7. Durably save the completed relocation in the ledger.
//! 8. Remove the renamed tree.
//!
//! Relocation permission is renewed before copying, after renaming, and
//! immediately before removing the original. A new ancestor or descendant
//! opt-out, excluded component, or uncertain policy observation stops the move.
//!
//! Every remote operation is an rsync, so a key restricted with `rrsync` to
//! one directory on the target is enough.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, Stat};
use serde::{Deserialize, Serialize};

use super::config::RelocationConfig;
use super::ledger::{Ledger, RelocationEntry};
use super::plan::{self, Candidate};
use super::survey;
use super::{README_FILENAME, RECORD_FILENAME, SCHEMA};
use crate::platform::pal::Platform;
use crate::scanner::protection::MARKER_FILENAME;

/// The record kept in the stub and next to the copy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelocationRecord {
    /// Always [`SCHEMA`].
    pub schema: String,
    /// Where the tree lived.
    pub path: PathBuf,
    /// rsync destination holding it (ends with `/`).
    pub destination: String,
    /// Host it moved from.
    pub host: String,
    /// When it moved (RFC 3339).
    pub relocated_at: String,
    /// Allocated bytes.
    pub bytes: u64,
    /// Regular files.
    pub files: u64,
    /// Newest change at relocation (RFC 3339).
    pub newest_change: String,
    /// Newest regular-file read at relocation, when the mount records it.
    pub newest_access: Option<String>,
    /// Days of observed quiet, on a mount without atime.
    pub observed_days: Option<f64>,
    /// Owner, group and mode of the original directory.
    pub uid: u32,
    /// Group of the original directory.
    pub gid: u32,
    /// Mode of the original directory.
    pub mode: u32,
    /// SSH identity used, so a restore can use the same one.
    pub ssh_identity: Option<PathBuf>,
    /// SSH port used.
    pub ssh_port: Option<u16>,
    /// Extra `ssh -o` options used.
    #[serde(default)]
    pub ssh_options: Vec<String>,
    /// Whether ownership was stored with `--fake-super`.
    pub fake_super: bool,
    /// Where the target is, in words, when its rsync spelling hides it.
    #[serde(default)]
    pub target_note: Option<String>,
}

/// What happened to one unit.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// Moved; the original path is now a stub.
    Relocated {
        /// The original path.
        path: PathBuf,
        /// The rsync destination holding the copy.
        destination: String,
        /// Allocated bytes moved.
        bytes: u64,
    },
    /// Left in place.
    Failed {
        /// The original path.
        path: PathBuf,
        /// The step that refused: precheck, copy, verify, record, rename,
        /// postcheck, stub, remove or ledger.
        stage: String,
        /// Why.
        error: String,
    },
}

fn rfc3339(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map_or_else(|| seconds.to_string(), |time| time.to_rfc3339())
}

/// This host's name, as used in destinations.
#[must_use]
pub fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_string())
        .ok()
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn is_remote(target: &str) -> bool {
    // rsync's rule: a colon before any slash names a host.
    target
        .find(':')
        .is_some_and(|colon| target.find('/').is_none_or(|slash| colon < slash))
}

/// `<target>[/<host>]/<stamp>/<path without leading slash>/`.
#[must_use]
pub fn destination_for(
    config: &RelocationConfig,
    target: &str,
    host: &str,
    stamp: &str,
    path: &Path,
) -> String {
    let mut destination = target.trim_end_matches('/').to_string();
    let mut push = |part: &str| {
        if !(destination.is_empty() || destination.ends_with(':')) {
            destination.push('/');
        }
        destination.push_str(part);
    };
    if config.include_hostname {
        push(host);
    }
    push(stamp);
    push(path.to_string_lossy().trim_start_matches('/'));
    destination.push('/');
    destination
}

fn rsync_command(config: &RelocationConfig, remote: bool) -> Command {
    let mut command = Command::new("rsync");
    command.args([
        "-aHAX",
        "--numeric-ids",
        "--sparse",
        "--one-file-system",
        "--mkpath",
    ]);
    if remote {
        let mut ssh = vec![
            "ssh -o BatchMode=yes -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new"
                .to_string(),
        ];
        if let Some(identity) = &config.ssh_identity {
            ssh.push(format!("-i {}", identity.display()));
        }
        if let Some(port) = config.ssh_port {
            ssh.push(format!("-p {port}"));
        }
        // rsync splits -e on whitespace but honours single quotes.
        ssh.extend(
            config
                .ssh_options
                .iter()
                .map(|option| format!("-o '{option}'")),
        );
        command.arg("-e").arg(ssh.join(" "));
        if config.fake_super {
            command.arg("-M--fake-super");
        }
    }
    if let Some(limit) = config.bwlimit_kib {
        command.arg(format!("--bwlimit={limit}"));
    }
    command
}

fn run(mut command: Command, stage: &str) -> Result<String, (String, String)> {
    let output = command
        .output()
        .map_err(|error| (stage.to_string(), format!("could not run rsync: {error}")))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: String = stderr
            .lines()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ");
        Err((
            stage.to_string(),
            format!("rsync exited {}: {tail}", output.status),
        ))
    }
}

/// Copy `source/` to `destination` and prove the copy identical.
fn copy_and_verify(
    config: &RelocationConfig,
    remote: bool,
    source: &str,
    destination: &str,
) -> Result<(), (String, String)> {
    let mut copy = rsync_command(config, remote);
    copy.arg("--").arg(source).arg(destination);
    run(copy, "copy")?;
    let mut verify = rsync_command(config, remote);
    verify
        .args(["--checksum", "--dry-run", "--itemize-changes", "--delete"])
        .arg("--")
        .arg(source)
        .arg(destination);
    let differences = run(verify, "verify")?;
    let differences: Vec<&str> = differences
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if differences.is_empty() {
        Ok(())
    } else {
        Err((
            "verify".to_string(),
            format!(
                "{} differences after copy, first: {}",
                differences.len(),
                differences[0]
            ),
        ))
    }
}

fn sibling(path: &Path, suffix: &str) -> io::Result<PathBuf> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path has no parent",
        ));
    };
    Ok(parent.join(format!(".{}.{suffix}", name.to_string_lossy())))
}

/// `12.3 GiB` or `41.0 MiB`, for people.
fn human(bytes: u64) -> String {
    // Display only.
    #[allow(clippy::cast_precision_loss)]
    let mib = bytes as f64 / f64::from(1u32 << 20);
    if mib >= 1024.0 {
        format!("{:.1} GiB", mib / 1024.0)
    } else {
        format!("{mib:.1} MiB")
    }
}

fn readme(record: &RelocationRecord) -> String {
    format!(
        "# Relocated by sbh\n\n\
This directory held {bytes} in {files} files. Nothing in it had changed \
since {changed}{read}, and no process was using it, so sbh moved it to backup \
storage on {when} and left this stub in its place. Nothing was deleted.\n\n\
Copy: `{destination}`{note}\n\n\
## Restore\n\n\
```\nsudo sbh relocate --restore {path}\n```\n\n\
That copies the tree back, verifies it, and swaps it in for this stub. The \
backup copy and previous stub are kept for recovery.\n\n\
Without sbh: `rsync -aHAX --numeric-ids {fake}{destination} <somewhere>/`\n\n\
To keep a tree from ever being relocated, write `relocatable = false` into its \
`.sbh-protect` marker.\n",
        bytes = human(record.bytes),
        note = record
            .target_note
            .as_deref()
            .map_or_else(String::new, |note| format!(" ({note})")),
        files = record.files,
        changed = record.newest_change,
        read = record
            .newest_access
            .as_deref()
            .map_or_else(String::new, |access| format!(
                " and nothing had been read since {access}"
            )),
        when = record.relocated_at,
        destination = record.destination,
        path = record.path.display(),
        fake = if record.fake_super {
            "-M--fake-super "
        } else {
            ""
        },
    )
}

fn write_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn holder(platform: &dyn Platform, path: &Path) -> Option<String> {
    plan::Holders::of(&plan::sweep(platform, &[path.to_path_buf()]), path).veto()
}

/// Relocate one selected candidate. `stamp` names this run.
///
/// The caller must hold the ledger's [`super::ledger::WriterLock`] from
/// before loading it until this operation and its completion save finish.
pub fn relocate(
    config: &RelocationConfig,
    platform: &dyn Platform,
    ledger: &mut Ledger,
    candidate: &Candidate,
    stamp: &str,
    now: i64,
) -> Outcome {
    relocate_with_hooks(
        config,
        platform,
        ledger,
        candidate,
        stamp,
        now,
        &Hooks::default(),
    )
}

/// The postcheck: the renamed tree must be exactly what was copied. A mount
/// that appeared inside it was skipped by the copy (`--one-file-system`) and
/// must not reach the removal either.
fn postcheck_matches(snapshot: &survey::UnitStats, after: &survey::TreeSurvey) -> bool {
    let unit = &after.units[0];
    !after.truncated
        && !unit.crosses_mount
        && !unit.unreadable
        && unit.newest_change_below <= snapshot.newest_change_below
        && unit.files == snapshot.files
        && unit.entries == snapshot.entries
}

/// Remove the stub this run created, file by file. Anything else found in it
/// (a job that wrote there meanwhile) keeps the directory.
fn remove_own_stub(path: &Path) {
    for name in [README_FILENAME, RECORD_FILENAME, MARKER_FILENAME] {
        let _ = fs::remove_file(path.join(name));
    }
    let _ = fs::remove_dir(path);
}

/// Fault-injection points for tests: what another process might do between
/// two steps. `after_rename` gets the original path, `before_remove` the
/// renamed tree.
#[derive(Default)]
struct Hooks<'a> {
    after_rename: Option<&'a dyn Fn(&Path)>,
    before_remove: Option<&'a dyn Fn(&Path)>,
}

/// [`relocate`] with fault-injection hooks.
#[allow(clippy::too_many_lines)]
fn relocate_with_hooks(
    config: &RelocationConfig,
    platform: &dyn Platform,
    ledger: &mut Ledger,
    candidate: &Candidate,
    stamp: &str,
    now: i64,
    hooks: &Hooks<'_>,
) -> Outcome {
    let path = candidate.stats.path.clone();
    let fail = |stage: &str, error: String| Outcome::Failed {
        path: path.clone(),
        stage: stage.to_string(),
        error,
    };
    let Some(target) = config.target.as_deref() else {
        return fail("config", "no target configured".into());
    };
    let remote = is_remote(target);
    let host = hostname();

    // Re-check right before acting: the plan may be minutes old.
    let before = match plan::check_relocation_policy(config, &path, &path) {
        Ok(survey) => survey,
        Err(error) => {
            return fail(
                "precheck",
                format!("relocation policy refuses the move: {error}"),
            );
        }
    };
    if let Some(reason) = holder(platform, &path) {
        return fail("precheck", format!("in use: {reason}"));
    }
    let snapshot = before.units[0].clone();
    if snapshot.newest_change != candidate.stats.newest_change {
        return fail("precheck", "tree changed since it was planned".into());
    }

    let destination = ledger
        .in_progress
        .get(&path)
        .cloned()
        .unwrap_or_else(|| destination_for(config, target, &host, stamp, &path));
    ledger.in_progress.insert(path.clone(), destination.clone());
    if let Err(error) = ledger.save(&config.state_dir) {
        return fail("ledger", error.to_string());
    }
    let source = format!("{}/", path.display());
    if let Err((stage, error)) = copy_and_verify(config, remote, &source, &destination) {
        return fail(&stage, error);
    }

    let record = RelocationRecord {
        schema: SCHEMA.to_string(),
        path: path.clone(),
        destination: destination.clone(),
        host,
        relocated_at: rfc3339(now),
        bytes: snapshot.bytes,
        files: snapshot.files,
        newest_change: rfc3339(snapshot.newest_change),
        newest_access: candidate
            .atime_evidence
            .then_some(snapshot.newest_access)
            .flatten()
            .map(rfc3339),
        observed_days: (!candidate.atime_evidence)
            .then_some(candidate.observed_days)
            .flatten(),
        uid: snapshot.uid,
        gid: snapshot.gid,
        mode: snapshot.mode,
        ssh_identity: config.ssh_identity.clone(),
        ssh_port: config.ssh_port,
        ssh_options: config.ssh_options.clone(),
        fake_super: config.fake_super && remote,
        target_note: config.target_note.clone(),
    };
    let record_json = match serde_json::to_vec_pretty(&record) {
        Ok(json) => json,
        Err(error) => return fail("record", error.to_string()),
    };
    // The record goes next to the copy, never inside it, so the copy stays
    // byte-identical to the source and a later verify stays clean.
    let staging = config.state_dir.join(format!(".record-{stamp}.json"));
    if let Err(error) = write_file(&staging, &record_json) {
        return fail("record", error.to_string());
    }
    let mut upload = rsync_command(config, remote);
    upload.arg(&staging).arg(format!(
        "{}{}",
        destination.trim_end_matches('/'),
        RECORD_FILENAME
    ));
    let uploaded = run(upload, "record");
    let _ = fs::remove_file(&staging);
    if let Err((stage, error)) = uploaded {
        return fail(&stage, error);
    }

    let aside = match sibling(&path, "sbh-relocating") {
        Ok(aside) if !aside.exists() => aside,
        Ok(aside) => return fail("rename", format!("{} already exists", aside.display())),
        Err(error) => return fail("rename", error.to_string()),
    };
    if let Err(error) = fs::rename(&path, &aside) {
        return fail("rename", error.to_string());
    }
    let undo = |stage: &str, error: String| {
        let restored = if path.exists() {
            format!(
                "; {} was recreated meanwhile, so the tree stays at {}",
                path.display(),
                aside.display()
            )
        } else {
            match fs::rename(&aside, &path) {
                Ok(()) => String::new(),
                Err(undo_error) => format!(
                    "; rename back failed: {undo_error}; tree is at {}",
                    aside.display()
                ),
            }
        };
        fail(stage, format!("{error}{restored}"))
    };
    if let Some(hook) = hooks.after_rename {
        hook(&path);
    }
    match plan::check_relocation_policy(config, &path, &aside) {
        Ok(after) if postcheck_matches(&snapshot, &after) => {}
        Ok(_) => return undo("postcheck", "tree changed during the copy".into()),
        Err(error) => return undo("postcheck", format!("relocation policy changed: {error}")),
    }
    let aside_identity = match fs::symlink_metadata(&aside) {
        Ok(metadata) => metadata,
        Err(error) => return undo("postcheck", error.to_string()),
    };
    if let Some(reason) = holder(platform, &aside) {
        return undo("postcheck", format!("in use: {reason}"));
    }

    // The stub: same owner and mode as the original directory. A path that
    // reappeared meanwhile belongs to whoever made it: create_dir fails and
    // nothing of theirs is touched.
    let mut created = false;
    let stub = (|| -> io::Result<()> {
        fs::create_dir(&path)?;
        created = true;
        write_file(&path.join(README_FILENAME), readme(&record).as_bytes())?;
        write_file(&path.join(RECORD_FILENAME), &record_json)?;
        if candidate.stats.depth == 0 {
            fs::copy(aside.join(MARKER_FILENAME), path.join(MARKER_FILENAME))?;
        }
        for entry in fs::read_dir(&path)? {
            std::os::unix::fs::lchown(entry?.path(), Some(record.uid), Some(record.gid))?;
        }
        std::os::unix::fs::chown(&path, Some(record.uid), Some(record.gid))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(record.mode))
    })();
    if let Err(error) = stub {
        if created {
            remove_own_stub(&path);
        }
        return undo("stub", error.to_string());
    }

    // Keep resumable state in memory until the completion is durable. If
    // saving fails, a later candidate must not persist this as completed.
    let mut completed = ledger.clone();
    completed.in_progress.remove(&path);
    completed.observations.remove(&path);
    completed.relocations.push(RelocationEntry {
        path: path.clone(),
        destination: destination.clone(),
        bytes: snapshot.bytes,
        files: snapshot.files,
        relocated_at: now,
    });
    if let Err(error) = completed.save(&config.state_dir) {
        return fail(
            "ledger",
            format!(
                "completion could not be durably saved: {error}; original tree preserved at {}; verified copy at {destination}; restore stub at {}. Repair the ledger before continuing; no original bytes were removed",
                aside.display(),
                path.display()
            ),
        );
    }
    *ledger = completed;
    // The copy is verified, the stub is in place and the completion is
    // durable; only now may the original bytes go.
    if let Some(hook) = hooks.before_remove {
        hook(&aside);
    }
    let refuse_removal = |reason: String| {
        fail(
            "remove",
            format!(
                "{reason}; original tree preserved at {}; earlier verified copy at {destination}; restore stub at {}; no original bytes were removed",
                aside.display(),
                path.display()
            ),
        )
    };
    match plan::check_relocation_policy(config, &path, &aside) {
        Ok(current) if postcheck_matches(&snapshot, &current) => {}
        Ok(_) => {
            return refuse_removal(
                "tree changed after verification; preserved source may contain newer data than the backup".into(),
            );
        }
        Err(error) => {
            return refuse_removal(format!(
                "relocation policy no longer permits removal: {error}"
            ));
        }
    }
    // A policy walk may be large. Its current content evidence and a holder
    // sweep after that walk must both pass at the final removal boundary.
    if let Some(reason) = holder(platform, &aside) {
        return refuse_removal(format!("in use before removal: {reason}"));
    }
    // Descriptor-relative, no symlinks followed, and refusing any other
    // mount (openat2 NO_XDEV): the deletion executor's own removal.
    if let Err(error) = crate::scanner::quarantine::remove_direct(&aside, &aside_identity, false) {
        return fail(
            "remove",
            format!(
                "relocated, but {} could not be removed: {error}",
                aside.display()
            ),
        );
    }
    Outcome::Relocated {
        path,
        destination,
        bytes: snapshot.bytes,
    }
}

const MAX_RESTORE_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_RESTORE_STUB_ENTRIES: usize = 4096;

fn restore_invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn same_restore_identity(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && FileType::from_raw_mode(left.st_mode) == FileType::from_raw_mode(right.st_mode)
}

fn same_restore_stamp(left: &Stat, right: &Stat) -> bool {
    same_restore_identity(left, right)
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

struct RestoreSnapshot {
    directory: Stat,
    entries: BTreeMap<OsString, Stat>,
    record: Vec<u8>,
}

impl RestoreSnapshot {
    fn same_contents(&self, other: &Self) -> bool {
        same_restore_identity(&self.directory, &other.directory)
            && self.directory.st_mode == other.directory.st_mode
            && self.directory.st_uid == other.directory.st_uid
            && self.directory.st_gid == other.directory.st_gid
            && self.record == other.record
            && self.entries.len() == other.entries.len()
            && self.entries.iter().zip(&other.entries).all(
                |((name, stamp), (other_name, other_stamp))| {
                    name == other_name && same_restore_stamp(stamp, other_stamp)
                },
            )
    }
}

/// The stub is small metadata, but may also contain newer user files. Pin
/// their top-level identities without following links or reading payloads.
fn restore_snapshot(directory: &fs::File) -> io::Result<RestoreSnapshot> {
    let before = rustix::fs::fstat(directory)?;
    let mut entries = BTreeMap::new();
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == OsStr::new(".") || name == OsStr::new("..") {
            continue;
        }
        if entries.len() >= MAX_RESTORE_STUB_ENTRIES {
            return Err(restore_invalid("restore stub entry budget exhausted"));
        }
        entries.insert(
            name.to_os_string(),
            rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?,
        );
    }
    let expected = entries
        .get(OsStr::new(RECORD_FILENAME))
        .ok_or_else(|| restore_invalid("restore stub has no relocation record"))?;
    if FileType::from_raw_mode(expected.st_mode) != FileType::RegularFile
        || !u64::try_from(expected.st_size).is_ok_and(|size| size <= MAX_RESTORE_RECORD_BYTES)
    {
        return Err(restore_invalid(
            "relocation record is not a bounded regular file",
        ));
    }
    let file = fs::File::from(crate::scanner::quarantine::open_beneath(
        directory,
        OsStr::new(RECORD_FILENAME),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOATIME | OFlags::CLOEXEC,
    )?);
    if !same_restore_stamp(expected, &rustix::fs::fstat(&file)?) {
        return Err(restore_invalid("relocation record changed while opening"));
    }
    let mut record = Vec::new();
    (&file)
        .take(MAX_RESTORE_RECORD_BYTES + 1)
        .read_to_end(&mut record)?;
    if record.len() as u64 > MAX_RESTORE_RECORD_BYTES
        || !same_restore_stamp(expected, &rustix::fs::fstat(&file)?)
        || !same_restore_stamp(
            expected,
            &rustix::fs::statat(directory, RECORD_FILENAME, AtFlags::SYMLINK_NOFOLLOW)?,
        )
        || !same_restore_stamp(&before, &rustix::fs::fstat(directory)?)
    {
        return Err(restore_invalid("restore stub changed while reading"));
    }
    Ok(RestoreSnapshot {
        directory: before,
        entries,
        record,
    })
}

fn restore_parent_current(parent: &fs::File, path: &Path) -> io::Result<()> {
    let current = rustix::fs::statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)?;
    if !same_restore_identity(&rustix::fs::fstat(parent)?, &current) {
        return Err(restore_invalid("restore parent path was replaced or moved"));
    }
    Ok(())
}

struct RestoreWorkspace {
    directory: fs::File,
    name: String,
    path: PathBuf,
}

impl RestoreWorkspace {
    fn create(parent: &fs::File, parent_path: &Path) -> io::Result<Self> {
        for _ in 0..8 {
            let name = format!(".sbh-restore-{:032x}", rand::random::<u128>());
            match rustix::fs::mkdirat(parent, &name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error.into()),
            }
            let directory = fs::File::from(crate::scanner::quarantine::open_beneath(
                parent,
                OsStr::new(&name),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            )?);
            let metadata = rustix::fs::fstat(&directory)?;
            if metadata.st_uid != nix::unistd::geteuid().as_raw()
                || metadata.st_mode & 0o777 != 0o700
            {
                return Err(restore_invalid("restore workspace is not private"));
            }
            rustix::fs::mkdirat(&directory, "payload", Mode::from_raw_mode(0o700))?;
            parent.sync_all()?;
            return Ok(Self {
                directory,
                path: parent_path.join(&name),
                name,
            });
        }
        Err(restore_invalid(
            "cannot exclusively create a restore workspace",
        ))
    }

    fn location(&self) -> PathBuf {
        fs::read_link(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
            .unwrap_or_else(|_| self.path.clone())
    }

    fn check_identity(&self, parent: &fs::File) -> io::Result<()> {
        let current = rustix::fs::statat(parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !same_restore_identity(&rustix::fs::fstat(&self.directory)?, &current) {
            return Err(restore_invalid("restore workspace was replaced or moved"));
        }
        Ok(())
    }
}

type RestoreHook<'a> = &'a dyn Fn(&Path, &Path);

#[derive(Default)]
struct RestoreHooks<'a> {
    before_copy: Option<RestoreHook<'a>>,
    before_swap: Option<RestoreHook<'a>>,
    after_stub_move: Option<RestoreHook<'a>>,
}

/// Bring a relocated tree back from its copy and replace the stub. Every
/// attempt has private staging; the previous stub is retained for recovery.
pub fn restore(stub: &Path) -> Result<Restored, String> {
    restore_with_hooks(stub, &RestoreHooks::default())
}

#[allow(clippy::too_many_lines)]
fn restore_with_hooks(stub: &Path, hooks: &RestoreHooks<'_>) -> Result<Restored, String> {
    if !stub.is_absolute()
        || stub
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return Err("restore needs an absolute path without parent components".into());
    }
    let (Some(parent_path), Some(name)) = (stub.parent(), stub.file_name()) else {
        return Err("restore path has no parent or name".into());
    };
    let parent = survey::open_directory(parent_path).map_err(|error| error.to_string())?;
    let directory = fs::File::from(
        crate::scanner::quarantine::open_beneath(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        )
        .map_err(|error| format!("opening restore stub: {error}"))?,
    );
    // A directory lock cannot be redirected by a replaced lock file and
    // needs no allocation. Different opens of this inode serialize restores.
    let locked = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| {
            format!("cannot lock restore stub (another restore may be running): {error}")
        })?;
    let initial = restore_snapshot(&locked).map_err(|error| error.to_string())?;
    let record: RelocationRecord = serde_json::from_slice(&initial.record)
        .map_err(|error| format!("bad relocation record: {error}"))?;
    if record.schema != SCHEMA || record.path != stub {
        return Err(format!(
            "relocation record does not identify this stub: {}",
            stub.display()
        ));
    }
    if record.destination.is_empty() || !record.destination.ends_with('/') {
        return Err("relocation record has no directory destination".into());
    }
    let config = RelocationConfig {
        target: Some(record.destination.clone()),
        ssh_identity: record.ssh_identity.clone(),
        ssh_port: record.ssh_port,
        ssh_options: record.ssh_options.clone(),
        fake_super: record.fake_super,
        ..RelocationConfig::default()
    };
    config
        .validate()
        .map_err(|error| format!("bad relocation settings: {error}"))?;
    restore_parent_current(&parent, parent_path).map_err(|error| error.to_string())?;
    let workspace = RestoreWorkspace::create(&parent, parent_path)
        .map_err(|error| format!("creating private restore staging: {error}"))?;
    let retained = |reason: String| {
        format!(
            "{reason}; restore data retained at {}; backup remains at {}",
            workspace.location().display(),
            record.destination
        )
    };
    let payload = fs::File::from(
        crate::scanner::quarantine::open_beneath(
            &workspace.directory,
            OsStr::new("payload"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        )
        .map_err(|error| retained(error.to_string()))?,
    );
    let payload_identity =
        rustix::fs::fstat(&payload).map_err(|error| retained(error.to_string()))?;
    if let Some(hook) = hooks.before_copy {
        hook(stub, &workspace.location());
    }
    // Pin the payload itself, not just its parent: replacing the payload
    // entry with a symlink must never redirect even the initial rsync writes.
    let destination = format!("/proc/{}/fd/{}/", std::process::id(), payload.as_raw_fd());
    copy_and_verify(
        &config,
        is_remote(&record.destination),
        &record.destination,
        &destination,
    )
    .map_err(|(stage, error)| retained(format!("{stage}: {error}")))?;
    if let Some(hook) = hooks.before_swap {
        hook(stub, &workspace.location());
    }
    let current = restore_snapshot(&locked).map_err(|error| retained(error.to_string()))?;
    if !same_restore_stamp(&initial.directory, &current.directory)
        || !initial.same_contents(&current)
    {
        return Err(retained("restore stub changed during the copy".into()));
    }
    restore_parent_current(&parent, parent_path).map_err(|error| retained(error.to_string()))?;
    workspace
        .check_identity(&parent)
        .map_err(|error| retained(error.to_string()))?;
    let current_stub = rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| retained(error.to_string()))?;
    let current_payload =
        rustix::fs::statat(&workspace.directory, "payload", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| retained(error.to_string()))?;
    if !same_restore_identity(&initial.directory, &current_stub)
        || !same_restore_identity(&payload_identity, &current_payload)
    {
        return Err(retained("restore stub or copied tree was replaced".into()));
    }
    rustix::fs::renameat_with(
        &parent,
        name,
        &workspace.directory,
        "stub",
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| retained(format!("moving the stub aside: {error}")))?;
    let undo = |reason: String| {
        let rollback = rustix::fs::renameat_with(
            &workspace.directory,
            "stub",
            &parent,
            name,
            RenameFlags::NOREPLACE,
        );
        retained(match rollback {
            Ok(()) => format!("{reason}; original stub put back"),
            Err(error) => format!(
                "{reason}; original path was not overwritten and rollback could not finish ({error}); previous stub is at {}",
                workspace.location().join("stub").display()
            ),
        })
    };
    if let Some(hook) = hooks.after_stub_move {
        hook(stub, &workspace.location());
    }
    // Rename changes the directory ctime. Its identity and entries must
    // still match, including the record read before the transfer started.
    let moved = fs::File::from(
        crate::scanner::quarantine::open_beneath(
            &workspace.directory,
            OsStr::new("stub"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        )
        .map_err(|error| undo(error.to_string()))?,
    );
    let moved_snapshot = restore_snapshot(&moved).map_err(|error| undo(error.to_string()))?;
    if !initial.same_contents(&moved_snapshot) {
        return Err(undo("stub identity or contents changed during swap".into()));
    }
    restore_parent_current(&parent, parent_path).map_err(|error| undo(error.to_string()))?;
    workspace
        .check_identity(&parent)
        .map_err(|error| undo(error.to_string()))?;
    let current_payload =
        rustix::fs::statat(&workspace.directory, "payload", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| undo(error.to_string()))?;
    if !same_restore_identity(&payload_identity, &current_payload) {
        return Err(undo("copied tree was replaced during swap".into()));
    }
    rustix::fs::renameat_with(
        &workspace.directory,
        "payload",
        &parent,
        name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| undo(format!("publishing restored tree: {error}")))?;
    let published_error = |reason: String| {
        let actual_parent = fs::read_link(format!("/proc/self/fd/{}", parent.as_raw_fd()))
            .unwrap_or_else(|_| parent_path.to_path_buf());
        format!(
            "restored tree was installed at {}, but completion could not be confirmed: {reason}; previous stub retained at {}; backup remains at {}",
            actual_parent.join(name).display(),
            workspace.location().join("stub").display(),
            record.destination,
        )
    };
    let published = rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| published_error(error.to_string()))?;
    if !same_restore_identity(&payload_identity, &published) {
        return Err(published_error("installed tree identity changed".into()));
    }
    parent
        .sync_all()
        .map_err(|error| published_error(format!("restored tree directory sync: {error}")))?;
    workspace
        .directory
        .sync_all()
        .map_err(|error| published_error(format!("saved stub directory sync: {error}")))?;
    restore_parent_current(&parent, parent_path)
        .map_err(|error| published_error(error.to_string()))?;
    // Retain even a pristine stub. A writer holding a directory/file handle
    // can still add work after the swap; cleanup by known filename would lose it.
    let foreign = initial
        .entries
        .keys()
        .filter(|name| {
            ![README_FILENAME, RECORD_FILENAME, MARKER_FILENAME]
                .iter()
                .any(|known| name.as_os_str() == OsStr::new(known))
        })
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    Ok(Restored {
        path: record.path,
        kept_stub: Some((workspace.location().join("stub"), foreign)),
    })
}

/// A completed restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The restored path.
    pub path: PathBuf,
    /// The previous stub retained in private recovery staging, with any
    /// additional names it held before restoration.
    pub kept_stub: Option<(PathBuf, Vec<String>)>,
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use crate::relocate::plan::Verdict;

    /// The precheck refuses while it cannot see every process, as it must. A
    /// user who cannot read other users' processes has nothing to prove here.
    fn sees_every_process(path: &Path) -> bool {
        let platform = crate::platform::current();
        let visible = crate::relocate::plan::sweep(&platform, &[path.to_path_buf()]).is_complete();
        if !visible {
            eprintln!("skipped: this user cannot see every process");
        }
        visible
    }

    fn rsync_available() -> bool {
        Command::new("rsync")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// A marked tree with nested files, a symlink and a hard link.
    fn marked_tree(root: &Path) -> PathBuf {
        let unit = root.join("scratch/unit");
        fs::create_dir_all(unit.join("a/b")).unwrap();
        fs::write(unit.join(MARKER_FILENAME), "added_by = \"test\"\n").unwrap();
        fs::write(unit.join("a/b/data"), vec![7u8; 300_000]).unwrap();
        fs::write(unit.join("top"), b"top").unwrap();
        fs::hard_link(unit.join("top"), unit.join("a/top-link")).unwrap();
        std::os::unix::fs::symlink("a/b/data", unit.join("link")).unwrap();
        unit
    }

    fn candidate_for(unit: &Path) -> Candidate {
        let survey = survey::survey_tree(unit, 0, 10_000).unwrap();
        Candidate {
            marked_tree: unit.to_path_buf(),
            stats: survey.units[0].clone(),
            atime_evidence: true,
            observed_days: None,
            verdict: Verdict::Eligible,
            selected: true,
        }
    }

    fn local_config(root: &Path) -> RelocationConfig {
        RelocationConfig {
            enabled: true,
            target: Some(root.join("bulk").display().to_string()),
            state_dir: root.join("state"),
            roots: vec![root.join("scratch")],
            ..RelocationConfig::default()
        }
    }

    #[test]
    fn relocates_to_a_local_target_and_restores() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        if !sees_every_process(&unit) {
            return;
        }
        let config = local_config(tmp.path());
        let mut ledger = Ledger::default();
        let platform = crate::platform::current();
        let outcome = relocate(
            &config,
            &platform,
            &mut ledger,
            &candidate_for(&unit),
            "S",
            1_000,
        );
        let Outcome::Relocated { destination, .. } = outcome else {
            panic!("not relocated: {outcome:?}");
        };
        let copy = PathBuf::from(destination.trim_end_matches('/'));
        assert_eq!(fs::read(copy.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert_eq!(
            fs::read_link(copy.join("link")).unwrap(),
            Path::new("a/b/data")
        );
        assert!(
            copy.with_file_name(format!("unit{RECORD_FILENAME}"))
                .is_file()
        );
        // The stub: readme, record and marker, and nothing else.
        let mut names: Vec<_> = fs::read_dir(&unit)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![MARKER_FILENAME, RECORD_FILENAME, README_FILENAME]
        );
        assert!(!sibling(&unit, "sbh-relocating").unwrap().exists());
        assert_eq!(ledger.relocations.len(), 1);
        assert!(ledger.in_progress.is_empty());

        let restored = restore(&unit).unwrap();
        assert_eq!(restored.path, unit);
        let (kept, foreign) = restored.kept_stub.expect("previous stub retained");
        assert!(foreign.is_empty());
        assert!(kept.join(RECORD_FILENAME).is_file());
        assert!(kept.join(README_FILENAME).is_file());
        assert_eq!(fs::read(unit.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert!(!unit.join(README_FILENAME).exists());
        assert!(!sibling(&unit, "sbh-stub").unwrap().exists());
        assert!(!sibling(&unit, "sbh-restoring").unwrap().exists());
        // The hard link survived both trips.
        assert_eq!(
            fs::metadata(unit.join("top")).unwrap().ino(),
            fs::metadata(unit.join("a/top-link")).unwrap().ino()
        );
    }

    fn restore_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let stub = root.join("scratch/unit");
        let backup = root.join("backup");
        fs::create_dir_all(&stub).unwrap();
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("data"), b"verified backup payload").unwrap();
        let record = RelocationRecord {
            schema: SCHEMA.into(),
            path: stub.clone(),
            destination: format!("{}/", backup.display()),
            host: "fixture".into(),
            relocated_at: rfc3339(1_000),
            bytes: 4096,
            files: 1,
            newest_change: rfc3339(1),
            newest_access: None,
            observed_days: Some(14.0),
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
            mode: 0o700,
            ssh_identity: None,
            ssh_port: None,
            ssh_options: Vec::new(),
            fake_super: false,
            target_note: None,
        };
        fs::write(
            stub.join(RECORD_FILENAME),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        fs::write(stub.join(README_FILENAME), readme(&record)).unwrap();
        (stub, backup)
    }

    #[test]
    fn restore_never_reuses_foreign_or_symlinked_legacy_staging() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        for symlink in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let (stub, backup) = restore_fixture(tmp.path());
            let foreign = tmp.path().join("foreign");
            fs::create_dir(&foreign).unwrap();
            fs::write(foreign.join("data"), b"unrelated data").unwrap();
            let incoming = sibling(&stub, "sbh-restoring").unwrap();
            if symlink {
                std::os::unix::fs::symlink(&foreign, &incoming).unwrap();
            } else {
                fs::create_dir(&incoming).unwrap();
                fs::write(incoming.join("data"), b"interrupted work").unwrap();
            }
            let old = sibling(&stub, "sbh-stub").unwrap();
            fs::create_dir(&old).unwrap();
            fs::write(old.join("keep"), b"previous recovery").unwrap();
            let restored = restore(&stub).unwrap();
            assert_eq!(
                fs::read(stub.join("data")).unwrap(),
                b"verified backup payload"
            );
            assert_eq!(
                fs::read(backup.join("data")).unwrap(),
                b"verified backup payload"
            );
            assert_eq!(fs::read(foreign.join("data")).unwrap(), b"unrelated data");
            assert_eq!(fs::read(old.join("keep")).unwrap(), b"previous recovery");
            if symlink {
                assert_eq!(fs::read_link(incoming).unwrap(), foreign);
            } else {
                assert_eq!(
                    fs::read(incoming.join("data")).unwrap(),
                    b"interrupted work"
                );
            }
            let (kept, _) = restored.kept_stub.unwrap();
            assert_eq!(
                fs::metadata(kept.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert!(kept.join(RECORD_FILENAME).is_file());
        }
    }

    #[test]
    fn restore_lock_refuses_a_second_attempt_before_it_copies() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let (stub, _) = restore_fixture(tmp.path());
        let attempted = std::cell::Cell::new(false);
        let concurrent = |path: &Path, _: &Path| {
            let error = restore(path).unwrap_err();
            assert!(error.contains("cannot lock restore stub"), "{error}");
            attempted.set(true);
            let workspaces = fs::read_dir(path.parent().unwrap())
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".sbh-restore-")
                })
                .count();
            assert_eq!(workspaces, 1, "the second attempt never created staging");
        };
        restore_with_hooks(
            &stub,
            &RestoreHooks {
                before_copy: Some(&concurrent),
                ..RestoreHooks::default()
            },
        )
        .unwrap();
        assert!(attempted.get());
        assert_eq!(
            fs::read(stub.join("data")).unwrap(),
            b"verified backup payload"
        );
    }

    #[test]
    fn restore_copies_to_its_pinned_payload_and_refuses_a_substituted_leaf() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        for after_move in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let (stub, backup) = restore_fixture(tmp.path());
            let foreign = tmp.path().join("foreign");
            fs::create_dir(&foreign).unwrap();
            fs::write(foreign.join("data"), b"unrelated destination").unwrap();
            let workspace = std::cell::RefCell::new(PathBuf::new());
            let substitute = |_: &Path, staging: &Path| {
                *workspace.borrow_mut() = staging.to_path_buf();
                fs::rename(staging.join("payload"), staging.join("retained-payload")).unwrap();
                std::os::unix::fs::symlink(&foreign, staging.join("payload")).unwrap();
            };
            let hooks = if after_move {
                RestoreHooks {
                    after_stub_move: Some(&substitute),
                    ..RestoreHooks::default()
                }
            } else {
                RestoreHooks {
                    before_copy: Some(&substitute),
                    ..RestoreHooks::default()
                }
            };
            let error = restore_with_hooks(&stub, &hooks).unwrap_err();
            assert!(error.contains("replaced"), "{error}");
            assert!(
                stub.join(RECORD_FILENAME).is_file(),
                "original stub survives"
            );
            assert!(!stub.join("data").exists());
            assert_eq!(
                fs::read(foreign.join("data")).unwrap(),
                b"unrelated destination"
            );
            assert_eq!(
                fs::read(workspace.borrow().join("retained-payload/data")).unwrap(),
                b"verified backup payload"
            );
            assert_eq!(
                fs::read(backup.join("data")).unwrap(),
                b"verified backup payload"
            );
            assert!(error.contains(&workspace.borrow().display().to_string()));
        }
    }

    #[test]
    fn restore_refuses_a_replaced_stub_or_edited_record_after_copy() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        for replace in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let (stub, backup) = restore_fixture(tmp.path());
            let workspace = std::cell::RefCell::new(PathBuf::new());
            let change = |path: &Path, staging: &Path| {
                *workspace.borrow_mut() = staging.to_path_buf();
                if replace {
                    fs::rename(path, tmp.path().join("original-stub")).unwrap();
                    fs::create_dir(path).unwrap();
                    fs::write(path.join("data"), b"new occupant").unwrap();
                } else {
                    let file = path.join(RECORD_FILENAME);
                    let mut record: RelocationRecord =
                        serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
                    record.host = "edited during transfer".into();
                    fs::write(file, serde_json::to_vec(&record).unwrap()).unwrap();
                }
            };
            let error = restore_with_hooks(
                &stub,
                &RestoreHooks {
                    before_swap: Some(&change),
                    ..RestoreHooks::default()
                },
            )
            .unwrap_err();
            assert!(
                error.contains("changed") || error.contains("replaced"),
                "{error}"
            );
            assert!(
                error.contains(&workspace.borrow().display().to_string()),
                "{error}"
            );
            assert_eq!(
                fs::read(workspace.borrow().join("payload/data")).unwrap(),
                b"verified backup payload"
            );
            assert_eq!(
                fs::read(backup.join("data")).unwrap(),
                b"verified backup payload"
            );
            if replace {
                assert_eq!(fs::read(stub.join("data")).unwrap(), b"new occupant");
                assert!(
                    tmp.path()
                        .join("original-stub")
                        .join(RECORD_FILENAME)
                        .is_file()
                );
            } else {
                assert!(
                    fs::read_to_string(stub.join(RECORD_FILENAME))
                        .unwrap()
                        .contains("edited during transfer")
                );
                assert!(!stub.join("data").exists());
            }
        }
    }

    #[test]
    fn restore_preserves_a_path_recreated_during_swap_and_both_recovery_trees() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let (stub, backup) = restore_fixture(tmp.path());
        let workspace = std::cell::RefCell::new(PathBuf::new());
        let recreate = |path: &Path, staging: &Path| {
            *workspace.borrow_mut() = staging.to_path_buf();
            fs::create_dir(path).unwrap();
            fs::write(path.join("new-work"), b"keep the new occupant").unwrap();
        };
        let error = restore_with_hooks(
            &stub,
            &RestoreHooks {
                after_stub_move: Some(&recreate),
                ..RestoreHooks::default()
            },
        )
        .unwrap_err();
        assert!(
            error.contains("original path was not overwritten"),
            "{error}"
        );
        assert!(
            error.contains(&workspace.borrow().join("stub").display().to_string()),
            "{error}"
        );
        assert_eq!(
            fs::read(stub.join("new-work")).unwrap(),
            b"keep the new occupant"
        );
        assert_eq!(
            fs::read(workspace.borrow().join("payload/data")).unwrap(),
            b"verified backup payload"
        );
        assert!(
            workspace
                .borrow()
                .join("stub")
                .join(RECORD_FILENAME)
                .is_file()
        );
        assert_eq!(
            fs::read(backup.join("data")).unwrap(),
            b"verified backup payload"
        );
    }

    #[test]
    fn restore_reports_the_actual_staging_location_when_its_parent_moves() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let (stub, _) = restore_fixture(tmp.path());
        let retained = std::cell::RefCell::new(PathBuf::new());
        let move_parent = |path: &Path, staging: &Path| {
            let parent = path.parent().unwrap();
            let moved = tmp.path().join("moved-scratch");
            fs::rename(parent, &moved).unwrap();
            *retained.borrow_mut() = moved.join(staging.file_name().unwrap());
            fs::create_dir(parent).unwrap();
            fs::create_dir(path).unwrap();
            fs::write(path.join("new-work"), b"unrelated replacement").unwrap();
        };
        let error = restore_with_hooks(
            &stub,
            &RestoreHooks {
                before_copy: Some(&move_parent),
                ..RestoreHooks::default()
            },
        )
        .unwrap_err();
        assert!(
            error.contains("parent path was replaced or moved"),
            "{error}"
        );
        assert!(
            error.contains(&retained.borrow().display().to_string()),
            "{error}"
        );
        assert_eq!(
            fs::read(retained.borrow().join("payload/data")).unwrap(),
            b"verified backup payload"
        );
        assert!(
            tmp.path()
                .join("moved-scratch/unit")
                .join(RECORD_FILENAME)
                .is_file()
        );
        assert_eq!(
            fs::read(stub.join("new-work")).unwrap(),
            b"unrelated replacement"
        );
    }

    #[test]
    fn restore_refuses_unsafe_or_oversized_records_before_creating_staging() {
        for kind in ["symlink", "fifo", "oversized", "wrong-schema"] {
            let tmp = tempfile::tempdir().unwrap();
            let (stub, _) = restore_fixture(tmp.path());
            let path = stub.join(RECORD_FILENAME);
            let saved = tmp.path().join("saved-record");
            fs::rename(&path, &saved).unwrap();
            match kind {
                "symlink" => std::os::unix::fs::symlink(&saved, &path).unwrap(),
                "fifo" => nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap(),
                "oversized" => fs::File::create(&path)
                    .unwrap()
                    .set_len(MAX_RESTORE_RECORD_BYTES + 1)
                    .unwrap(),
                _ => {
                    let mut record: RelocationRecord =
                        serde_json::from_slice(&fs::read(&saved).unwrap()).unwrap();
                    record.schema = "not-a-relocation".into();
                    fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
            }
            assert!(restore(&stub).is_err(), "{kind}");
            assert_eq!(
                fs::read_dir(stub.parent().unwrap()).unwrap().count(),
                1,
                "{kind}"
            );
            assert!(saved.is_file());
            assert!(!stub.join("data").exists());
        }
    }

    #[test]
    fn failed_completion_save_preserves_original_backup_stub_and_resume_state() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        if !sees_every_process(&unit) {
            return;
        }
        let config = local_config(tmp.path());
        let _lock = super::super::ledger::WriterLock::acquire(&config.state_dir).unwrap();
        let preserved_state = tmp.path().join("preserved-state");
        // The transfer and its resumable destination have already been saved.
        // Now make the state path unwritable without relying on uid or chmod.
        let lose_state_directory = |_: &Path| {
            fs::rename(&config.state_dir, &preserved_state).unwrap();
            fs::write(&config.state_dir, b"state directory unavailable").unwrap();
        };
        let mut ledger = Ledger::default();
        let outcome = relocate_with_hooks(
            &config,
            &crate::platform::current(),
            &mut ledger,
            &candidate_for(&unit),
            "S",
            1_000,
            &Hooks {
                after_rename: Some(&lose_state_directory),
                ..Hooks::default()
            },
        );
        let aside = sibling(&unit, "sbh-relocating").unwrap();
        let record: RelocationRecord =
            serde_json::from_slice(&fs::read(unit.join(RECORD_FILENAME)).unwrap()).unwrap();
        let copy = PathBuf::from(record.destination.trim_end_matches('/'));
        assert!(
            matches!(&outcome, Outcome::Failed { stage, error, .. }
                if stage == "ledger"
                    && error.contains("no original bytes were removed")
                    && error.contains(&aside.display().to_string())
                    && error.contains(&record.destination)),
            "{outcome:?}"
        );
        assert_eq!(
            fs::read(aside.join("a/b/data")).unwrap(),
            vec![7u8; 300_000]
        );
        assert_eq!(fs::read(copy.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert!(unit.join(README_FILENAME).is_file());
        assert!(unit.join(MARKER_FILENAME).is_file());
        assert_eq!(ledger.in_progress.get(&unit), Some(&record.destination));
        assert!(ledger.relocations.is_empty());
        assert_eq!(Ledger::load(&preserved_state).unwrap(), ledger);
    }

    #[test]
    fn ancestor_opt_out_after_planning_refuses_before_any_transfer_or_ledger_write() {
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        let config = local_config(tmp.path());
        let candidate = candidate_for(&unit);
        // This is outside the selected unit: its own metadata and payload
        // have not changed, so the ordinary tree snapshot cannot catch it.
        let marker = unit.parent().unwrap().join(MARKER_FILENAME);
        fs::write(&marker, "relocatable = false\n").unwrap();
        let mut ledger = Ledger::default();
        let outcome = relocate(
            &config,
            &crate::platform::pal::MockPlatform::healthy(),
            &mut ledger,
            &candidate,
            "S",
            1_000,
        );
        assert!(
            matches!(&outcome, Outcome::Failed { stage, error, .. }
                if stage == "precheck"
                    && error.contains("relocatable = false")
                    && error.contains(&marker.display().to_string())),
            "{outcome:?}"
        );
        assert_eq!(fs::read(unit.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert!(!tmp.path().join("bulk").exists());
        assert!(!config.state_dir.exists());
        assert_eq!(ledger, Ledger::default());
    }

    #[test]
    fn ancestor_opt_out_after_rename_undoes_the_move_and_preserves_verified_copy() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        if !sees_every_process(&unit) {
            return;
        }
        let config = local_config(tmp.path());
        let _lock = super::super::ledger::WriterLock::acquire(&config.state_dir).unwrap();
        let marker = unit.parent().unwrap().join(MARKER_FILENAME);
        let opt_out = |_: &Path| {
            fs::write(&marker, "relocatable = false\n").unwrap();
        };
        let mut ledger = Ledger::default();
        let outcome = relocate_with_hooks(
            &config,
            &crate::platform::current(),
            &mut ledger,
            &candidate_for(&unit),
            "S",
            1_000,
            &Hooks {
                after_rename: Some(&opt_out),
                ..Hooks::default()
            },
        );
        assert!(
            matches!(&outcome, Outcome::Failed { stage, error, .. }
                if stage == "postcheck"
                    && error.contains("relocatable = false")
                    && error.contains(&marker.display().to_string())),
            "{outcome:?}"
        );
        let destination = ledger.in_progress.get(&unit).expect("resumable copy");
        let copy = PathBuf::from(destination.trim_end_matches('/'));
        assert_eq!(fs::read(unit.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert_eq!(fs::read(copy.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert!(!sibling(&unit, "sbh-relocating").unwrap().exists());
        assert!(
            !unit.join(RECORD_FILENAME).exists(),
            "no stub was installed"
        );
        assert!(ledger.relocations.is_empty());
        assert_eq!(Ledger::load(&config.state_dir).unwrap(), ledger);
    }

    #[test]
    fn late_ancestor_or_descendant_opt_out_preserves_original_copy_and_stub() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        for ancestor in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let unit = marked_tree(tmp.path());
            if !sees_every_process(&unit) {
                return;
            }
            let config = local_config(tmp.path());
            let _lock = super::super::ledger::WriterLock::acquire(&config.state_dir).unwrap();
            let opt_out = |aside: &Path| {
                let marker = if ancestor {
                    unit.parent().unwrap().join(MARKER_FILENAME)
                } else {
                    aside.join("a").join(MARKER_FILENAME)
                };
                fs::write(marker, "relocatable = false\n").unwrap();
            };
            let mut ledger = Ledger::default();
            let outcome = relocate_with_hooks(
                &config,
                &crate::platform::current(),
                &mut ledger,
                &candidate_for(&unit),
                "S",
                1_000,
                &Hooks {
                    before_remove: Some(&opt_out),
                    ..Hooks::default()
                },
            );
            let aside = sibling(&unit, "sbh-relocating").unwrap();
            assert!(
                matches!(&outcome, Outcome::Failed { stage, error, .. }
                    if stage == "remove"
                        && error.contains("relocatable = false")
                        && error.contains("no original bytes were removed")
                        && error.contains(&aside.display().to_string())
                        && error.contains(&unit.display().to_string())),
                "ancestor={ancestor}: {outcome:?}"
            );
            let record: RelocationRecord =
                serde_json::from_slice(&fs::read(unit.join(RECORD_FILENAME)).unwrap()).unwrap();
            let copy = PathBuf::from(record.destination.trim_end_matches('/'));
            assert_eq!(
                fs::read(aside.join("a/b/data")).unwrap(),
                vec![7u8; 300_000]
            );
            assert_eq!(fs::read(copy.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
            assert!(unit.join(README_FILENAME).is_file());
            assert!(unit.join(MARKER_FILENAME).is_file());
            assert!(matches!(&outcome, Outcome::Failed { error, .. }
                if error.contains(&record.destination)));
            // Completion was saved before the final guard; its copy/stub
            // record remains true, while failed removal is explicit.
            assert_eq!(ledger.relocations.len(), 1);
            assert!(ledger.in_progress.is_empty());
            assert_eq!(Ledger::load(&config.state_dir).unwrap(), ledger);
        }
    }

    #[test]
    fn content_changed_after_postcheck_preserves_new_source_and_earlier_backup() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        if !sees_every_process(&unit) {
            return;
        }
        let config = local_config(tmp.path());
        let _lock = super::super::ledger::WriterLock::acquire(&config.state_dir).unwrap();
        let new_work = |aside: &Path| {
            fs::write(aside.join("a/b/data"), b"new work after verification").unwrap();
            // A new entry makes the changed tree unambiguous even when the
            // fixture and hook run within one filesystem timestamp second.
            fs::write(aside.join("late-output"), b"also preserve this").unwrap();
        };
        let mut ledger = Ledger::default();
        let outcome = relocate_with_hooks(
            &config,
            &crate::platform::current(),
            &mut ledger,
            &candidate_for(&unit),
            "S",
            1_000,
            &Hooks {
                before_remove: Some(&new_work),
                ..Hooks::default()
            },
        );
        let aside = sibling(&unit, "sbh-relocating").unwrap();
        assert!(
            matches!(&outcome, Outcome::Failed { stage, error, .. }
                if stage == "remove"
                    && error.contains("tree changed after verification")
                    && error.contains("preserved source may contain newer data")
                    && error.contains("no original bytes were removed")
                    && error.contains(&aside.display().to_string())),
            "{outcome:?}"
        );
        let record: RelocationRecord =
            serde_json::from_slice(&fs::read(unit.join(RECORD_FILENAME)).unwrap()).unwrap();
        let copy = PathBuf::from(record.destination.trim_end_matches('/'));
        assert_eq!(
            fs::read(aside.join("a/b/data")).unwrap(),
            b"new work after verification"
        );
        assert_eq!(
            fs::read(aside.join("late-output")).unwrap(),
            b"also preserve this"
        );
        assert_eq!(fs::read(copy.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert!(!copy.join("late-output").exists());
        assert!(unit.join(README_FILENAME).is_file());
        assert!(matches!(&outcome, Outcome::Failed { error, .. }
            if error.contains(&record.destination)
                && error.contains(&unit.display().to_string())));
    }

    #[test]
    fn regular_file_opened_after_postcheck_refuses_removal_with_all_copies_intact() {
        if !rsync_available() {
            eprintln!("skipped: rsync not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        if !sees_every_process(&unit) {
            return;
        }
        let config = local_config(tmp.path());
        let _lock = super::super::ledger::WriterLock::acquire(&config.state_dir).unwrap();
        let held = std::cell::RefCell::new(None);
        let open_after_postcheck = |aside: &Path| {
            // Opening an existing regular file changes no content metadata.
            // The fresh process sweep, not the tree comparison, must veto it.
            *held.borrow_mut() = Some(fs::File::open(aside.join("a/b/data")).unwrap());
        };
        let mut ledger = Ledger::default();
        let outcome = relocate_with_hooks(
            &config,
            &crate::platform::current(),
            &mut ledger,
            &candidate_for(&unit),
            "S",
            1_000,
            &Hooks {
                before_remove: Some(&open_after_postcheck),
                ..Hooks::default()
            },
        );
        let aside = sibling(&unit, "sbh-relocating").unwrap();
        assert!(
            matches!(&outcome, Outcome::Failed { stage, error, .. }
                if stage == "remove"
                    && error.contains("in use before removal")
                    && error.contains("open file descriptor")
                    && error.contains("no original bytes were removed")
                    && error.contains(&aside.display().to_string())),
            "{outcome:?}"
        );
        assert!(held.borrow().is_some());
        let record: RelocationRecord =
            serde_json::from_slice(&fs::read(unit.join(RECORD_FILENAME)).unwrap()).unwrap();
        let copy = PathBuf::from(record.destination.trim_end_matches('/'));
        assert_eq!(
            fs::read(aside.join("a/b/data")).unwrap(),
            vec![7u8; 300_000]
        );
        assert_eq!(fs::read(copy.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
        assert!(unit.join(README_FILENAME).is_file());
        assert!(matches!(&outcome, Outcome::Failed { error, .. }
            if error.contains(&record.destination)
                && error.contains(&unit.display().to_string())));
    }

    #[test]
    fn a_tree_holding_a_live_socket_stays_put() {
        if !rsync_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        // A live server's socket is the only sign of use (bd-zx8b).
        let _listener = std::os::unix::net::UnixListener::bind(unit.join("server.sock")).unwrap();
        let config = local_config(tmp.path());
        let outcome = relocate(
            &config,
            &crate::platform::current(),
            &mut Ledger::default(),
            &candidate_for(&unit),
            "S",
            1_000,
        );
        assert!(
            matches!(&outcome, Outcome::Failed { stage, error, .. } if stage == "precheck" && error.contains("in use")),
            "{outcome:?}"
        );
        assert!(unit.join("a/b/data").is_file());
        assert!(!tmp.path().join("bulk").exists());
    }

    #[test]
    fn a_path_recreated_mid_move_is_left_alone() {
        if !rsync_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        if !sees_every_process(&unit) {
            return;
        }
        let config = local_config(tmp.path());
        // A job recreates the path between the rename and the stub.
        let job = |path: &Path| {
            fs::create_dir(path).unwrap();
            fs::write(path.join("job-output"), b"new work").unwrap();
        };
        let outcome = relocate_with_hooks(
            &config,
            &crate::platform::current(),
            &mut Ledger::default(),
            &candidate_for(&unit),
            "S",
            1_000,
            &Hooks {
                after_rename: Some(&job),
                ..Hooks::default()
            },
        );
        assert!(
            matches!(&outcome, Outcome::Failed { stage, .. } if stage == "stub"),
            "{outcome:?}"
        );
        // The job's directory is untouched, and the original tree is intact
        // where it was renamed to.
        assert_eq!(fs::read(unit.join("job-output")).unwrap(), b"new work");
        let aside = sibling(&unit, "sbh-relocating").unwrap();
        assert_eq!(
            fs::read(aside.join("a/b/data")).unwrap(),
            vec![7u8; 300_000]
        );
    }

    #[test]
    fn restore_keeps_a_stub_that_holds_new_files() {
        if !rsync_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        if !sees_every_process(&unit) {
            return;
        }
        let config = local_config(tmp.path());
        let outcome = relocate(
            &config,
            &crate::platform::current(),
            &mut Ledger::default(),
            &candidate_for(&unit),
            "S",
            1_000,
        );
        assert!(matches!(outcome, Outcome::Relocated { .. }), "{outcome:?}");
        fs::write(unit.join("written-after-the-move"), b"keep me").unwrap();
        let restored = restore(&unit).unwrap();
        let (kept, names) = restored.kept_stub.expect("stub kept");
        assert_eq!(names, vec!["written-after-the-move".to_string()]);
        assert_eq!(
            fs::read(kept.join("written-after-the-move")).unwrap(),
            b"keep me"
        );
        assert_eq!(fs::read(unit.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
    }

    /// Mount a 1 MiB tmpfs at `at` holding one file, or `None` without the
    /// privilege to mount (the test then has nothing to prove here).
    fn mount_victim(at: &Path) -> Option<PathBuf> {
        use nix::mount::{MsFlags, mount};
        mount(
            Some("tmpfs"),
            at,
            Some("tmpfs"),
            MsFlags::empty(),
            Some("size=1m"),
        )
        .ok()?;
        let victim = at.join("victim");
        fs::write(&victim, b"not part of the tree").unwrap();
        Some(victim)
    }

    fn unmount(at: &Path) {
        let _ = nix::mount::umount2(at, nix::mount::MntFlags::MNT_DETACH);
    }

    fn mount_allowed(tmp: &Path) -> bool {
        let probe = tmp.join("mount-probe");
        fs::create_dir(&probe).unwrap();
        let allowed = mount_victim(&probe).is_some();
        unmount(&probe);
        allowed
    }

    #[test]
    fn a_mount_appearing_after_the_precheck_stops_the_move() {
        let tmp = tempfile::tempdir().unwrap();
        if !rsync_available() || !mount_allowed(tmp.path()) {
            eprintln!("skipped: needs rsync and CAP_SYS_ADMIN");
            return;
        }
        // The filesystem exists before the tree is planned, so its times are
        // no newer than the snapshot: only the device boundary gives it away.
        let staging = tmp.path().join("staging");
        fs::create_dir(&staging).unwrap();
        mount_victim(&staging).unwrap();
        let unit = marked_tree(tmp.path());
        fs::create_dir(unit.join("a/mnt")).unwrap();
        let config = local_config(tmp.path());
        let bound = std::cell::Cell::new(false);
        let bind_inside = |path: &Path| {
            use nix::mount::{MsFlags, mount};
            let aside = sibling(path, "sbh-relocating").unwrap();
            let target = aside.join("a/mnt");
            bound.set(
                mount(
                    Some(&staging),
                    &target,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                )
                .is_ok(),
            );
        };
        let outcome = relocate_with_hooks(
            &config,
            &crate::platform::current(),
            &mut Ledger::default(),
            &candidate_for(&unit),
            "S",
            1_000,
            &Hooks {
                after_rename: Some(&bind_inside),
                ..Hooks::default()
            },
        );
        // The postcheck sees the boundary and puts the tree back.
        let kept = fs::read(unit.join("a/mnt/victim")).or_else(|_| {
            fs::read(
                sibling(&unit, "sbh-relocating")
                    .unwrap()
                    .join("a/mnt/victim"),
            )
        });
        unmount(&unit.join("a/mnt"));
        unmount(&sibling(&unit, "sbh-relocating").unwrap().join("a/mnt"));
        let staged = fs::read(staging.join("victim"));
        unmount(&staging);
        assert!(bound.get(), "bind mount failed");
        assert!(
            matches!(&outcome, Outcome::Failed { stage, .. } if stage == "postcheck"),
            "{outcome:?}"
        );
        assert_eq!(kept.unwrap(), b"not part of the tree");
        assert_eq!(staged.unwrap(), b"not part of the tree");
        assert_eq!(fs::read(unit.join("a/b/data")).unwrap(), vec![7u8; 300_000]);
    }

    #[test]
    fn removal_stops_at_a_mount_that_appears_after_the_postcheck() {
        let tmp = tempfile::tempdir().unwrap();
        if !rsync_available() || !mount_allowed(tmp.path()) {
            eprintln!("skipped: needs rsync and CAP_SYS_ADMIN");
            return;
        }
        let unit = marked_tree(tmp.path());
        fs::create_dir(unit.join("a/mnt")).unwrap();
        let config = local_config(tmp.path());
        let aside = sibling(&unit, "sbh-relocating").unwrap();
        let mount_inside = |aside: &Path| {
            assert!(mount_victim(&aside.join("a/mnt")).is_some());
        };
        let outcome = relocate_with_hooks(
            &config,
            &crate::platform::current(),
            &mut Ledger::default(),
            &candidate_for(&unit),
            "S",
            1_000,
            &Hooks {
                before_remove: Some(&mount_inside),
                ..Hooks::default()
            },
        );
        let kept = fs::read(aside.join("a/mnt/victim"));
        unmount(&aside.join("a/mnt"));
        // The removal refuses the other device; the mounted file survives.
        assert!(
            matches!(&outcome, Outcome::Failed { stage, .. } if stage == "remove"),
            "{outcome:?}"
        );
        assert_eq!(kept.unwrap(), b"not part of the tree");
    }

    #[test]
    fn a_mount_inside_fails_the_postcheck() {
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        let snapshot = survey::survey_tree(&unit, 0, 10_000).unwrap().units[0].clone();
        let mut after = survey::survey_tree(&unit, 0, 10_000).unwrap();
        assert!(postcheck_matches(&snapshot, &after));
        after.units[0].crosses_mount = true;
        assert!(!postcheck_matches(&snapshot, &after));
        after.units[0].crosses_mount = false;
        after.units[0].unreadable = true;
        assert!(!postcheck_matches(&snapshot, &after));
    }

    #[test]
    fn a_tree_changed_after_planning_stays_put() {
        if !rsync_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let unit = marked_tree(tmp.path());
        let config = local_config(tmp.path());
        let candidate = candidate_for(&unit);
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        fs::write(unit.join("late"), b"written after planning").unwrap();
        let outcome = relocate(
            &config,
            &crate::platform::current(),
            &mut Ledger::default(),
            &candidate,
            "S",
            1_000,
        );
        assert!(
            matches!(&outcome, Outcome::Failed { stage, .. } if stage == "precheck"),
            "{outcome:?}"
        );
        assert!(unit.join("late").is_file() && unit.join("a/b/data").is_file());
    }

    #[test]
    fn destinations() {
        let config = RelocationConfig::default();
        let path = Path::new("/dev/shm/scratch-x");
        assert_eq!(
            destination_for(
                &config,
                "ubuntu@backup-host:/bulk/sbh-relocated/",
                "worker2",
                "20261028T030000Z",
                path
            ),
            "ubuntu@backup-host:/bulk/sbh-relocated/worker2/20261028T030000Z/dev/shm/scratch-x/"
        );
        let per_host = RelocationConfig {
            include_hostname: false,
            ..RelocationConfig::default()
        };
        assert_eq!(
            destination_for(&per_host, "sbhrelo@backup-host:", "worker2", "S", path),
            "sbhrelo@backup-host:S/dev/shm/scratch-x/"
        );
        assert_eq!(
            destination_for(
                &config,
                "/bulk/r",
                "backup-host",
                "S",
                Path::new("/data/tmp/q")
            ),
            "/bulk/r/backup-host/S/data/tmp/q/"
        );
        assert!(is_remote("ubuntu@backup-host:/bulk"));
        assert!(is_remote("backup-host:"));
        assert!(!is_remote("/bulk/a:b"));
    }
}
