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
//! 7. Remove the renamed tree.
//!
//! Every remote operation is an rsync, so a key restricted with `rrsync` to
//! one directory on the target is enough.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
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
    copy.arg(source).arg(destination);
    run(copy, "copy")?;
    let mut verify = rsync_command(config, remote);
    verify
        .args(["--checksum", "--dry-run", "--itemize-changes", "--delete"])
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
backup copy is kept.\n\n\
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
    if let Some(reason) = holder(platform, &path) {
        return fail("precheck", format!("in use: {reason}"));
    }
    let snapshot = match survey::survey_tree(&path, 0, config.max_entries) {
        Ok(survey)
            if !survey.truncated
                && !survey.units[0].unreadable
                && !survey.units[0].crosses_mount =>
        {
            survey.units[0].clone()
        }
        Ok(_) => return fail("precheck", "tree is no longer fully readable".into()),
        Err(error) => return fail("precheck", error.to_string()),
    };
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
    match survey::survey_tree(&aside, 0, config.max_entries) {
        Ok(after) if postcheck_matches(&snapshot, &after) => {}
        Ok(_) => return undo("postcheck", "tree changed during the copy".into()),
        Err(error) => return undo("postcheck", error.to_string()),
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

    ledger.in_progress.remove(&path);
    ledger.observations.remove(&path);
    ledger.relocations.push(RelocationEntry {
        path: path.clone(),
        destination: destination.clone(),
        bytes: snapshot.bytes,
        files: snapshot.files,
        relocated_at: now,
    });
    let saved = ledger.save(&config.state_dir);
    // The copy is verified and the stub is in place; only now may the
    // original bytes go.
    if let Some(hook) = hooks.before_remove {
        hook(&aside);
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
    if let Err(error) = saved {
        return fail(
            "ledger",
            format!("relocated, but the ledger was not saved: {error}"),
        );
    }
    Outcome::Relocated {
        path,
        destination,
        bytes: snapshot.bytes,
    }
}

/// Bring a relocated tree back from its copy and replace the stub.
pub fn restore(stub: &Path) -> Result<Restored, String> {
    let record: RelocationRecord = serde_json::from_slice(
        &fs::read(stub.join(RECORD_FILENAME))
            .map_err(|error| format!("{}: {error}", stub.join(RECORD_FILENAME).display()))?,
    )
    .map_err(|error| format!("bad record: {error}"))?;
    if record.path != stub {
        return Err(format!(
            "the record is for {}, not {}",
            record.path.display(),
            stub.display()
        ));
    }
    let remote = is_remote(&record.destination);
    let config = RelocationConfig {
        ssh_identity: record.ssh_identity.clone(),
        ssh_port: record.ssh_port,
        ssh_options: record.ssh_options.clone(),
        fake_super: record.fake_super,
        ..RelocationConfig::default()
    };
    let incoming = sibling(stub, "sbh-restoring").map_err(|error| error.to_string())?;
    let incoming_arg = format!("{}/", incoming.display());
    copy_and_verify(&config, remote, &record.destination, &incoming_arg)
        .map_err(|(stage, error)| format!("{stage}: {error}"))?;
    let old_stub = sibling(stub, "sbh-stub").map_err(|error| error.to_string())?;
    fs::rename(stub, &old_stub).map_err(|error| format!("moving the stub aside: {error}"))?;
    if let Err(error) = fs::rename(&incoming, stub) {
        let _ = fs::rename(&old_stub, stub);
        return Err(format!("swapping the tree in: {error}"));
    }
    // The stub is an ordinary directory; a job may have written into it
    // since the move. Only a stub holding nothing but sbh's files goes.
    let foreign: Vec<String> = fs::read_dir(&old_stub)
        .map_err(|error| format!("restored, but reading the old stub failed: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            ![README_FILENAME, RECORD_FILENAME, MARKER_FILENAME].contains(&name.as_str())
        })
        .collect();
    if !foreign.is_empty() {
        return Ok(Restored {
            path: record.path,
            kept_stub: Some((old_stub, foreign)),
        });
    }
    remove_own_stub(&old_stub);
    Ok(Restored {
        path: record.path,
        kept_stub: old_stub.exists().then(|| (old_stub, Vec::new())),
    })
}

/// A completed restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The restored path.
    pub path: PathBuf,
    /// The old stub, kept because it held more than sbh's files, with the
    /// names it held.
    pub kept_stub: Option<(PathBuf, Vec<String>)>,
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use crate::relocate::plan::Verdict;

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
        assert_eq!(
            (restored.path.as_path(), restored.kept_stub),
            (unit.as_path(), None)
        );
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
