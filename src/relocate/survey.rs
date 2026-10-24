//! One metadata walk of a protected tree, aggregated per candidate unit.
//!
//! The metadata walk follows no symlinks. Its policy-aware form reads only
//! bounded protection markers, never the files being relocated. It records, for
//! the marked tree and for every directory up to `unit_depth` below it, the
//! newest change (max of mtime and ctime over every entry), the newest
//! regular-file atime, and the allocated bytes. A directory on another
//! device is not entered; its units are flagged instead.

use std::ffi::OsStr;
#[cfg(any(target_os = "linux", test))]
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, statat};
use serde::Serialize;

use super::config::RelocationConfig;
use crate::scanner::protection::MARKER_FILENAME;
use crate::scanner::quarantine::open_beneath;

const MAX_MARKER_BYTES: u64 = 64 * 1024;

/// Policy evidence that prevents moving a unit, even when it is dormant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyVeto {
    /// The protected or excluded entry, which can be below the unit boundary.
    pub path: PathBuf,
    /// Why this entry cannot be included in a relocation.
    pub reason: String,
    /// The configured or built-in exclusion, when this is an excluded component.
    pub excluded_pattern: Option<String>,
}

impl std::fmt::Display for PolicyVeto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.reason)
    }
}

/// Aggregates for one candidate unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnitStats {
    /// The unit's directory.
    pub path: PathBuf,
    /// Levels below the marked tree (0 is the marked tree itself).
    pub depth: usize,
    /// Allocated bytes of the regular files and symlinks below it.
    pub bytes: u64,
    /// Regular files below it.
    pub files: u64,
    /// Entries below it, of any kind.
    pub entries: u64,
    /// Newest mtime/ctime, unit directory included (Unix seconds).
    pub newest_change: i64,
    /// Newest mtime/ctime of the entries below the unit directory. Renaming
    /// the unit changes its own ctime, so post-rename checks compare this.
    pub newest_change_below: i64,
    /// Newest regular-file atime below it, if it holds any regular file.
    pub newest_access: Option<i64>,
    /// A directory below it is on another device and was not walked.
    pub crosses_mount: bool,
    /// Some directory below it could not be read.
    pub unreadable: bool,
    /// An ancestor or descendant must stay in place. A veto on a sibling is
    /// never inherited: unaffected sibling units can still be relocated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relocation_veto: Option<PolicyVeto>,
    /// Owner of the unit directory.
    pub uid: u32,
    /// Group of the unit directory.
    pub gid: u32,
    /// Permission bits of the unit directory.
    pub mode: u32,
}

/// The walk of one marked tree.
#[derive(Debug, Clone, Serialize)]
pub struct TreeSurvey {
    /// Units in walk order; parents precede their descendants.
    pub units: Vec<UnitStats>,
    /// The entry budget ran out, so no unit's aggregates are complete.
    pub truncated: bool,
    /// Entries visited.
    pub entries: u64,
}

impl TreeSurvey {
    /// Index of the nearest enclosing unit of `index`, if any.
    #[must_use]
    pub fn parent_of(&self, index: usize) -> Option<usize> {
        let path = &self.units[index].path;
        (0..index)
            .rev()
            .find(|&candidate| path.starts_with(&self.units[candidate].path))
    }
}

fn change_time(meta: &Stat) -> i64 {
    meta.st_mtime.max(meta.st_ctime)
}

#[allow(clippy::useless_conversion)] // mode_t is narrower on some Unix targets.
fn new_unit(path: PathBuf, depth: usize, meta: &Stat) -> UnitStats {
    UnitStats {
        path,
        depth,
        bytes: 0,
        files: 0,
        entries: 0,
        newest_change: change_time(meta),
        newest_change_below: i64::MIN,
        newest_access: None,
        crosses_mount: false,
        unreadable: false,
        relocation_veto: None,
        uid: meta.st_uid,
        gid: meta.st_gid,
        mode: u32::from(meta.st_mode) & 0o7777,
    }
}

pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

/// Reopen a descendant from the pinned root one component at a time. Keeping
/// only paths in the pending queue bounds descriptors even in very wide trees.
pub(super) fn open_relative_directory(root: &File, relative: &Path) -> io::Result<File> {
    let mut directory = root.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relocation requires normal descendant path components",
            ));
        };
        let child = File::from(open_beneath(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        )?);
        if rustix::fs::fstat(&child)?.st_dev != rustix::fs::fstat(&directory)?.st_dev {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        directory = child;
    }
    Ok(directory)
}

fn same_stamp(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

/// Missing markers are distinct from unsafe or unreadable markers. Empty
/// markers and the TOML/JSON metadata formats used by protection are valid;
/// an explicit relocation key must be a boolean.
pub(super) fn marker_policy(directory: &File) -> io::Result<Option<bool>> {
    let before = match statat(directory, MARKER_FILENAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || !u64::try_from(before.st_size).is_ok_and(|size| size <= MAX_MARKER_BYTES)
    {
        return Err(io::Error::other(
            "protection marker is not a bounded regular file",
        ));
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    // Reading policy must not make every marked tree look recently used at
    // the next sweep. Without permission to avoid atime writes, fail closed.
    #[cfg(target_os = "linux")]
    let flags = flags | OFlags::NOATIME;
    let mut marker = File::from(open_beneath(directory, OsStr::new(MARKER_FILENAME), flags)?);
    if !same_stamp(&before, &rustix::fs::fstat(&marker)?) {
        return Err(io::Error::other("protection marker changed while opening"));
    }
    let mut contents = String::new();
    marker
        .by_ref()
        .take(MAX_MARKER_BYTES + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_MARKER_BYTES
        || !same_stamp(&before, &rustix::fs::fstat(&marker)?)
        || !same_stamp(
            &before,
            &statat(directory, MARKER_FILENAME, AtFlags::SYMLINK_NOFOLLOW)?,
        )
    {
        return Err(io::Error::other("protection marker changed while reading"));
    }
    if let Ok(table) = toml::from_str::<toml::Table>(&contents) {
        return table.get("relocatable").map_or(Ok(Some(true)), |value| {
            value
                .as_bool()
                .map(Some)
                .ok_or_else(|| io::Error::other("protection marker relocatable must be a boolean"))
        });
    }
    if let Ok(table) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&contents)
    {
        return table.get("relocatable").map_or(Ok(Some(true)), |value| {
            value
                .as_bool()
                .map(Some)
                .ok_or_else(|| io::Error::other("protection marker relocatable must be a boolean"))
        });
    }
    Err(io::Error::other(
        "protection marker is not valid TOML or JSON",
    ))
}

pub(super) fn marker_veto(directory: &File, path: &Path) -> Option<PolicyVeto> {
    let reason = match marker_policy(directory) {
        Ok(Some(false)) => "protection marker sets relocatable = false".into(),
        Err(error) => format!("cannot establish relocation permission: {error}"),
        Ok(None | Some(true)) => return None,
    };
    Some(PolicyVeto {
        path: path.join(MARKER_FILENAME),
        reason,
        excluded_pattern: None,
    })
}

pub(super) fn excluded_veto(config: &RelocationConfig, path: &Path) -> Option<PolicyVeto> {
    let pattern = config.excluded_by(&path.file_name()?.to_string_lossy())?;
    Some(PolicyVeto {
        path: path.to_path_buf(),
        reason: format!("component matches never-relocate pattern {pattern}"),
        excluded_pattern: Some(pattern),
    })
}

/// Walk `root` and aggregate per unit. `max_entries` bounds the whole walk.
pub fn survey_tree(root: &Path, unit_depth: usize, max_entries: u64) -> io::Result<TreeSurvey> {
    survey_tree_inner(root, unit_depth, max_entries, None)
}

/// Include relocation policy throughout the tree, even below `unit_depth`.
///
/// Descendant vetoes apply to enclosing units; ancestor vetoes apply only to
/// their own branch, so a protected child does not hide movable siblings.
pub fn survey_tree_with_policy(
    root: &Path,
    unit_depth: usize,
    max_entries: u64,
    config: &RelocationConfig,
) -> io::Result<TreeSurvey> {
    survey_tree_inner(root, unit_depth, max_entries, Some(config))
}

struct PendingDirectory {
    relative: PathBuf,
    depth: usize,
    chain: Vec<usize>,
    expected: Stat,
    inherited_veto: Option<PolicyVeto>,
}

#[allow(clippy::too_many_lines)]
fn survey_tree_inner(
    root: &Path,
    unit_depth: usize,
    max_entries: u64,
    config: Option<&RelocationConfig>,
) -> io::Result<TreeSurvey> {
    let anchor = open_directory(root)?;
    let root_meta = rustix::fs::fstat(&anchor)?;
    let device = root_meta.st_dev;
    let mut survey = TreeSurvey {
        units: vec![new_unit(root.to_path_buf(), 0, &root_meta)],
        truncated: false,
        entries: 0,
    };
    let mut stack = vec![PendingDirectory {
        relative: PathBuf::new(),
        depth: 0,
        chain: vec![0],
        expected: root_meta,
        inherited_veto: None,
    }];
    while let Some(task) = stack.pop() {
        let path = root.join(&task.relative);
        let opened = open_relative_directory(&anchor, &task.relative).and_then(|directory| {
            let stat = rustix::fs::fstat(&directory)?;
            if stat.st_dev != task.expected.st_dev || stat.st_ino != task.expected.st_ino {
                return Err(io::Error::other(
                    "relocation directory changed during survey",
                ));
            }
            let reader = Dir::read_from(&directory)?;
            Ok((directory, stat, reader))
        });
        let (directory, before, reader) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                for &unit in &task.chain {
                    if error.raw_os_error() == Some(libc::EXDEV) {
                        survey.units[unit].crosses_mount = true;
                    } else {
                        survey.units[unit].unreadable = true;
                    }
                }
                continue;
            }
        };
        let inherited = task
            .inherited_veto
            .or_else(|| config.and_then(|_| marker_veto(&directory, &path)));
        if let Some(veto) = &inherited {
            for &unit in &task.chain {
                survey.units[unit]
                    .relocation_veto
                    .get_or_insert_with(|| veto.clone());
            }
        }
        for entry in reader {
            let Ok(entry) = entry else {
                for &unit in &task.chain {
                    survey.units[unit].unreadable = true;
                }
                continue;
            };
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == OsStr::new(".") || name == OsStr::new("..") {
                continue;
            }
            survey.entries += 1;
            if survey.entries > max_entries {
                survey.truncated = true;
                return Ok(survey);
            }
            let Ok(meta) = statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) else {
                for &unit in &task.chain {
                    survey.units[unit].unreadable = true;
                }
                continue;
            };
            let child_path = path.join(name);
            let excluded = config.and_then(|config| excluded_veto(config, &child_path));
            if let Some(veto) = &excluded {
                for &unit in &task.chain {
                    survey.units[unit]
                        .relocation_veto
                        .get_or_insert_with(|| veto.clone());
                }
            }
            let changed = change_time(&meta);
            let file_type = FileType::from_raw_mode(meta.st_mode);
            let regular = file_type == FileType::RegularFile;
            let accessed = meta.st_atime;
            let counted_bytes = if file_type == FileType::Directory {
                0
            } else {
                u64::try_from(meta.st_blocks)
                    .ok()
                    .and_then(|blocks| blocks.checked_mul(512))
                    .ok_or_else(|| io::Error::other("allocated byte accounting overflow"))?
            };
            for &unit in &task.chain {
                let stats = &mut survey.units[unit];
                stats.entries += 1;
                stats.bytes = stats
                    .bytes
                    .checked_add(counted_bytes)
                    .ok_or_else(|| io::Error::other("allocated byte accounting overflow"))?;
                stats.newest_change = stats.newest_change.max(changed);
                stats.newest_change_below = stats.newest_change_below.max(changed);
                if regular {
                    stats.files += 1;
                    stats.newest_access =
                        Some(stats.newest_access.map_or(accessed, |a| a.max(accessed)));
                }
            }
            if file_type != FileType::Directory {
                continue;
            }
            if meta.st_dev != device {
                for &unit in &task.chain {
                    survey.units[unit].crosses_mount = true;
                }
                continue;
            }
            let child_veto = inherited.clone().or(excluded);
            let mut child_chain = task.chain.clone();
            if task.depth < unit_depth {
                let mut unit = new_unit(child_path, task.depth + 1, &meta);
                unit.relocation_veto.clone_from(&child_veto);
                survey.units.push(unit);
                child_chain.push(survey.units.len() - 1);
            }
            stack.push(PendingDirectory {
                relative: task.relative.join(name),
                depth: task.depth + 1,
                chain: child_chain,
                expected: meta,
                inherited_veto: child_veto,
            });
        }
        if !same_stamp(&before, &rustix::fs::fstat(&directory)?) {
            for &unit in &task.chain {
                survey.units[unit].unreadable = true;
            }
        }
    }
    // Order units so every parent precedes its descendants.
    survey.units.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(survey)
}

/// Whether the mount holding `path` maintains atime. `None` when unknown
/// (not Linux, or the mount table could not be read): no atime evidence.
#[must_use]
pub fn atime_maintained(path: &Path) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let table = fs::read_to_string("/proc/self/mountinfo").ok()?;
        let resolved = fs::canonicalize(path).ok()?;
        atime_maintained_in(&table, &resolved)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

/// Parse a mountinfo table and decide atime maintenance for `path`.
#[must_use]
pub fn atime_maintained_in(mountinfo: &str, path: &Path) -> Option<bool> {
    let mut best: Option<(usize, bool)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 6 {
            continue;
        }
        let mount_point = PathBuf::from(unescape_mountinfo(fields[4]));
        if !path.starts_with(&mount_point) {
            continue;
        }
        let depth = mount_point.components().count();
        let maintained = !fields[5].split(',').any(|option| option == "noatime");
        // Later lines for the same mount point are mounted over earlier ones.
        if best.is_none_or(|(best_depth, _)| depth >= best_depth) {
            best = Some((depth, maintained));
        }
    }
    best.map(|(_, maintained)| maintained)
}

/// Undo mountinfo's octal escapes (`\040` for a space, and so on).
fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..=index + 3]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let digit = |offset: usize| u32::from(bytes[index + offset] - b'0');
            if let Ok(value) = u8::try_from(digit(1) * 64 + digit(2) * 8 + digit(3)) {
                out.push(value);
                index += 4;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use filetime::{FileTime, set_symlink_file_times};

    fn age(path: &Path, days: i64) {
        let when = FileTime::from_unix_time(chrono::Utc::now().timestamp() - days * 86_400, 0);
        set_symlink_file_times(path, when, when).unwrap();
    }

    #[test]
    fn aggregates_per_unit_and_keeps_parents_first() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("marked");
        fs::create_dir_all(root.join("old/deep")).unwrap();
        fs::create_dir_all(root.join("new")).unwrap();
        fs::write(root.join("old/deep/a"), vec![1u8; 10_000]).unwrap();
        fs::write(root.join("new/b"), b"b").unwrap();
        for path in ["old/deep/a", "old/deep", "old"] {
            age(&root.join(path), 30);
        }
        let survey = survey_tree(&root, 2, 1_000).unwrap();
        assert!(!survey.truncated);
        let paths: Vec<_> = survey.units.iter().map(|u| u.path.clone()).collect();
        assert_eq!(
            paths,
            vec![
                root.clone(),
                root.join("new"),
                root.join("old"),
                root.join("old/deep")
            ]
        );
        let old = &survey.units[2];
        assert_eq!(old.files, 1);
        // ctime cannot be set backwards, so only the access evidence is old.
        assert!(old.newest_access.unwrap() < chrono::Utc::now().timestamp() - 29 * 86_400);
        assert_eq!(survey.parent_of(3), Some(2));
        assert_eq!(survey.parent_of(1), Some(0));
        assert_eq!(survey.parent_of(0), None);
        assert!(survey.units[0].bytes >= survey.units[2].bytes);
    }

    #[test]
    fn symlinks_are_not_followed_and_budget_truncates() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("big"), vec![0u8; 50_000]).unwrap();
        let root = tmp.path().join("marked");
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let survey = survey_tree(&root, 2, 1_000).unwrap();
        assert_eq!(survey.units.len(), 1);
        assert_eq!(survey.units[0].files, 0);
        assert!(survey.units[0].bytes < 50_000);
        for index in 0..10 {
            fs::write(root.join(format!("f{index}")), b"x").unwrap();
        }
        assert!(survey_tree(&root, 2, 5).unwrap().truncated);
    }

    #[test]
    fn policy_veto_below_unit_depth_propagates_up_but_not_sideways() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("marked");
        fs::create_dir_all(root.join("pinned/deep/below")).unwrap();
        fs::create_dir_all(root.join("safe/child")).unwrap();
        fs::write(root.join(MARKER_FILENAME), "").unwrap();
        let marker = root.join("pinned/deep/below").join(MARKER_FILENAME);
        fs::write(&marker, "relocatable = false\n").unwrap();
        let config = RelocationConfig::default();
        let survey = survey_tree_with_policy(&root, 1, 1_000, &config).unwrap();
        assert_eq!(survey.units.len(), 3);
        for unit in &survey.units {
            if unit.path == root.join("safe") {
                assert!(unit.relocation_veto.is_none());
            } else {
                assert_eq!(unit.relocation_veto.as_ref().unwrap().path, marker);
            }
        }
    }

    #[test]
    fn descendant_true_cannot_override_an_ancestor_false() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("marked");
        fs::create_dir_all(root.join("pinned/child")).unwrap();
        fs::create_dir_all(root.join("safe")).unwrap();
        let marker = root.join("pinned").join(MARKER_FILENAME);
        fs::write(&marker, "relocatable = false\n").unwrap();
        fs::write(
            root.join("pinned/child").join(MARKER_FILENAME),
            "relocatable = true\n",
        )
        .unwrap();
        let survey =
            survey_tree_with_policy(&root, 2, 1_000, &RelocationConfig::default()).unwrap();
        let child = survey
            .units
            .iter()
            .find(|unit| unit.path == root.join("pinned/child"))
            .unwrap();
        assert_eq!(child.relocation_veto.as_ref().unwrap().path, marker);
        let safe = survey
            .units
            .iter()
            .find(|unit| unit.path == root.join("safe"))
            .unwrap();
        assert!(safe.relocation_veto.is_none());
    }

    #[test]
    fn marker_formats_and_unsafe_entries_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        for (name, contents, permission) in [
            ("empty", "", Some(true)),
            ("toml", "added_by = \"agent\"\n", Some(true)),
            (
                "json",
                "{\"reason\":\"keep\",\"relocatable\":false}",
                Some(false),
            ),
            ("false", "relocatable = false\n", Some(false)),
            ("malformed", "relocatable =", None),
            ("wrong_type", "relocatable = \"false\"", None),
            ("json_wrong_type", "{\"relocatable\":\"false\"}", None),
        ] {
            let directory = tmp.path().join(name);
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join(MARKER_FILENAME), contents).unwrap();
            let descriptor = open_directory(&directory).unwrap();
            let result = marker_policy(&descriptor);
            if let Some(permission) = permission {
                assert_eq!(result.unwrap(), Some(permission), "{name}");
            } else {
                assert!(result.is_err(), "{name} granted permission");
                assert!(marker_veto(&descriptor, &directory).is_some());
            }
        }
        for name in ["symlink", "directory", "fifo", "oversized"] {
            let directory = tmp.path().join(name);
            fs::create_dir(&directory).unwrap();
            let marker = directory.join(MARKER_FILENAME);
            match name {
                "symlink" => std::os::unix::fs::symlink(
                    tmp.path().join("empty").join(MARKER_FILENAME),
                    &marker,
                )
                .unwrap(),
                "directory" => fs::create_dir(&marker).unwrap(),
                "fifo" => nix::unistd::mkfifo(&marker, nix::sys::stat::Mode::S_IRUSR).unwrap(),
                "oversized" => File::create(&marker)
                    .unwrap()
                    .set_len(MAX_MARKER_BYTES + 1)
                    .unwrap(),
                _ => unreachable!(),
            }
            let descriptor = open_directory(&directory).unwrap();
            assert!(
                marker_policy(&descriptor).is_err(),
                "{name} granted permission"
            );
            let report =
                survey_tree_with_policy(&directory, 0, 100, &RelocationConfig::default()).unwrap();
            assert!(
                report.units[0].relocation_veto.is_some(),
                "{name} was not vetoed"
            );
        }
    }

    #[test]
    fn excluded_descendant_applies_beyond_unit_depth_and_to_its_children() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("marked");
        fs::create_dir_all(root.join("branch/deep/.cargo/cache")).unwrap();
        fs::create_dir_all(root.join("safe")).unwrap();
        let survey =
            survey_tree_with_policy(&root, 4, 1_000, &RelocationConfig::default()).unwrap();
        for unit in &survey.units {
            if unit.path == root.join("safe") {
                assert!(unit.relocation_veto.is_none());
            } else {
                assert_eq!(
                    unit.relocation_veto
                        .as_ref()
                        .unwrap()
                        .excluded_pattern
                        .as_deref(),
                    Some(".cargo")
                );
            }
        }
        let shallow =
            survey_tree_with_policy(&root, 0, 1_000, &RelocationConfig::default()).unwrap();
        assert_eq!(shallow.units.len(), 1);
        assert_eq!(
            shallow.units[0]
                .relocation_veto
                .as_ref()
                .unwrap()
                .excluded_pattern
                .as_deref(),
            Some(".cargo")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn policy_reads_do_not_reset_marker_access_age() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join(MARKER_FILENAME);
        fs::write(&marker, "added_by = \"agent\"\n").unwrap();
        age(&marker, 30);
        let before = fs::metadata(&marker).unwrap();
        let survey =
            survey_tree_with_policy(tmp.path(), 0, 100, &RelocationConfig::default()).unwrap();
        assert!(survey.units[0].relocation_veto.is_none());
        let after = fs::metadata(&marker).unwrap();
        assert_eq!(
            (before.atime(), before.atime_nsec()),
            (after.atime(), after.atime_nsec())
        );
    }

    #[test]
    fn mountinfo_noatime_and_escapes() {
        let table = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 0:5 / /data rw,noatime shared:2 - btrfs /dev/sdb rw
41 22 0:6 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw
42 40 0:7 / /data/my\\040dir rw,relatime shared:4 - tmpfs tmpfs rw
";
        assert_eq!(
            atime_maintained_in(table, Path::new("/data/tmp/x")),
            Some(false)
        );
        assert_eq!(
            atime_maintained_in(table, Path::new("/dev/shm/x")),
            Some(true)
        );
        assert_eq!(atime_maintained_in(table, Path::new("/tmp/x")), Some(true));
        assert_eq!(
            atime_maintained_in(table, Path::new("/data/my dir/x")),
            Some(true)
        );
        assert_eq!(atime_maintained_in("", Path::new("/x")), None);
    }
}
