//! One metadata walk of a protected tree, aggregated per candidate unit.
//!
//! The walk opens no file contents and follows no symlinks. It records, for
//! the marked tree and for every directory up to `unit_depth` below it, the
//! newest change (max of mtime and ctime over every entry), the newest
//! regular-file atime, and the allocated bytes. A directory on another
//! device is not entered; its units are flagged instead.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Serialize;

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

fn change_time(meta: &fs::Metadata) -> i64 {
    meta.mtime().max(meta.ctime())
}

fn new_unit(path: PathBuf, depth: usize, meta: &fs::Metadata) -> UnitStats {
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
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o7777,
    }
}

/// Walk `root` and aggregate per unit. `max_entries` bounds the whole walk.
pub fn survey_tree(root: &Path, unit_depth: usize, max_entries: u64) -> io::Result<TreeSurvey> {
    let root_meta = fs::symlink_metadata(root)?;
    if !root_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", root.display()),
        ));
    }
    let device = root_meta.dev();
    let mut survey = TreeSurvey {
        units: vec![new_unit(root.to_path_buf(), 0, &root_meta)],
        truncated: false,
        entries: 0,
    };
    // (directory, depth below root, indices of the units enclosing it)
    let mut stack: Vec<(PathBuf, usize, Vec<usize>)> = vec![(root.to_path_buf(), 0, vec![0])];
    while let Some((dir, depth, chain)) = stack.pop() {
        let Ok(reader) = fs::read_dir(&dir) else {
            for &unit in &chain {
                survey.units[unit].unreadable = true;
            }
            continue;
        };
        for entry in reader {
            survey.entries += 1;
            if survey.entries > max_entries {
                survey.truncated = true;
                return Ok(survey);
            }
            // `DirEntry::metadata` is an lstat: symlinks are never followed.
            let Ok(meta) = entry.and_then(|entry| entry.metadata().map(|meta| (entry, meta)))
            else {
                for &unit in &chain {
                    survey.units[unit].unreadable = true;
                }
                continue;
            };
            let (entry, meta) = meta;
            let changed = change_time(&meta);
            let regular = meta.file_type().is_file();
            let accessed = meta.atime();
            let counted_bytes = if meta.is_dir() {
                0
            } else {
                meta.blocks() * 512
            };
            for &unit in &chain {
                let stats = &mut survey.units[unit];
                stats.entries += 1;
                stats.bytes += counted_bytes;
                stats.newest_change = stats.newest_change.max(changed);
                stats.newest_change_below = stats.newest_change_below.max(changed);
                if regular {
                    stats.files += 1;
                    stats.newest_access =
                        Some(stats.newest_access.map_or(accessed, |a| a.max(accessed)));
                }
            }
            if !meta.is_dir() {
                continue;
            }
            if meta.dev() != device {
                for &unit in &chain {
                    survey.units[unit].crosses_mount = true;
                }
                continue;
            }
            let path = entry.path();
            let mut child_chain = chain.clone();
            if depth < unit_depth {
                survey.units.push(new_unit(path.clone(), depth + 1, &meta));
                child_chain.push(survey.units.len() - 1);
            }
            stack.push((path, depth + 1, child_chain));
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
