//! Linux mount and filesystem helpers for the PAL.

#![allow(missing_docs)]

use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::MountPoint;

pub(super) fn read_mount_points() -> Result<Vec<MountPoint>> {
    let raw = fs::read_to_string("/proc/self/mounts").map_err(|source| SbhError::Io {
        path: PathBuf::from("/proc/self/mounts"),
        source,
    })?;
    Ok(parse_proc_mounts(&raw))
}

pub(super) fn parse_proc_mounts(raw: &str) -> Vec<MountPoint> {
    let mut mounts = Vec::new();
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            // Skip malformed lines rather than failing the entire mount parse.
            eprintln!("[sbh] warning: skipping malformed /proc/self/mounts line: {line}");
            continue;
        }
        let mount_path = unescape_mount_path(fields[1]);
        let fs_type = fields[2].to_string();
        mounts.push(MountPoint {
            path: mount_path,
            device: fields[0].to_string(),
            is_ram_backed: is_ram_fs(&fs_type),
            fs_type,
        });
    }
    mounts.sort_by(|left, right| {
        right
            .path
            .as_os_str()
            .len()
            .cmp(&left.path.as_os_str().len())
    });
    mounts
}

pub(super) fn find_mount<'a>(path: &Path, mounts: &'a [MountPoint]) -> Option<&'a MountPoint> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.path))
        .max_by_key(|mount| mount.path.as_os_str().len())
}

/// Whether a filesystem type name is RAM-backed (`tmpfs`, `ramfs`,
/// `devtmpfs`): space reclaimed there frees memory, not disk.
pub fn is_ram_fs(fs_type: &str) -> bool {
    matches!(
        fs_type.to_ascii_lowercase().as_str(),
        "tmpfs" | "ramfs" | "devtmpfs"
    )
}

#[cfg(test)]
fn unescape_mount_field(raw: &str) -> String {
    unescape_mount_path(raw).to_string_lossy().into_owned()
}

/// Decode octal escape sequences (`\NNN`) used by the Linux kernel.
fn unescape_mount_path(raw: &str) -> PathBuf {
    let mut bytes = Vec::with_capacity(raw.len());
    let raw_bytes = raw.as_bytes();
    let mut i = 0;
    while i < raw_bytes.len() {
        if raw_bytes[i] == b'\\' && i + 3 < raw_bytes.len() {
            let a = raw_bytes[i + 1];
            let b = raw_bytes[i + 2];
            let c = raw_bytes[i + 3];
            if (b'0'..=b'7').contains(&a)
                && (b'0'..=b'7').contains(&b)
                && (b'0'..=b'7').contains(&c)
            {
                let val = (a - b'0') * 64 + (b - b'0') * 8 + (c - b'0');
                bytes.push(val);
                i += 4;
                continue;
            }
        }
        bytes.push(raw_bytes[i]);
        i += 1;
    }

    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::platform::pal::MountPoint;

    use super::{
        find_mount, is_ram_fs, parse_proc_mounts, unescape_mount_field, unescape_mount_path,
    };

    #[test]
    fn parses_mount_table() {
        let sample = "/dev/sda1 / ext4 rw,relatime 0 0\n\
                      tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n";
        let mounts = parse_proc_mounts(sample);
        assert_eq!(mounts.len(), 2);
        assert!(mounts.iter().any(|entry| entry.path == Path::new("/tmp")));
        assert!(mounts.iter().any(|entry| entry.fs_type == "ext4"));
    }

    #[test]
    fn find_mount_prefers_longest_prefix() {
        let mounts = vec![
            MountPoint {
                path: "/".into(),
                device: "root".to_string(),
                fs_type: "ext4".to_string(),
                is_ram_backed: false,
            },
            MountPoint {
                path: "/tmp".into(),
                device: "tmpfs".to_string(),
                fs_type: "tmpfs".to_string(),
                is_ram_backed: true,
            },
        ];
        let mount = find_mount(Path::new("/tmp/work"), &mounts).expect("mount expected");
        assert_eq!(mount.path, Path::new("/tmp"));
    }

    #[test]
    fn ram_fs_detection_matches_expected_types() {
        assert!(is_ram_fs("tmpfs"));
        assert!(is_ram_fs("ramfs"));
        assert!(!is_ram_fs("ext4"));
    }

    #[test]
    fn unescape_mount_field_handles_all_octal_sequences() {
        // \040 = space, \011 = tab, \134 = backslash, \012 = newline.
        assert_eq!(unescape_mount_field("/mnt/my\\040dir"), "/mnt/my dir");
        assert_eq!(unescape_mount_field("/mnt/a\\011b"), "/mnt/a\tb");
        assert_eq!(unescape_mount_field("/mnt/a\\134b"), "/mnt/a\\b");
        assert_eq!(unescape_mount_field("/mnt/a\\012b"), "/mnt/a\nb");
        assert_eq!(unescape_mount_field("/mnt/simple"), "/mnt/simple");
        assert_eq!(
            unescape_mount_path("/mnt/a\\04").to_string_lossy(),
            "/mnt/a\\04"
        );
    }

    #[test]
    fn unescape_mount_path_handles_invalid_utf8() {
        use std::os::unix::ffi::OsStrExt;

        let raw = "/mnt/bad\\377byte";
        let path = unescape_mount_path(raw);
        let bytes = path.as_os_str().as_bytes();

        let expected = b"/mnt/bad\xffbyte";
        assert_eq!(bytes, expected);
        assert_eq!(path.to_string_lossy(), "/mnt/bad\u{FFFD}byte");
    }
}
