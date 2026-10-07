//! Linux mount and filesystem helpers for the PAL.

#![allow(missing_docs)]

use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::MountPoint;

pub(super) fn read_mount_points() -> Result<Vec<MountPoint>> {
    // procfs escapes field delimiters, not arbitrary non-UTF-8 pathname bytes.
    // One byte-named mount must not disable pressure readings for every disk.
    let raw = fs::read("/proc/self/mounts").map_err(|source| SbhError::Io {
        path: PathBuf::from("/proc/self/mounts"),
        source,
    })?;
    parse_proc_mounts(&raw)
}

pub(super) fn parse_proc_mounts(raw: &[u8]) -> Result<Vec<MountPoint>> {
    let mut mounts = Vec::new();
    for (line_number, line) in raw.split(|byte| *byte == b'\n').enumerate() {
        // Unicode whitespace and unescaped CR/VT/FF can be literal pathname
        // bytes. Only the actual procfs field separators delimit these rows.
        let mut fields = line
            .split(|byte| matches!(byte, b' ' | b'\t'))
            .filter(|field| !field.is_empty());
        let Some(device) = fields.next() else {
            continue;
        };
        let malformed = || SbhError::MountParse {
            // Do not echo mount options, which can contain credentials.
            details: format!("invalid /proc/self/mounts record at line {}", line_number + 1),
        };
        let (Some(path), Some(kind), Some(_options), Some(dump), Some(pass)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(malformed());
        };
        if fields.next().is_some()
            || line.contains(&0)
            || !dump.iter().all(u8::is_ascii_digit)
            || !pass.iter().all(u8::is_ascii_digit)
        {
            return Err(malformed());
        }
        let mount_path = unescape_mount_path(path);
        if !mount_path.is_absolute() || mount_path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(malformed());
        }
        let fs_type = mount_label(kind);
        mounts.push(MountPoint {
            path: mount_path,
            device: mount_label(device),
            is_ram_backed: is_ram_fs(&fs_type),
            fs_type,
        });
    }
    // Dropping a malformed child mount and retaining its parent can attribute
    // pressure to the wrong disk. This API has no partial-coverage flag, so a
    // malformed or empty table must be an error rather than a successful subset.
    if mounts.is_empty() {
        return Err(SbhError::MountParse {
            details: "/proc/self/mounts contained no mount records".to_string(),
        });
    }
    mounts.sort_by(|left, right| {
        right
            .path
            .as_os_str()
            .len()
            .cmp(&left.path.as_os_str().len())
    });
    Ok(mounts)
}

/// Keep the existing procfs spelling of textual labels. Non-UTF-8 labels
/// use octal bytes rather than replacement characters that merge identities.
/// Kernel-escaped literal backslashes remain escaped, so a literal `\377`
/// (spelled `\134377` by procfs) differs from the encoded non-UTF-8 byte.
fn mount_label(raw: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(raw) {
        return text.to_string();
    }
    let mut text = String::new();
    for &byte in raw {
        if byte.is_ascii() {
            text.push(char::from(byte));
        } else {
            text.push('\\');
            text.push(char::from(b'0' + (byte >> 6)));
            text.push(char::from(b'0' + ((byte >> 3) & 7)));
            text.push(char::from(b'0' + (byte & 7)));
        }
    }
    text
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
fn unescape_mount_path(raw: impl AsRef<[u8]>) -> PathBuf {
    let raw_bytes = raw.as_ref();
    let mut bytes = Vec::with_capacity(raw_bytes.len());
    let mut i = 0;
    while i < raw_bytes.len() {
        if raw_bytes[i] == b'\\' && i + 3 < raw_bytes.len() {
            let a = raw_bytes[i + 1];
            let b = raw_bytes[i + 2];
            let c = raw_bytes[i + 3];
            if (b'0'..=b'3').contains(&a)
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
        let mounts = parse_proc_mounts(sample.as_bytes()).unwrap();
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

    #[test]
    fn byte_named_mount_does_not_erase_other_filesystems() {
        use std::os::unix::ffi::OsStrExt;

        let raw = b"rootfs / ext4 rw 0 0\ntmpfs /mnt/raw\xff tmpfs rw 0 0\n\
                    disk /mnt/escaped\\376 xfs rw 0 0\n";
        let mounts = parse_proc_mounts(raw).unwrap();
        assert_eq!(mounts.len(), 3);
        let raw_path = Path::new(std::ffi::OsStr::from_bytes(b"/mnt/raw\xff/work"));
        let mount = find_mount(raw_path, &mounts).unwrap();
        assert_eq!(mount.path.as_os_str().as_bytes(), b"/mnt/raw\xff");
        assert!(mount.is_ram_backed);
        assert_eq!(
            find_mount(Path::new("/ordinary"), &mounts).unwrap().fs_type,
            "ext4"
        );
        assert!(
            mounts.iter().any(|mount| mount.path.as_os_str().as_bytes() == b"/mnt/escaped\xfe")
        );
    }

    #[test]
    fn nondelimiter_whitespace_is_part_of_the_mount_path() {
        for separator in ["\u{a0}", "\u{2003}", "\u{2028}", "\r", "\u{b}", "\u{c}"] {
            let path = format!("/mnt/a{separator}b");
            let raw = format!("device {path} tmpfs rw 0 0\n");
            let mounts = parse_proc_mounts(raw.as_bytes()).unwrap();
            assert_eq!(mounts.len(), 1);
            assert_eq!(mounts[0].path, Path::new(&path));
            assert_eq!(mounts[0].fs_type, "tmpfs");
            assert!(mounts[0].is_ram_backed);
        }
    }

    #[test]
    fn delimiter_escapes_are_decoded_once_without_aliasing_literal_escapes() {
        let mounts = parse_proc_mounts(
            b"disk /mnt/a\\040b ext4 rw 0 0\ndisk /mnt/a\\134040b xfs rw 0 0\n\
              tmpfs /mnt/tab\\011newline\\012slash\\134 tmpfs rw 0 0\n",
        )
        .unwrap();
        assert_eq!(mounts.len(), 3);
        assert_eq!(
            find_mount(Path::new("/mnt/a b/child"), &mounts).unwrap().fs_type,
            "ext4"
        );
        assert_eq!(
            find_mount(Path::new("/mnt/a\\040b/child"), &mounts).unwrap().fs_type,
            "xfs"
        );
        assert!(
            mounts.iter().any(|mount| mount.path == Path::new("/mnt/tab\tnewline\nslash\\"))
        );
    }

    #[test]
    fn non_utf8_labels_and_options_do_not_disable_discovery() {
        let mounts = parse_proc_mounts(
            b"disk\xff /one ext4 rw,label=\xfe 0 0\ndisk\xfe /two xfs rw 0 0\n\
              disk\\134377 /three fuse.\xff rw 0 0\n",
        )
        .unwrap();
        let one = find_mount(Path::new("/one"), &mounts).unwrap();
        let two = find_mount(Path::new("/two"), &mounts).unwrap();
        let three = find_mount(Path::new("/three"), &mounts).unwrap();
        assert_eq!(one.device, "disk\\377");
        assert_eq!(two.device, "disk\\376");
        assert_eq!(three.device, "disk\\134377");
        assert_eq!(three.fs_type, "fuse.\\377");
        assert!(!three.is_ram_backed);
    }

    #[test]
    fn malformed_child_mount_is_not_silently_replaced_by_parent_coverage() {
        let error = parse_proc_mounts(
            b"rootfs / ext4 rw 0 0\ndisk /data xfs\ntmpfs /tmp tmpfs rw 0 0\n",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            crate::core::errors::SbhError::MountParse { .. }
        ));
        assert!(error.to_string().contains("line 2"));
    }

    #[test]
    fn empty_relative_nul_and_incomplete_records_are_rejected() {
        for raw in [
            b"".as_slice(),
            b" \t\n",
            b"disk relative ext4 rw 0 0\n",
            b"disk /nul\0 ext4 rw 0 0\n",
            b"disk /nul\\000 ext4 rw 0 0\n",
            b"disk / ext4 rw 0\n",
            b"disk / ext4 rw x 0\n",
            b"disk / ext4 rw 0 0 extra\n",
        ] {
            assert!(
                parse_proc_mounts(raw).is_err(),
                "accepted malformed row: {raw:?}"
            );
        }
        assert!(parse_proc_mounts(b"disk\t/\text4\trw\t0\t0").is_ok());
    }

    #[test]
    fn octal_decoding_is_total_and_does_not_wrap_values_above_a_byte() {
        use std::os::unix::ffi::OsStrExt;

        for byte in 0..=u8::MAX {
            let raw = format!("/mnt/x\\{byte:03o}y");
            let path = unescape_mount_path(raw);
            assert_eq!(
                path.as_os_str().as_bytes(),
                [b"/mnt/x".as_slice(), &[byte], b"y"].concat()
            );
        }
        for raw in ["/mnt/\\400", "/mnt/\\777", "/mnt/\\04", "/mnt/\\xyz"] {
            assert_eq!(unescape_mount_path(raw), Path::new(raw));
        }
    }

    #[test]
    fn native_mount_snapshot_remains_usable() {
        let mounts = super::read_mount_points().unwrap();
        assert!(!mounts.is_empty());
        assert!(mounts.iter().all(|mount| mount.path.is_absolute()));
        let cwd = std::fs::canonicalize(".").unwrap();
        assert!(find_mount(&cwd, &mounts).is_some());
    }
}
