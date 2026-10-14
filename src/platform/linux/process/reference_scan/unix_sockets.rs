//! Coverage-aware parsing of Linux Unix-domain socket tables.
//!
//! A readable header-only table is empty evidence; a missing, malformed or
//! truncated table is not. Positive absolute paths survive malformed rows.
//! Relative bindings cannot be reconstructed from a process's *current* cwd
//! (a server may chdir after bind), so they name no path; they do not revoke
//! coverage either: Postfix binds every service socket relatively.
//! This module never opens a socket, follows a binding, or reads file payloads.

use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

pub(super) const HEADER: &[u8] = b"Num RefCount Protocol Flags Type St Inode Path\n";

#[derive(Debug, Default)]
pub(super) struct Table {
    pub(super) paths: HashMap<u64, PathBuf>,
    complete: bool,
}

impl Table {
    /// Only a validated, fully observed table can supply negative evidence.
    /// Row and clock limits bound parsing as well as the caller's bounded read.
    pub(super) fn parse(raw: &[u8], max_rows: usize, mut expired: impl FnMut() -> bool) -> Self {
        let mut lines = raw.split_inclusive(|byte| *byte == b'\n');
        let Some(header) = lines.next() else {
            return Self::default();
        };
        let mut table = Self {
            complete: header.ends_with(b"\n")
                && header
                    .split(u8::is_ascii_whitespace)
                    .filter(|word| !word.is_empty())
                    .eq(HEADER
                        .split(u8::is_ascii_whitespace)
                        .filter(|word| !word.is_empty())),
            ..Self::default()
        };
        let mut seen = HashSet::new();
        for (index, line) in lines.enumerate() {
            if index >= max_rows || expired() {
                table.complete = false;
                break;
            }
            let Some(line) = line.strip_suffix(b"\n") else {
                // The final path may itself be cut in half. Do not invent a
                // reference to that prefix, and never call this complete.
                table.complete = false;
                break;
            };
            let Some((inode, binding)) = row(line) else {
                table.complete = false;
                continue;
            };
            // Sockets without an associated file can legitimately report 0,
            // including several pending connections. No fd names socket:[0].
            if inode == 0 {
                continue;
            }
            if !seen.insert(inode) {
                table.complete = false;
            }
            // Only an absolute binding names a file. Linux prints abstract
            // names with '@', and unbound sockets have no path column. A
            // relative binding is relative to the binder's cwd at bind time,
            // which is not recorded anywhere; a server still working in that
            // directory holds it through its cwd (bd-d1kt). Revoking coverage
            // for it held every batch on any host running Postfix, whose
            // master binds `public/pickup`, `private/*` and the rest relative
            // to its queue directory (css, csd and yto, 2026-10-14).
            if let Some(bytes) = binding
                && bytes.first() == Some(&b'/')
            {
                table
                    .paths
                    .entry(inode)
                    .or_insert_with(|| PathBuf::from(std::ffi::OsStr::from_bytes(bytes)));
            }
        }
        if expired() {
            table.complete = false;
        }
        table
    }

    pub(super) fn complete_for(&self, _inode: u64) -> bool {
        self.complete
    }

    pub(super) fn path(&self, inode: u64) -> Option<&Path> {
        self.paths.get(&inode).map(PathBuf::as_path)
    }
}

fn row(mut rest: &[u8]) -> Option<(u64, Option<&[u8]>)> {
    // Numeric columns are space-padded. After the inode, consume exactly ONE
    // separator: spaces, tabs and arbitrary non-UTF-8 bytes belong to the name.
    let mut inode = 0;
    for index in 0..7 {
        let start = rest.iter().position(|byte| !byte.is_ascii_whitespace())?;
        rest = &rest[start..];
        let end = rest
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(rest.len());
        let token = &rest[..end];
        if index == 6 {
            inode = decimal(token)?;
        } else {
            let hex = if index == 0 {
                token.strip_suffix(b":")?
            } else {
                token
            };
            if hex.is_empty() || hex.len() > 16 || !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
        }
        rest = &rest[end..];
    }
    if rest.is_empty() {
        return Some((inode, None));
    }
    let path = rest.strip_prefix(b" ")?;
    if path.is_empty() || path.contains(&0) {
        return None;
    }
    Some((inode, Some(path)))
}

pub(super) fn decimal(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(raw).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(inode: u64, binding: Option<&[u8]>) -> Vec<u8> {
        let mut raw =
            format!("0000000000000000: 00000002 00000000 00010000 0001 01 {inode:7}").into_bytes();
        if let Some(path) = binding {
            raw.push(b' ');
            raw.extend_from_slice(path);
        }
        raw.push(b'\n');
        raw
    }

    fn parse(rows: &[Vec<u8>]) -> Table {
        let mut raw = HEADER.to_vec();
        for row in rows {
            raw.extend_from_slice(row);
        }
        Table::parse(&raw, 100, || false)
    }

    #[test]
    fn only_a_valid_header_can_establish_an_empty_table() {
        assert!(Table::parse(HEADER, 0, || false).complete_for(1));
        for raw in [b"".as_slice(), b"\n", b"Num RefCount", b"garbage\n"] {
            assert!(!Table::parse(raw, 100, || false).complete_for(1));
        }
        let table = Table::parse(
            b"Num\tRefCount Protocol Flags Type St Inode Path\n",
            100,
            || false,
        );
        assert!(table.complete_for(1));
    }

    #[test]
    fn absolute_bindings_keep_spaces_tabs_trailing_spaces_and_native_bytes() {
        let names: [&[u8]; 4] = [
            b"/tmp/socket with spaces",
            b"/tmp/socket\tname",
            b"/tmp/socket ",
            b"/tmp/socket-\xff",
        ];
        let rows: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(i, name)| line(i as u64 + 1, Some(name)))
            .collect();
        let table = parse(&rows);
        for (index, name) in names.iter().enumerate() {
            let inode = index as u64 + 1;
            assert!(table.complete_for(inode));
            assert_eq!(table.path(inode).unwrap().as_os_str().as_bytes(), *name);
        }
    }

    #[test]
    fn relative_bindings_name_no_path_and_keep_coverage() {
        // Postfix's master binds its services relative to the queue directory.
        let table = parse(&[
            line(1, Some(b"public/pickup")),
            line(2, Some(b"private/local")),
            line(3, Some(b"  leading-space.sock")),
            line(4, Some(b"/tmp/absolute")),
        ]);
        for inode in 1..=3 {
            assert!(table.complete_for(inode));
            assert!(table.path(inode).is_none());
        }
        assert!(table.complete_for(4));
        assert!(table.complete_for(99));
        assert_eq!(table.path(4), Some(Path::new("/tmp/absolute")));
    }

    #[test]
    fn abstract_and_unbound_sockets_do_not_invent_filesystem_paths() {
        let table = parse(&[line(1, Some(b"@abstract")), line(2, None)]);
        assert!(table.complete_for(1));
        assert!(table.complete_for(2));
        assert!(table.paths.is_empty());
        let table = parse(&[line(0, None), line(0, None), line(1, Some(b"/tmp/live"))]);
        assert!(table.complete_for(1), "fileless inode-zero rows may repeat");
    }

    #[test]
    fn malformed_rows_revoke_coverage_without_erasing_other_positive_paths() {
        for bad in [
            b"garbage\n".to_vec(),
            b"\n".to_vec(),
            b"0: 2 0 10000 1 1 +42 /tmp/malformed\n".to_vec(),
            b"0: 2 0 10000 1 1 18446744073709551616 /tmp/overflow\n".to_vec(),
            b"0: 2 0 G 1 1 42 /tmp/bad-flags\n".to_vec(),
            line(42, Some(b"/tmp/embedded\0nul")),
        ] {
            let table = parse(&[
                line(1, Some(b"/tmp/first")),
                bad,
                line(2, Some(b"/tmp/last")),
            ]);
            assert!(!table.complete_for(1));
            assert!(!table.complete_for(99));
            assert_eq!(table.path(1), Some(Path::new("/tmp/first")));
            assert_eq!(table.path(2), Some(Path::new("/tmp/last")));
        }
    }

    #[test]
    fn incomplete_final_rows_never_publish_a_truncated_path_prefix() {
        let row = line(2, Some(b"/tmp/second"));
        for length in 1..row.len() {
            let mut raw = HEADER.to_vec();
            raw.extend(line(1, Some(b"/tmp/first")));
            raw.extend_from_slice(&row[..length]);
            let table = Table::parse(&raw, 100, || false);
            assert!(!table.complete_for(1), "length={length}");
            assert_eq!(table.path(1), Some(Path::new("/tmp/first")));
            assert!(table.path(2).is_none());
        }
    }

    #[test]
    fn duplicate_inode_rows_are_not_an_atomic_negative_snapshot() {
        let table = parse(&[line(1, Some(b"/tmp/first")), line(1, Some(b"/tmp/reused"))]);
        assert!(!table.complete_for(99));
        assert_eq!(table.path(1), Some(Path::new("/tmp/first")));
    }

    #[test]
    fn row_budget_distinguishes_exact_completion_from_a_truncated_table() {
        let mut raw = HEADER.to_vec();
        raw.extend(line(1, Some(b"/tmp/first")));
        raw.extend(line(2, Some(b"/tmp/second")));
        for limit in 0..=3 {
            let table = Table::parse(&raw, limit, || false);
            assert_eq!(table.paths.len(), limit.min(2));
            assert_eq!(table.complete_for(99), limit >= 2);
        }
    }

    #[test]
    fn parsing_obeys_the_original_deadline_and_keeps_earlier_positives() {
        let mut raw = HEADER.to_vec();
        raw.extend(line(1, Some(b"/tmp/first")));
        raw.extend(line(2, Some(b"/tmp/second")));
        let mut checks = 0;
        let table = Table::parse(&raw, 100, || {
            checks += 1;
            checks >= 2
        });
        assert_eq!(table.paths.len(), 1);
        assert!(!table.complete_for(99));
    }
}
