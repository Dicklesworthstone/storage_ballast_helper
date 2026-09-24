//! What is filling a mount sbh cannot reclaim.
//!
//! A pressured mount whose scans find nothing deletable used to go quiet: the
//! controller idled with `nothing_to_reclaim` and backed off, and the operator
//! learned nothing about why the disk was full (fleet audit 2026-09-24: hz1 at
//! 97% with 89 GB of project repos and 56 GB of home, css at 100% with 118 GB
//! of build caches outside its scan roots). This module names the largest
//! directories on such a mount so the warning says where the bytes are.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use crate::scanner::walker::{device_id, opaque_tree_probe};

/// Top-level directories whose children are reported instead of themselves
/// (`/home/ubuntu`, `/data/projects` say more than `/home` and `/data`).
const CONTAINERS: &[&str] = &["home", "data", "var", "srv", "opt", "Users", "root"];

/// Entries one directory's size probe may visit; a larger tree reports a
/// lower bound (`complete == false`).
pub const PROBE_BUDGET_ENTRIES: usize = 400_000;

/// Directories named in one report.
pub const REPORT_TOP: usize = 8;

/// One directory's measured size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumer {
    /// The directory measured.
    pub path: PathBuf,
    /// Allocated bytes (a lower bound when `complete` is false).
    pub bytes: u64,
    /// Whether the probe saw the whole tree within its budget.
    pub complete: bool,
}

/// The largest directories on `mount` (its own filesystem only), largest
/// first: the mount's top-level directories, with each conventional
/// container (`home`, `data`, ...) replaced by its children.
#[must_use]
pub fn top_consumers(mount: &Path, budget: usize, top: usize) -> Vec<Consumer> {
    let Ok(mount_meta) = fs::metadata(mount) else {
        return Vec::new();
    };
    let dev = device_id(&mount_meta);
    let mut dirs = Vec::new();
    for dir in same_device_subdirs(mount, dev) {
        let is_container = dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| CONTAINERS.contains(&name));
        if is_container {
            dirs.extend(same_device_subdirs(&dir, dev));
        } else {
            dirs.push(dir);
        }
    }
    let cancel = AtomicBool::new(false);
    let mut consumers: Vec<Consumer> = dirs
        .into_iter()
        .map(|path| {
            let probe = opaque_tree_probe(&path, false, dev, budget, &cancel);
            Consumer {
                path,
                bytes: probe.allocated_bytes,
                complete: !probe.truncated,
            }
        })
        .collect();
    consumers.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    consumers.truncate(top);
    consumers
}

fn same_device_subdirs(dir: &Path, dev: u64) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .metadata()
                .is_ok_and(|meta| meta.is_dir() && device_id(&meta) == dev)
        })
        .map(|entry| entry.path())
        .collect();
    dirs.sort();
    dirs
}

/// `/home/ubuntu 278.1 GiB, /data/projects >=235.0 GiB, ...` (`>=` marks a
/// lower bound).
#[must_use]
pub fn describe(consumers: &[Consumer]) -> String {
    let mut out = String::new();
    for (index, consumer) in consumers.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        #[allow(clippy::cast_precision_loss)]
        let gib = consumer.bytes as f64 / 1_073_741_824.0;
        let bound = if consumer.complete { "" } else { ">=" };
        let _ = write!(out, "{} {bound}{gib:.1} GiB", consumer.path.display());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn largest_directories_first_with_containers_expanded() {
        let mount = tempfile::tempdir().unwrap();
        let big = mount.path().join("home/alice/cache");
        let small = mount.path().join("tools");
        fs::create_dir_all(&big).unwrap();
        fs::create_dir_all(&small).unwrap();
        fs::write(big.join("blob"), vec![7u8; 2 * 1024 * 1024]).unwrap();
        fs::write(small.join("f"), vec![7u8; 64 * 1024]).unwrap();

        let consumers = top_consumers(mount.path(), PROBE_BUDGET_ENTRIES, REPORT_TOP);
        let paths: Vec<&Path> = consumers.iter().map(|c| c.path.as_path()).collect();
        // `home` is a container: its child is named, not `home` itself.
        assert_eq!(
            paths,
            vec![mount.path().join("home/alice").as_path(), small.as_path()]
        );
        assert!(consumers[0].bytes >= 2 * 1024 * 1024);
        assert!(consumers.iter().all(|c| c.complete));
    }

    #[test]
    fn budget_truncation_is_reported_as_a_lower_bound() {
        let mount = tempfile::tempdir().unwrap();
        let wide = mount.path().join("wide");
        fs::create_dir_all(&wide).unwrap();
        for index in 0..20 {
            fs::write(wide.join(format!("f{index}")), b"x").unwrap();
        }
        let consumers = top_consumers(mount.path(), 5, REPORT_TOP);
        assert_eq!(consumers.len(), 1);
        assert!(!consumers[0].complete);
        assert!(describe(&consumers).contains(">="));
    }
}
