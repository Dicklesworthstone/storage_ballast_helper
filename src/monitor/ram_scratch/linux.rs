//! Linux collection is bounded and read-only; all thresholds live in assess().

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::platform::pal::Platform;

use super::{ProcessSwap, ScratchLimits, ScratchMount, ScratchReport, assess, invalid};

const MAX_STATUS_BYTES: u64 = 64 * 1024;

pub(super) fn inspect(platform: &dyn Platform, limits: ScratchLimits) -> io::Result<ScratchReport> {
    let deadline = Instant::now() + Duration::from_secs(limits.timeout_secs);
    let memory = platform
        .memory_info()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let listed = platform
        .mount_points()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut mounts = Vec::new();
    let mut issues = Vec::new();
    let mut considered = 0;
    for mount in listed {
        if !mount.fs_type.eq_ignore_ascii_case("tmpfs")
            && !mount.fs_type.eq_ignore_ascii_case("ramfs")
        {
            continue;
        }
        if considered >= limits.max_mounts || Instant::now() >= deadline {
            issues.push("tmpfs mount enumeration budget exhausted".into());
            break;
        }
        considered += 1;
        if mount.fs_type.eq_ignore_ascii_case("ramfs") {
            issues.push(format!(
                "{}: ramfs occupancy is not measurable with tmpfs block accounting",
                mount.path.display()
            ));
            continue;
        }
        let observed = (|| -> io::Result<ScratchMount> {
            let before = fs::metadata(&mount.path)?;
            let stats = platform
                .fs_stats(&mount.path)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let after = fs::metadata(&mount.path)?;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || !stats.fs_type.eq_ignore_ascii_case("tmpfs")
            {
                return Err(invalid("mount changed during inspection"));
            }
            let used_bytes = stats
                .total_bytes
                .checked_sub(stats.free_bytes)
                .ok_or_else(|| invalid("tmpfs free bytes exceed its size limit"))?;
            Ok(ScratchMount {
                path: mount.path.to_string_lossy().into_owned(),
                filesystem_id: before.dev(),
                total_bytes: stats.total_bytes,
                used_bytes,
                available_bytes: stats.available_bytes,
            })
        })();
        match observed {
            Ok(usage) => mounts.push(usage),
            Err(error) => issues.push(format!("{}: {error}", mount.path.display())),
        }
    }
    let process_swap =
        match collect_process_swap(Path::new("/proc"), limits.max_processes, deadline) {
            Ok(observation) => observation,
            Err(error) => {
                issues.push(format!("process swap collection failed: {error}"));
                ProcessSwap::default()
            }
        };
    if !process_swap.complete {
        issues.push(format!("process swap observation incomplete: {} statuses inspected, {} unreadable or malformed", process_swap.inspected, process_swap.unreadable));
    }
    let complete = issues.is_empty();
    let assessment = assess(memory, mounts, process_swap)?;
    let exit_code = if complete {
        i32::from(assessment.warning())
    } else {
        4
    };
    Ok(ScratchReport {
        schema: "sbh.ram_scratch.v1",
        read_only: true,
        supported: true,
        complete,
        scope: "visible mount and process namespaces; host meminfo; not cgroup headroom or swap attribution",
        assessment: Some(assessment),
        issues,
        exit_code,
    })
}

fn collect_process_swap(root: &Path, maximum: usize, deadline: Instant) -> io::Result<ProcessSwap> {
    let mut observation = ProcessSwap {
        complete: true,
        ..Default::default()
    };
    let mut attempted = 0;
    for entry in fs::read_dir(root)? {
        if Instant::now() >= deadline {
            observation.complete = false;
            break;
        }
        let Ok(entry) = entry else {
            observation.unreadable += 1;
            observation.complete = false;
            continue;
        };
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        if attempted >= maximum {
            observation.complete = false;
            break;
        }
        attempted += 1;
        let value = (|| -> io::Result<u64> {
            let mut text = String::new();
            File::open(entry.path().join("status"))?
                .take(MAX_STATUS_BYTES + 1)
                .read_to_string(&mut text)?;
            if text.len() as u64 > MAX_STATUS_BYTES {
                return Err(invalid("process status exceeds inspection budget"));
            }
            parse_vm_swap(&text)
        })();
        match value {
            Ok(bytes) => {
                observation.bytes = observation
                    .bytes
                    .checked_add(bytes)
                    .ok_or_else(|| invalid("process swap sum overflow"))?;
                observation.inspected += 1;
            }
            // A process may exit between enumeration and its status read.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                observation.unreadable += 1;
                observation.complete = false;
            }
        }
    }
    Ok(observation)
}

fn parse_vm_swap(status: &str) -> io::Result<u64> {
    let mut swap = None;
    let mut has_address_space = false;
    for line in status.lines() {
        has_address_space |= line.starts_with("VmSize:");
        if let Some(value) = line.strip_prefix("VmSwap:") {
            if swap.is_some() {
                return Err(invalid("duplicate process VmSwap counter"));
            }
            let mut words = value.split_whitespace();
            let kib = words
                .next()
                .and_then(|word| word.parse::<u64>().ok())
                .ok_or_else(|| invalid("invalid process VmSwap counter"))?;
            if words.next() != Some("kB") || words.next().is_some() {
                return Err(invalid("invalid process VmSwap units"));
            }
            swap = Some(
                kib.checked_mul(1024)
                    .ok_or_else(|| invalid("process VmSwap byte overflow"))?,
            );
        }
    }
    match swap {
        Some(value) => Ok(value),
        None if !has_address_space && status.lines().any(|line| line.starts_with("Name:")) => Ok(0),
        None => Err(invalid("process status lacks VmSwap evidence")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parser_distinguishes_zero_missing_malformed_and_overflow() {
        assert_eq!(
            parse_vm_swap("Name:\tbuild\nVmSize:\t10 kB\nVmSwap:\t4 kB\n").unwrap(),
            4096
        );
        assert_eq!(parse_vm_swap("Name:\tkworker\nState:\tS\n").unwrap(), 0);
        for text in [
            "",
            "Name:\tbuild\nVmSize:\t10 kB",
            "VmSwap: 1 MB",
            "VmSwap: -1 kB",
            "VmSwap: 18446744073709551615 kB",
            "VmSwap: 1 kB\nVmSwap: 1 kB",
            "VmSwap: 1 kB garbage",
        ] {
            assert!(parse_vm_swap(text).is_err(), "{text}");
        }
    }
}
