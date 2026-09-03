//! Linux process readers for future PAL process methods.

#![allow(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::core::errors::{Result, SbhError};
use crate::core::paths::resolve_absolute_path;
use crate::platform::types::{
    ExecutablesResult, MappedRegion, OPEN_FILES_MAX_PIDS, OPEN_FILES_SCAN_BUDGET, OpenFile,
    OpenFileKind, OpenFileMode, OpenFilesResult, PalError, ProcessInfo, ProcessIo, SelfStats,
};

const PROC_SELF_STATUS: &str = "/proc/self/status";
const PROC_SELF_STAT: &str = "/proc/self/stat";
const PROC_SELF_IO: &str = "/proc/self/io";
const PROC_ROOT: &str = "/proc";
const PROC_STAT: &str = "/proc/stat";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusMemory {
    rss_bytes: u64,
    virtual_memory_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    user_micros: u64,
    system_micros: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IoCounters {
    bytes_read: u64,
    bytes_written: u64,
}

pub(super) fn read_process_list() -> Result<Vec<ProcessInfo>> {
    let current_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    let boot_time_unix_ms = read_proc_file(PROC_STAT)
        .ok()
        .and_then(|raw| parse_proc_boot_time_unix_ms(&raw).ok());
    let mut processes = Vec::new();

    for pid in proc_pids()? {
        if pid <= 0 || pid == current_pid {
            continue;
        }
        if let Some(process) = process_info_for_pid(pid, boot_time_unix_ms) {
            processes.push(process);
        }
    }

    processes.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(processes)
}

pub(super) fn read_open_files_under(root: &Path) -> Result<OpenFilesResult> {
    let root = resolve_absolute_path(root);
    let mut open_files = Vec::new();
    let deadline = Instant::now() + OPEN_FILES_SCAN_BUDGET;
    let mut pids_scanned: usize = 0;
    let mut incomplete = false;

    for pid in proc_pids()? {
        if pids_scanned >= OPEN_FILES_MAX_PIDS || Instant::now() >= deadline {
            incomplete = true;
            break;
        }
        if pid > 0 {
            pids_scanned += 1;
            open_files.extend(open_files_for_pid_under(pid, &root));
        }
    }
    open_files.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.fd.cmp(&right.fd))
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(OpenFilesResult {
        files: open_files,
        complete: !incomplete,
    })
}

pub(super) fn read_executables_under(root: &Path) -> Result<ExecutablesResult> {
    let root = resolve_absolute_path(root);
    let boot_time_unix_ms = read_proc_file(PROC_STAT)
        .ok()
        .and_then(|raw| parse_proc_boot_time_unix_ms(&raw).ok());
    let mut processes = Vec::new();
    let deadline = Instant::now() + OPEN_FILES_SCAN_BUDGET;
    let mut pids_scanned: usize = 0;
    let mut incomplete = false;

    for pid in proc_pids()? {
        if pids_scanned >= OPEN_FILES_MAX_PIDS || Instant::now() >= deadline {
            incomplete = true;
            break;
        }
        if pid > 0 {
            pids_scanned += 1;
            if let Some(process) = process_info_for_pid(pid, boot_time_unix_ms)
                && process
                    .executable
                    .as_deref()
                    .is_some_and(|executable| resolve_absolute_path(executable).starts_with(&root))
            {
                processes.push(process);
            }
        }
    }
    processes.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(ExecutablesResult {
        processes,
        complete: !incomplete,
    })
}

pub(super) fn read_mmap_regions_under(root: &Path) -> Result<Vec<MappedRegion>> {
    let root = resolve_absolute_path(root);
    let mut regions = Vec::new();
    for pid in proc_pids()? {
        if pid > 0 {
            regions.extend(mapped_regions_for_pid_under(pid, &root));
        }
    }
    regions.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.start_address.cmp(&right.start_address))
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(regions)
}

pub(super) fn read_process_io(pid: i32) -> Result<ProcessIo> {
    let path = pid_proc_path(pid).join("io");
    let raw = fs::read_to_string(&path).map_err(|source| SbhError::Io {
        path: path.clone(),
        source,
    })?;
    let counters = parse_proc_io(&raw, "process_io")?;
    Ok(ProcessIo {
        pid,
        bytes_read_total: counters.bytes_read,
        bytes_written_total: counters.bytes_written,
        bytes_read_recent_15m: None,
        bytes_written_recent_15m: None,
    })
}

pub(super) fn read_self_stats() -> Result<SelfStats> {
    let status = read_proc_file(PROC_SELF_STATUS)?;
    let stat = read_proc_file(PROC_SELF_STAT)?;
    let memory = parse_proc_self_status(&status)?;
    let cpu = parse_proc_self_stat(&stat, clock_ticks_per_second())?;
    let io = read_proc_file(PROC_SELF_IO)
        .and_then(|raw| parse_proc_io(&raw, "self_stats"))
        .ok();

    Ok(SelfStats {
        rss_bytes: memory.rss_bytes,
        virtual_memory_bytes: memory.virtual_memory_bytes,
        cpu_user_micros: cpu.user_micros,
        cpu_system_micros: cpu.system_micros,
        idle_wakeups: None,
        bytes_read: io.map(|counters| counters.bytes_read),
        bytes_written: io.map(|counters| counters.bytes_written),
    })
}

fn read_proc_file(path: &str) -> Result<String> {
    fs::read_to_string(path).map_err(|source| SbhError::Io {
        path: PathBuf::from(path),
        source,
    })
}

fn proc_pids() -> Result<Vec<i32>> {
    let proc_dir = fs::read_dir(PROC_ROOT).map_err(|source| SbhError::Io {
        path: PathBuf::from(PROC_ROOT),
        source,
    })?;
    Ok(proc_dir
        .filter_map(|entry| {
            let entry = entry.ok()?;
            pid_from_proc_entry_name(&entry.file_name().to_string_lossy())
        })
        .collect())
}

fn pid_from_proc_entry_name(name: &str) -> Option<i32> {
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    name.parse::<i32>().ok()
}

fn pid_proc_path(pid: i32) -> PathBuf {
    PathBuf::from(PROC_ROOT).join(pid.to_string())
}

fn process_info_for_pid(pid: i32, boot_time_unix_ms: Option<i64>) -> Option<ProcessInfo> {
    let proc_path = pid_proc_path(pid);
    let name = fs::read_to_string(proc_path.join("comm"))
        .ok()?
        .trim()
        .to_string();
    if name.is_empty() {
        return None;
    }

    let status = fs::read_to_string(proc_path.join("status")).ok();
    let stat = fs::read_to_string(proc_path.join("stat")).ok();
    let ticks_per_second = clock_ticks_per_second();
    let cpu = stat
        .as_deref()
        .and_then(|raw| parse_proc_self_stat(raw, ticks_per_second).ok());

    Some(ProcessInfo {
        pid,
        parent_pid: status
            .as_deref()
            .and_then(|raw| parse_status_i32_field(raw, "PPid")),
        name,
        command_line: read_command_line(&proc_path),
        executable: fs::read_link(proc_path.join("exe")).ok(),
        cwd: fs::read_link(proc_path.join("cwd")).ok(),
        start_time_unix_ms: stat
            .as_deref()
            .zip(boot_time_unix_ms)
            .and_then(|(raw, boot_time)| {
                parse_proc_start_time_unix_ms(raw, boot_time, ticks_per_second).ok()
            }),
        virtual_memory_bytes: status
            .as_deref()
            .and_then(|raw| parse_status_kib_field_from_raw(raw, "VmSize")),
        resident_memory_bytes: status
            .as_deref()
            .and_then(|raw| parse_status_kib_field_from_raw(raw, "VmRSS")),
        cpu_user_micros: cpu.map(|times| times.user_micros),
        cpu_system_micros: cpu.map(|times| times.system_micros),
    })
}

fn read_command_line(proc_path: &std::path::Path) -> Vec<String> {
    let Ok(raw) = fs::read(proc_path.join("cmdline")) else {
        return Vec::new();
    };
    raw.split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

fn open_files_for_pid_under(pid: i32, root: &Path) -> Vec<OpenFile> {
    let proc_path = pid_proc_path(pid);
    let fd_dir = proc_path.join("fd");
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return Vec::new();
    };

    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let fd_path = entry.path();
            open_file_for_fd_under(pid, &proc_path, &fd_path, root)
        })
        .collect()
}

fn open_file_for_fd_under(
    pid: i32,
    proc_path: &Path,
    fd_path: &Path,
    root: &Path,
) -> Option<OpenFile> {
    let fd = fd_path
        .file_name()
        .and_then(|name| name.to_str())?
        .parse::<i32>()
        .ok()?;
    let path = resolve_absolute_path(&fs::read_link(fd_path).ok()?);
    if !path.starts_with(root) {
        return None;
    }
    Some(OpenFile {
        pid,
        path,
        fd: Some(fd),
        kind: open_file_kind_for_fd(fd_path),
        mode: open_file_mode_for_fd(proc_path, fd),
    })
}

fn open_file_kind_for_fd(fd_path: &Path) -> OpenFileKind {
    use std::os::unix::fs::FileTypeExt;

    let Ok(metadata) = fs::metadata(fd_path) else {
        return OpenFileKind::Unknown;
    };
    let file_type = metadata.file_type();
    if file_type.is_file() {
        OpenFileKind::Regular
    } else if file_type.is_dir() {
        OpenFileKind::Directory
    } else if file_type.is_socket() {
        OpenFileKind::Socket
    } else if file_type.is_fifo() {
        OpenFileKind::Pipe
    } else if file_type.is_char_device() || file_type.is_block_device() {
        OpenFileKind::Device
    } else {
        OpenFileKind::Unknown
    }
}

fn open_file_mode_for_fd(proc_path: &Path, fd: i32) -> OpenFileMode {
    let fdinfo = proc_path.join("fdinfo").join(fd.to_string());
    let Some(flags) = fs::read_to_string(fdinfo)
        .ok()
        .and_then(|raw| parse_fdinfo_flags(&raw))
    else {
        return OpenFileMode::Unknown;
    };

    if flags & u64::try_from(libc::O_PATH).unwrap_or(0) != 0 {
        return OpenFileMode::Unknown;
    }

    match flags & u64::try_from(libc::O_ACCMODE).unwrap_or(0) {
        value if value == u64::try_from(libc::O_WRONLY).unwrap_or(u64::MAX) => OpenFileMode::Write,
        value if value == u64::try_from(libc::O_RDWR).unwrap_or(u64::MAX) => {
            OpenFileMode::ReadWrite
        }
        _ => OpenFileMode::Read,
    }
}

fn parse_fdinfo_flags(raw: &str) -> Option<u64> {
    raw.lines().find_map(|line| {
        let value = line.strip_prefix("flags:")?.trim();
        u64::from_str_radix(value, 8)
            .ok()
            .or_else(|| value.parse::<u64>().ok())
    })
}

fn mapped_regions_for_pid_under(pid: i32, root: &Path) -> Vec<MappedRegion> {
    let maps_path = pid_proc_path(pid).join("maps");
    let Ok(raw) = fs::read_to_string(maps_path) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|line| mapped_region_from_maps_line(pid, line, root))
        .collect()
}

fn mapped_region_from_maps_line(pid: i32, line: &str, root: &Path) -> Option<MappedRegion> {
    let (range, rest) = take_whitespace_field(line)?;
    let (perms, rest) = take_whitespace_field(rest)?;
    let (_, rest) = take_whitespace_field(rest)?;
    let (_, rest) = take_whitespace_field(rest)?;
    let (_, rest) = take_whitespace_field(rest)?;
    let raw_path = rest.trim_start();
    if raw_path.is_empty() || raw_path.starts_with('[') {
        return None;
    }
    let (start, end) = parse_maps_address_range(range)?;
    let path = resolve_absolute_path(Path::new(raw_path));
    if !path.starts_with(root) {
        return None;
    }
    Some(MappedRegion {
        pid,
        path,
        start_address: Some(start),
        end_address: Some(end),
        protection: Some(maps_protection(perms)),
    })
}

fn take_whitespace_field(input: &str) -> Option<(&str, &str)> {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    Some((&trimmed[..end], &trimmed[end..]))
}

fn parse_maps_address_range(range: &str) -> Option<(u64, u64)> {
    let (start, end) = range.split_once('-')?;
    Some((
        u64::from_str_radix(start, 16).ok()?,
        u64::from_str_radix(end, 16).ok()?,
    ))
}

fn maps_protection(perms: &str) -> String {
    let mut protection = perms.chars().take(3).collect::<String>();
    while protection.len() < 3 {
        protection.push('-');
    }
    protection
}

fn parse_status_i32_field(raw: &str, key: &'static str) -> Option<i32> {
    raw.lines().find_map(|line| {
        let rest = line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(':'))?;
        rest.split_whitespace().next()?.parse::<i32>().ok()
    })
}

fn parse_status_kib_field_from_raw(raw: &str, key: &'static str) -> Option<u64> {
    raw.lines()
        .find_map(|line| parse_status_kib_field(line, key).ok().flatten())
}

fn parse_proc_boot_time_unix_ms(raw: &str) -> Result<i64> {
    let boot_seconds = raw
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .ok_or_else(|| process_parse_error("process_list", "missing btime in /proc/stat"))?
        .trim()
        .parse::<i64>()
        .map_err(|error| {
            process_parse_error("process_list", format!("invalid btime value: {error}"))
        })?;
    Ok(boot_seconds.saturating_mul(1_000))
}

fn parse_proc_self_status(raw: &str) -> Result<StatusMemory> {
    let mut rss_bytes = None;
    let mut virtual_memory_bytes = None;

    for line in raw.lines() {
        if let Some(value) = parse_status_kib_field(line, "VmRSS")? {
            rss_bytes = Some(value);
        } else if let Some(value) = parse_status_kib_field(line, "VmSize")? {
            virtual_memory_bytes = Some(value);
        }
    }

    Ok(StatusMemory {
        rss_bytes: required_counter(rss_bytes, "VmRSS")?,
        virtual_memory_bytes: required_counter(virtual_memory_bytes, "VmSize")?,
    })
}

fn parse_status_kib_field(line: &str, key: &'static str) -> Result<Option<u64>> {
    let Some(rest) = line
        .strip_prefix(key)
        .and_then(|rest| rest.strip_prefix(':'))
    else {
        return Ok(None);
    };
    let mut parts = rest.split_whitespace();
    let raw_value = parts
        .next()
        .ok_or_else(|| self_stats_parse_error(format!("missing value for {key}")))?;
    let value = raw_value.parse::<u64>().map_err(|error| {
        self_stats_parse_error(format!("invalid numeric value for {key}: {error}"))
    })?;
    let bytes = match parts.next() {
        Some("kB") => value.saturating_mul(1024),
        None => value,
        Some(unit) => {
            return Err(self_stats_parse_error(format!(
                "unsupported unit for {key}: {unit}"
            )));
        }
    };
    Ok(Some(bytes))
}

fn parse_proc_self_stat(raw: &str, ticks_per_second: u64) -> Result<CpuTimes> {
    let fields = proc_stat_fields_after_comm(raw)?;
    let user_ticks = parse_stat_tick_field(&fields, 11, "utime")?;
    let system_ticks = parse_stat_tick_field(&fields, 12, "stime")?;

    Ok(CpuTimes {
        user_micros: ticks_to_micros(user_ticks, ticks_per_second),
        system_micros: ticks_to_micros(system_ticks, ticks_per_second),
    })
}

fn parse_proc_start_time_unix_ms(
    raw: &str,
    boot_time_unix_ms: i64,
    ticks_per_second: u64,
) -> Result<i64> {
    let fields = proc_stat_fields_after_comm(raw)?;
    let start_ticks = parse_stat_tick_field(&fields, 19, "starttime")?;
    Ok(boot_time_unix_ms.saturating_add(ticks_to_millis(start_ticks, ticks_per_second)))
}

fn proc_stat_fields_after_comm(raw: &str) -> Result<Vec<&str>> {
    let Some((_, rest)) = raw.rsplit_once(") ") else {
        return Err(self_stats_parse_error(
            "invalid /proc/self/stat format: missing command terminator",
        ));
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() <= 12 {
        return Err(self_stats_parse_error(format!(
            "invalid /proc/self/stat format: expected at least 13 fields after command, got {}",
            fields.len()
        )));
    }
    Ok(fields)
}

fn parse_stat_tick_field(fields: &[&str], index: usize, name: &'static str) -> Result<u64> {
    fields
        .get(index)
        .ok_or_else(|| self_stats_parse_error(format!("missing {name} field")))?
        .parse::<u64>()
        .map_err(|error| self_stats_parse_error(format!("invalid {name} value: {error}")))
}

fn parse_proc_io(raw: &str, method: &'static str) -> Result<IoCounters> {
    let mut bytes_read = None;
    let mut bytes_written = None;

    for line in raw.lines() {
        if let Some(value) = parse_io_field(line, "read_bytes", method)? {
            bytes_read = Some(value);
        } else if let Some(value) = parse_io_field(line, "write_bytes", method)? {
            bytes_written = Some(value);
        }
    }

    Ok(IoCounters {
        bytes_read: required_method_counter(bytes_read, "read_bytes", method)?,
        bytes_written: required_method_counter(bytes_written, "write_bytes", method)?,
    })
}

fn parse_io_field(line: &str, key: &'static str, method: &'static str) -> Result<Option<u64>> {
    let Some(rest) = line
        .strip_prefix(key)
        .and_then(|rest| rest.strip_prefix(':'))
    else {
        return Ok(None);
    };
    rest.trim()
        .parse::<u64>()
        .map(Some)
        .map_err(|error| process_parse_error(method, format!("invalid {key} value: {error}")))
}

fn required_counter(value: Option<u64>, field: &'static str) -> Result<u64> {
    value.ok_or_else(|| self_stats_parse_error(format!("missing required field: {field}")))
}

fn required_method_counter(
    value: Option<u64>,
    field: &'static str,
    method: &'static str,
) -> Result<u64> {
    value.ok_or_else(|| process_parse_error(method, format!("missing required field: {field}")))
}

fn clock_ticks_per_second() -> u64 {
    nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .ok()
        .flatten()
        .and_then(|ticks| u64::try_from(ticks).ok())
        .filter(|ticks| *ticks > 0)
        .unwrap_or(100)
}

fn ticks_to_micros(ticks: u64, ticks_per_second: u64) -> u64 {
    ticks
        .saturating_mul(1_000_000)
        .checked_div(ticks_per_second)
        .unwrap_or(0)
}

fn ticks_to_millis(ticks: u64, ticks_per_second: u64) -> i64 {
    let millis = ticks
        .saturating_mul(1_000)
        .checked_div(ticks_per_second)
        .unwrap_or(0);
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn self_stats_parse_error(details: impl Into<String>) -> SbhError {
    process_parse_error("self_stats", details)
}

fn process_parse_error(method: &'static str, details: impl Into<String>) -> SbhError {
    PalError::method_failed("linux", method, details.into()).into()
}

#[cfg(test)]
mod tests {
    use super::{
        mapped_region_from_maps_line, parse_fdinfo_flags, parse_proc_boot_time_unix_ms,
        parse_proc_io, parse_proc_self_stat, parse_proc_self_status, parse_proc_start_time_unix_ms,
        read_executables_under, read_mmap_regions_under, read_open_files_under, read_process_io,
        read_process_list, read_self_stats, ticks_to_micros,
    };
    use crate::core::paths::resolve_absolute_path;
    use crate::platform::types::{OpenFileKind, OpenFileMode};

    #[test]
    fn parses_proc_status_memory_fields() {
        let memory = parse_proc_self_status(
            "Name:\tsbh\n\
             VmPeak:\t  999999 kB\n\
             VmSize:\t  123456 kB\n\
             VmRSS:\t    7890 kB\n",
        )
        .expect("status should parse");

        assert_eq!(memory.virtual_memory_bytes, 123_456 * 1024);
        assert_eq!(memory.rss_bytes, 7_890 * 1024);
    }

    #[test]
    fn parses_proc_stat_cpu_times_with_spaces_in_command() {
        let cpu = parse_proc_self_stat(
            "12345 (sbh worker thread) S 1 2 3 4 5 6 7 8 9 10 345 67 0 0 20 0 1 0 0",
            100,
        )
        .expect("stat should parse");

        assert_eq!(cpu.user_micros, 3_450_000);
        assert_eq!(cpu.system_micros, 670_000);
    }

    #[test]
    fn parses_proc_stat_process_start_time() {
        let start_time = parse_proc_start_time_unix_ms(
            "12345 (sbh worker thread) S 1 2 3 4 5 6 7 8 9 10 345 67 0 0 20 0 1 0 12345",
            1_700_000_000_000,
            100,
        )
        .expect("stat should parse");

        assert_eq!(start_time, 1_700_000_123_450);
    }

    #[test]
    fn parses_proc_boot_time() {
        let boot_time =
            parse_proc_boot_time_unix_ms("cpu  1 2 3\nbtime 1700000000\n").expect("btime parses");

        assert_eq!(boot_time, 1_700_000_000_000);
    }

    #[test]
    fn parses_proc_io_lifetime_byte_counters() {
        let counters = parse_proc_io(
            "rchar: 1\n\
             wchar: 2\n\
             syscr: 3\n\
             syscw: 4\n\
             read_bytes: 4096\n\
             write_bytes: 8192\n",
            "test",
        )
        .expect("io counters should parse");

        assert_eq!(counters.bytes_read, 4096);
        assert_eq!(counters.bytes_written, 8192);
    }

    #[test]
    fn converts_ticks_to_microseconds_without_overflowing() {
        assert_eq!(ticks_to_micros(345, 100), 3_450_000);
        assert_eq!(ticks_to_micros(u64::MAX, 100), u64::MAX / 100);
    }

    #[test]
    fn linux_self_stats_reports_current_process() {
        let stats = read_self_stats().expect("self stats should be readable from /proc");

        assert!(stats.rss_bytes > 0);
        assert!(stats.virtual_memory_bytes >= stats.rss_bytes);
        assert_eq!(stats.idle_wakeups, None);
        assert!(stats.bytes_read.is_some());
        assert!(stats.bytes_written.is_some());
    }

    #[test]
    fn linux_process_list_reports_visible_processes() {
        let current_pid = i32::try_from(std::process::id()).expect("pid should fit i32");
        let processes = read_process_list().expect("process list should be readable from /proc");

        assert!(!processes.iter().any(|process| process.pid == current_pid));
        assert!(processes.iter().all(|process| process.pid > 0));
        assert!(processes.iter().all(|process| !process.name.is_empty()));
        assert!(
            processes
                .iter()
                .any(|process| process.start_time_unix_ms.is_some())
        );
    }

    #[test]
    fn linux_process_io_reports_current_process_counters() {
        let current_pid = i32::try_from(std::process::id()).expect("pid should fit i32");
        let io = read_process_io(current_pid).expect("current process io should be readable");

        assert_eq!(io.pid, current_pid);
        assert_eq!(io.bytes_read_recent_15m, None);
        assert_eq!(io.bytes_written_recent_15m, None);
    }

    #[test]
    fn parses_fdinfo_octal_flags() {
        assert_eq!(
            parse_fdinfo_flags("pos:\t0\nflags:\t0100002\nmnt_id:\t1\n"),
            Some(0o100_002)
        );
    }

    #[test]
    fn parses_linux_maps_line_with_path_containing_spaces() {
        let root = std::path::Path::new("/tmp/sbh maps");
        let region = mapped_region_from_maps_line(
            42,
            "7f0000000000-7f0000001000 r-xp 00000000 00:00 1 /tmp/sbh maps/bin",
            root,
        )
        .expect("mapped region should parse under root");

        assert_eq!(region.pid, 42);
        assert_eq!(region.start_address, Some(0x7f00_0000_0000));
        assert_eq!(region.end_address, Some(0x7f00_0000_1000));
        assert_eq!(region.protection.as_deref(), Some("r-x"));
        assert!(region.path.ends_with("bin"));
    }

    #[test]
    fn linux_open_files_under_reports_current_process_tempfile_fd() {
        let dir = tempfile::TempDir::new().expect("temp dir should be created");
        let path = dir.path().join("open.txt");
        let _file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("temp file should open");
        let resolved_path = resolve_absolute_path(&path);
        let current_pid = i32::try_from(std::process::id()).expect("pid should fit i32");

        let result =
            read_open_files_under(dir.path()).expect("open files should be readable from /proc");
        assert!(result.complete);
        let actual = result
            .files
            .iter()
            .find(|open_file| open_file.pid == current_pid && open_file.path == resolved_path)
            .unwrap_or_else(|| {
                panic!(
                    "current process open file was not reported; open_files={:?}",
                    result.files
                )
            });

        assert_eq!(actual.kind, OpenFileKind::Regular);
        assert_eq!(actual.mode, OpenFileMode::ReadWrite);
        assert!(actual.fd.is_some());
    }

    #[test]
    fn linux_executables_under_reports_current_process_executable() {
        let exe = std::env::current_exe().expect("current executable should be known");
        let root = exe
            .parent()
            .expect("current executable should have a parent");
        let resolved_exe = resolve_absolute_path(&exe);
        let current_pid = i32::try_from(std::process::id()).expect("pid should fit i32");

        let result =
            read_executables_under(root).expect("executables should be readable from /proc");
        assert!(result.complete);

        assert!(result.processes.iter().any(|process| {
            process.pid == current_pid && process.executable.as_ref() == Some(&resolved_exe)
        }));
    }

    #[test]
    fn linux_mmap_regions_under_reports_current_process_executable_mapping() {
        let exe = std::env::current_exe().expect("current executable should be known");
        let resolved_exe = resolve_absolute_path(&exe);
        let current_pid = i32::try_from(std::process::id()).expect("pid should fit i32");

        let regions =
            read_mmap_regions_under(&resolved_exe).expect("maps should be readable from /proc");

        assert!(regions.iter().any(|region| {
            region.pid == current_pid
                && region.path == resolved_exe
                && region
                    .protection
                    .as_deref()
                    .is_some_and(|mode| mode.contains('x'))
        }));
    }
}
