//! Safe macOS libproc adapter.

#![cfg(target_os = "macos")]
#![allow(missing_docs)]

use std::io;
use std::path::PathBuf;
use std::process::Command;

use super::sys;
use proc_pidinfo::{Fd, Pid, proc_pidfdinfo, proc_pidinfo, proc_pidinfo_list};

pub type ProcTaskInfo = proc_pidinfo::ProcTaskInfo;
pub type ProcTaskAllInfo = proc_pidinfo::ProcTaskAllInfo;
pub type ProcFdInfo = proc_pidinfo::ProcFDInfo;
pub type ProcFdType = proc_pidinfo::ProcFDType;
pub type ProcFileInfo = proc_pidinfo::ProcFileInfo;
pub type VnodeFdInfoWithPath = proc_pidinfo::VnodeFdInfoWithPath;
pub type ProcRegionInfo = sbh_mach::ProcRegionInfo;
pub type ProcRegionWithPathInfo = sbh_mach::ProcRegionWithPathInfo;
pub type RUsageInfoV4 = sbh_mach::RUsageInfoV4;

pub const PROC_ALL_PIDS: u32 = 1;
pub const PROC_PIDLISTFDS: i32 = 1;
pub const PROC_PIDTASKALLINFO: i32 = 2;
pub const PROC_PIDTASKINFO: i32 = 4;
pub const PROC_PIDPATHINFO: i32 = 11;
pub const PROC_PIDFDVNODEPATHINFO: i32 = 2;
pub const RUSAGE_INFO_V4: i32 = 4;
const PROCARGS2_HEADER_BYTES: usize = core::mem::size_of::<i32>();

pub fn proc_listpids_safe() -> io::Result<Vec<i32>> {
    sbh_mach::proc_listpids_all()
}

pub fn proc_pidinfo_task(pid: i32) -> io::Result<ProcTaskInfo> {
    proc_pidinfo::<ProcTaskInfo>(pid_arg(pid)?)?.ok_or_else(|| process_not_found(pid))
}

pub fn proc_pidinfo_task_all(pid: i32) -> io::Result<ProcTaskAllInfo> {
    proc_pidinfo::<ProcTaskAllInfo>(pid_arg(pid)?)?.ok_or_else(|| process_not_found(pid))
}

pub fn proc_pidpath_safe(pid: i32) -> io::Result<PathBuf> {
    validate_pid(pid)?;
    sbh_mach::proc_pidpath(pid)
}

pub fn proc_pid_command_line(pid: i32) -> io::Result<Vec<String>> {
    validate_pid(pid)?;
    match proc_pid_procargs2(pid).and_then(|raw| parse_procargs2_command_line(&raw)) {
        Ok(args) => Ok(args),
        Err(procargs_error) => proc_pid_command_line_from_ps(pid).map_err(|ps_error| {
            io::Error::new(
                ps_error.kind(),
                format!(
                    "KERN_PROCARGS2 failed ({procargs_error}); ps command fallback failed ({ps_error})"
                ),
            )
        }),
    }
}

pub fn proc_pid_procargs2(pid: i32) -> io::Result<Vec<u8>> {
    validate_pid(pid)?;
    sys::sysctl::read_mib::<Vec<u8>>(&[libc::CTL_KERN, libc::KERN_PROCARGS2, pid])
}

pub fn proc_pid_rusage_v4_safe(pid: i32) -> io::Result<RUsageInfoV4> {
    validate_pid(pid)?;
    sbh_mach::proc_pid_rusage_v4(pid)
}

pub fn proc_pid_list_fds(pid: i32) -> io::Result<Vec<ProcFdInfo>> {
    proc_pidinfo_list::<ProcFdInfo>(pid_arg(pid)?)
}

pub fn proc_pidfdinfo_vnode_path(pid: i32, fd: i32) -> io::Result<Option<VnodeFdInfoWithPath>> {
    proc_pidfdinfo::<VnodeFdInfoWithPath>(pid_arg(pid)?, fd_arg(fd)?)
}

pub fn proc_pid_region_path(pid: i32, address: u64) -> io::Result<ProcRegionWithPathInfo> {
    validate_pid(pid)?;
    sbh_mach::proc_pid_region_path(pid, address)
}

pub fn parse_procargs2_command_line(raw: &[u8]) -> io::Result<Vec<String>> {
    let argc = procargs2_argc(raw)?;
    let argc = usize::try_from(argc)
        .map_err(|_| invalid_procargs2("argc must be non-negative and fit usize"))?;
    if argc == 0 {
        return Ok(Vec::new());
    }

    let strings = raw
        .get(PROCARGS2_HEADER_BYTES..)
        .ok_or_else(|| invalid_procargs2("missing string table"))?;
    let exec_path_end =
        next_nul(strings, 0).ok_or_else(|| invalid_procargs2("missing exec path terminator"))?;
    let mut cursor = exec_path_end + 1;
    cursor = skip_exec_path_padding(strings, cursor);

    let mut command_line = Vec::with_capacity(argc);
    while command_line.len() < argc {
        let next = next_nul(strings, cursor)
            .ok_or_else(|| invalid_procargs2("argv table ended before argc entries"))?;
        command_line.push(String::from_utf8_lossy(&strings[cursor..next]).into_owned());
        cursor = next + 1;
    }

    Ok(command_line)
}

fn procargs2_argc(raw: &[u8]) -> io::Result<i32> {
    let bytes: [u8; PROCARGS2_HEADER_BYTES] = raw
        .get(..PROCARGS2_HEADER_BYTES)
        .ok_or_else(|| invalid_procargs2("missing argc header"))?
        .try_into()
        .expect("slice length checked above");
    let argc = i32::from_ne_bytes(bytes);
    if argc < 0 {
        return Err(invalid_procargs2("argc must be non-negative"));
    }
    Ok(argc)
}

fn skip_exec_path_padding(strings: &[u8], cursor: usize) -> usize {
    strings
        .get(cursor..)
        .and_then(|rest| rest.iter().position(|byte| *byte != 0))
        .map_or(strings.len(), |offset| cursor + offset)
}

fn next_nul(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| start + offset)
}

fn invalid_procargs2(detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("malformed KERN_PROCARGS2 buffer: {detail}"),
    )
}

fn proc_pid_command_line_from_ps(pid: i32) -> io::Result<Vec<String>> {
    validate_pid(pid)?;
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-ww", "-o", "command="])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("ps did not report process {pid}"),
        ));
    }

    let command = String::from_utf8_lossy(&output.stdout);
    let command = command.trim();
    if command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("process {pid} had no ps command output"),
        ));
    }

    Ok(split_ps_command_line(command))
}

fn split_ps_command_line(command: &str) -> Vec<String> {
    command.split_whitespace().map(ToOwned::to_owned).collect()
}

fn validate_pid(pid: i32) -> io::Result<()> {
    if pid < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pid must be non-negative",
        ));
    }
    Ok(())
}

fn pid_arg(pid: i32) -> io::Result<Pid> {
    u32::try_from(pid)
        .map(Pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid must be non-negative"))
}

fn fd_arg(fd: i32) -> io::Result<Fd> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file descriptor must be non-negative",
        ));
    }
    Ok(Fd(fd))
}

fn process_not_found(pid: i32) -> io::Error {
    native_or(io::Error::new(
        io::ErrorKind::NotFound,
        format!("libproc returned no data for pid {pid}"),
    ))
}

/// The reason a libproc call that just returned no data failed, or `fallback`.
///
/// libproc returns zero bytes when the call fails and leaves the reason in
/// errno; the proc_pidinfo crate reports that as `Ok(None)` and drops it. Call
/// this at once, before any other call. Without it a zombie (ESRCH: about 20
/// at any time on one busy Mac) looked like an unreadable process, and every
/// collector that treats only ESRCH as exited reported incomplete coverage on
/// every pass.
pub fn native_or(fallback: io::Error) -> io::Error {
    let native = io::Error::last_os_error();
    if native.raw_os_error().is_some_and(|code| code != 0) {
        native
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use std::mem;
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    use super::{
        PROC_ALL_PIDS, PROC_PIDFDVNODEPATHINFO, PROC_PIDLISTFDS, PROC_PIDPATHINFO,
        PROC_PIDTASKALLINFO, PROC_PIDTASKINFO, PROCARGS2_HEADER_BYTES, ProcFdInfo, ProcFdType,
        ProcFileInfo, ProcRegionInfo, ProcRegionWithPathInfo, ProcTaskAllInfo, ProcTaskInfo,
        RUSAGE_INFO_V4, RUsageInfoV4, VnodeFdInfoWithPath, parse_procargs2_command_line,
        proc_listpids_safe, proc_pid_command_line, proc_pid_list_fds, proc_pid_procargs2,
        proc_pid_region_path, proc_pid_rusage_v4_safe, proc_pidfdinfo_vnode_path,
        proc_pidinfo_task, proc_pidinfo_task_all, proc_pidpath_safe, split_ps_command_line,
    };

    fn current_pid() -> i32 {
        i32::try_from(std::process::id()).expect("current process id should fit in i32")
    }

    fn procargs2_fixture(exec_path: &str, args: &[&str]) -> Vec<u8> {
        let mut raw = i32::try_from(args.len())
            .expect("test argc should fit i32")
            .to_ne_bytes()
            .to_vec();
        raw.extend_from_slice(exec_path.as_bytes());
        raw.push(0);

        let string_cursor = exec_path.len() + 1;
        let alignment = core::mem::size_of::<usize>();
        let padding = (alignment - (string_cursor % alignment)) % alignment;
        raw.resize(raw.len() + padding, 0);

        for arg in args {
            raw.extend_from_slice(arg.as_bytes());
            raw.push(0);
        }
        raw.extend_from_slice(b"ENV_FROM_TEST=1\0");
        raw
    }

    #[test]
    fn constants_and_struct_layouts_match_macos_sdk() {
        assert_eq!(PROC_ALL_PIDS, 1);
        assert_eq!(PROC_PIDLISTFDS, 1);
        assert_eq!(PROC_PIDTASKALLINFO, 2);
        assert_eq!(PROC_PIDTASKINFO, 4);
        assert_eq!(PROC_PIDPATHINFO, 11);
        assert_eq!(PROC_PIDFDVNODEPATHINFO, 2);
        assert_eq!(RUSAGE_INFO_V4, 4);

        assert_eq!(mem::size_of::<ProcTaskInfo>(), 96);
        assert_eq!(mem::size_of::<ProcTaskAllInfo>(), 232);
        assert_eq!(mem::size_of::<RUsageInfoV4>(), 296);
        assert_eq!(mem::size_of::<ProcFdInfo>(), 8);
        assert_eq!(mem::size_of::<ProcFileInfo>(), 24);
        assert_eq!(mem::size_of::<VnodeFdInfoWithPath>(), 1200);
        assert_eq!(mem::size_of::<ProcRegionInfo>(), 96);
        assert_eq!(mem::size_of::<ProcRegionWithPathInfo>(), 1272);
    }

    #[test]
    fn proc_listpids_includes_current_process() {
        let current = current_pid();
        let pids = proc_listpids_safe().expect("proc_listpids should succeed");
        assert!(pids.contains(&current));
    }

    #[test]
    fn current_process_task_path_and_rusage_are_readable() {
        let current = current_pid();
        let task = proc_pidinfo_task(current).expect("task info should be readable");
        assert!(task.pti_virtual_size > 0);
        assert!(task.pti_resident_size > 0);

        let all = proc_pidinfo_task_all(current).expect("task-all info should be readable");
        assert_eq!(all.pbsd.pbi_pid.0, std::process::id());

        let path = proc_pidpath_safe(current).expect("pid path should be readable");
        assert!(!path.as_os_str().is_empty());

        let rusage = proc_pid_rusage_v4_safe(current).expect("rusage should be readable");
        assert!(rusage.ri_resident_size > 0);
    }

    #[test]
    fn procargs2_parser_reads_argv_and_ignores_environment_tail() {
        let raw = procargs2_fixture("/bin/sbh-test", &["sbh-test", "--flag", "value"]);
        let args = parse_procargs2_command_line(&raw).expect("procargs2 fixture should parse");

        assert_eq!(args, vec!["sbh-test", "--flag", "value"]);
    }

    #[test]
    fn procargs2_parser_skips_exec_path_padding() {
        let mut raw = procargs2_fixture("/bin/sbh-test", &["sbh-test"]);
        let insert_at = PROCARGS2_HEADER_BYTES + "/bin/sbh-test".len() + 1;
        raw.splice(insert_at..insert_at, [0, 0, 0]);
        let args = parse_procargs2_command_line(&raw).expect("procargs2 fixture should parse");

        assert_eq!(args, vec!["sbh-test"]);
    }

    #[test]
    fn procargs2_parser_rejects_truncated_argv_table() {
        let raw = procargs2_fixture("/bin/sbh-test", &["only-one"]);
        let mut truncated = raw[..raw.len() - b"ENV_FROM_TEST=1\0".len()].to_vec();
        truncated[0..4].copy_from_slice(&2_i32.to_ne_bytes());

        let error = parse_procargs2_command_line(&truncated).expect_err("missing argv should fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn procargs2_reader_rejects_negative_pid() {
        let error = proc_pid_procargs2(-1).expect_err("negative pid should fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ps_command_line_split_extracts_observable_args() {
        let args = split_ps_command_line("/bin/sleep 5");

        assert_eq!(args, vec!["/bin/sleep", "5"]);
    }

    #[test]
    fn proc_pid_command_line_reads_current_process() {
        let current = current_pid();
        let args = proc_pid_command_line(current).expect("current argv should be readable");
        assert!(!args.is_empty());
        let current_exe = std::env::current_exe().expect("current exe should be known");
        let expected_name = current_exe
            .file_name()
            .and_then(|name| name.to_str())
            .expect("current exe name should be UTF-8");
        assert!(
            Path::new(&args[0])
                .file_name()
                .and_then(|name| name.to_str())
                == Some(expected_name)
                || args[0].contains(expected_name),
            "argv[0] should identify current test binary: {args:?}"
        );
    }

    #[test]
    fn proc_pid_command_line_reads_spawned_process_argv() {
        let mut child = Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("sleep process should spawn");
        let pid = i32::try_from(child.id()).expect("child pid should fit i32");

        let mut observed = None;
        for _ in 0..20 {
            match proc_pid_command_line(pid) {
                Ok(args) if args.len() >= 2 => {
                    observed = Some(args);
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }

        let _ = child.kill();
        let _ = child.wait();

        let args = observed.expect("spawned process argv should be readable");
        assert!(
            Path::new(&args[0])
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "sleep"),
            "argv[0] should identify sleep: {args:?}"
        );
        assert_eq!(args.get(1).map(String::as_str), Some("5"));
    }

    #[test]
    fn current_process_region_path_is_readable() {
        let current = current_pid();
        let region = proc_pid_region_path(current, 0).expect("region path should be readable");
        assert!(region.prp_prinfo.pri_size > 0);
    }

    #[test]
    fn vnode_fdinfo_reports_open_temp_file_path() {
        let file = tempfile::NamedTempFile::new().expect("temp file should be created");
        let expected =
            std::fs::canonicalize(file.path()).expect("temp file path should canonicalize");
        let current = current_pid();

        let fds = proc_pid_list_fds(current).expect("fd list should be readable");
        let mut found = false;
        for fd in fds {
            if fd.fd_type() != Ok(ProcFdType::VNODE) {
                continue;
            }
            let Some(info) = proc_pidfdinfo_vnode_path(current, fd.proc_fd.0)
                .expect("vnode fd info should be readable")
            else {
                continue;
            };
            let Ok(path) = info.path() else {
                continue;
            };
            let Ok(actual) = std::fs::canonicalize(path) else {
                continue;
            };
            if actual == expected {
                found = true;
                break;
            }
        }

        assert!(
            found,
            "open tempfile should appear in current process vnode fd list"
        );
    }
}
