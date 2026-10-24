//! Bounded, read-only process-path queries.
//!
//! All returned data is owned. The caller must still account for process exit,
//! PID reuse, permissions and changes between queries; these calls are not an
//! atomic process snapshot. No command is executed to obtain this evidence.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// Maximum bytes copied from one process's `KERN_PROCARGS2` buffer.
/// Oversized records fail rather than returning a truncated environment.
pub const PROCESS_ARGUMENTS_MAX_BYTES: usize = 512 * 1024;

fn validate_pid(pid: i32) -> io::Result<()> {
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process path queries require a positive pid",
        ));
    }
    Ok(())
}

/// Read the kernel-held current directory through `PROC_PIDVNODEPATHINFO`.
/// Native path bytes are preserved; an empty or unterminated path is unknown.
#[allow(unsafe_code)]
pub fn proc_pid_cwd(pid: i32) -> io::Result<PathBuf> {
    validate_pid(pid)?;
    let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    let expected = size_of::<libc::proc_vnodepathinfo>();
    let capacity = i32::try_from(expected)
        .map_err(|_| io::Error::other("process vnode buffer is too large"))?;
    // SAFETY: info is aligned, initialized storage for the libc ABI struct;
    // proc_pidinfo receives exactly its capacity and cannot retain the pointer.
    let received = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            capacity,
        )
    };
    if received <= 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(0) {
            io::Error::new(io::ErrorKind::NotFound, "process vnode paths unavailable")
        } else {
            error
        });
    }
    if usize::try_from(received).ok() != Some(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete process vnode path record",
        ));
    }
    // SAFETY: the syscall returned the exact libc struct size into initialized
    // storage. Only scalar fields and the fixed path array are inspected.
    let info = unsafe { info.assume_init() };
    if info.pvi_cdir.vip_vi.vi_stat.vst_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process cwd is not a directory",
        ));
    }
    // libc declares the MAXPATHLEN array as 32 rows of 32 for old compilers.
    decode_cwd(info.pvi_cdir.vip_path.as_flattened())
}

fn decode_cwd(raw: &[libc::c_char]) -> io::Result<PathBuf> {
    let end = raw
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unterminated process cwd"))?;
    let bytes: Vec<u8> = raw[..end]
        .iter()
        .map(|byte| byte.to_ne_bytes()[0])
        .collect();
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process cwd is not absolute",
        ));
    }
    Ok(path)
}

/// Read one complete, bounded `KERN_PROCARGS2` record.
///
/// The record holds argc, the executable, argv and the environment. Callers should retain only the specific fields they need and
/// must not log the buffer: unrelated environment variables can be sensitive.
/// No dynamic kernel size hint can make this allocate above the fixed cap.
#[allow(unsafe_code)]
pub fn proc_pid_arguments(pid: i32) -> io::Result<Vec<u8>> {
    validate_pid(pid)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut bytes = vec![0u8; PROCESS_ARGUMENTS_MAX_BYTES];
    let mut received = bytes.len();
    // SAFETY: mib contains three valid integer selectors. The initialized
    // byte buffer and length pointer are valid for the duration of sysctl;
    // there is no new-value buffer and no pointer is retained by the kernel.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            bytes.as_mut_ptr().cast(),
            &raw mut received,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    validate_argument_length(received)?;
    bytes.truncate(received);
    Ok(bytes)
}

fn validate_argument_length(length: usize) -> io::Result<()> {
    if !(size_of::<i32>()..=PROCESS_ARGUMENTS_MAX_BYTES).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or oversized process argument record",
        ));
    }
    Ok(())
}

/// `PROC_PIDFDSOCKETINFO` (xnu `sys/proc_info.h`). libc declares
/// `proc_pidfdinfo` but not `struct socket_fdinfo`, so the record is read
/// into bytes and only the fields below are decoded.
const PROC_PIDFDSOCKETINFO: i32 = 3;
/// `struct socket_fdinfo` is a 24-byte `proc_fileinfo` followed by
/// `struct socket_info`, whose `soi_family` is 160 bytes in and whose
/// protocol union starts 240 bytes in. For `AF_UNIX` that union is
/// `un_sockinfo`: two 8-byte handles, then the bound `sockaddr_un`
/// (`sun_len`, `sun_family`, then up to 104 path bytes).
const SOCKET_FAMILY_OFFSET: usize = 24 + 160;
const UNIX_BOUND_ADDRESS_OFFSET: usize = 24 + 240 + 16;
const UNIX_PATH_MAX: usize = 104;
/// Larger than any `socket_fdinfo` (792 bytes on macOS 14-27); the kernel
/// writes only the record and reports its size.
const SOCKET_FDINFO_CAPACITY: usize = 2048;

/// The filesystem path a process's `AF_UNIX` socket descriptor is bound to.
///
/// A listening server shows here what its descriptor is otherwise silent
/// about: the socket file it serves. `None` for other families, unbound
/// sockets (clients) and sockets bound to a relative or empty path.
#[allow(unsafe_code)]
pub fn proc_pid_unix_socket_path(pid: i32, fd: i32) -> io::Result<Option<PathBuf>> {
    validate_pid(pid)?;
    let mut record = vec![0u8; SOCKET_FDINFO_CAPACITY];
    let capacity = i32::try_from(record.len())
        .map_err(|_| io::Error::other("socket record buffer is too large"))?;
    // SAFETY: record is initialized, writable storage of `capacity` bytes;
    // proc_pidfdinfo writes at most that many and retains no pointer.
    let received = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            record.as_mut_ptr().cast(),
            capacity,
        )
    };
    if received <= 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(0) {
            io::Error::new(io::ErrorKind::NotFound, "socket descriptor unavailable")
        } else {
            error
        });
    }
    decode_unix_socket_path(&record, usize::try_from(received).unwrap_or(0))
}

fn decode_unix_socket_path(record: &[u8], received: usize) -> io::Result<Option<PathBuf>> {
    let path_start = UNIX_BOUND_ADDRESS_OFFSET + 2;
    if received < path_start + UNIX_PATH_MAX || record.len() < received {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete socket descriptor record",
        ));
    }
    let family = i32::from_ne_bytes(
        record[SOCKET_FAMILY_OFFSET..SOCKET_FAMILY_OFFSET + 4]
            .try_into()
            .map_err(|_| io::Error::other("socket family field"))?,
    );
    if family != libc::AF_UNIX {
        return Ok(None);
    }
    let raw = &record[path_start..path_start + UNIX_PATH_MAX];
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let path = PathBuf::from(OsString::from_vec(raw[..end].to_vec()));
    Ok(path.is_absolute().then_some(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn c_bytes(bytes: &[u8]) -> Vec<libc::c_char> {
        bytes
            .iter()
            .map(|byte| libc::c_char::from_ne_bytes([*byte]))
            .collect()
    }

    #[test]
    fn nonpositive_pids_are_rejected_before_native_queries() {
        for pid in [i32::MIN, -1, 0] {
            assert_eq!(
                proc_pid_cwd(pid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                proc_pid_arguments(pid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    /// Proves the record offsets on the running kernel: a listener reports
    /// the exact path it was bound to, a socketpair end reports nothing.
    #[test]
    fn a_bound_unix_socket_reports_its_path() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = std::env::temp_dir().join(format!("sbh-mach-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let pid = i32::try_from(std::process::id()).unwrap();

        let bound = proc_pid_unix_socket_path(pid, listener.as_raw_fd()).unwrap();
        let (left, _right) = UnixStream::pair().unwrap();
        let unbound = proc_pid_unix_socket_path(pid, left.as_raw_fd()).unwrap();
        drop(listener);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);

        assert_eq!(bound, Some(path));
        assert_eq!(unbound, None);
    }

    #[test]
    fn socket_records_are_decoded_only_when_complete_and_absolute() {
        let path_start = UNIX_BOUND_ADDRESS_OFFSET + 2;
        let full = path_start + UNIX_PATH_MAX;
        let mut record = vec![0u8; full];
        record[SOCKET_FAMILY_OFFSET..SOCKET_FAMILY_OFFSET + 4]
            .copy_from_slice(&libc::AF_UNIX.to_ne_bytes());
        record[path_start..path_start + 9].copy_from_slice(b"/tmp/x.so");
        assert_eq!(
            decode_unix_socket_path(&record, full).unwrap(),
            Some(PathBuf::from("/tmp/x.so"))
        );
        assert!(decode_unix_socket_path(&record, full - 1).is_err());
        record[path_start..path_start + 9].copy_from_slice(b"relative\0");
        assert_eq!(decode_unix_socket_path(&record, full).unwrap(), None);
        record[SOCKET_FAMILY_OFFSET..SOCKET_FAMILY_OFFSET + 4]
            .copy_from_slice(&libc::AF_INET.to_ne_bytes());
        assert_eq!(decode_unix_socket_path(&record, full).unwrap(), None);
    }

    #[test]
    fn cwd_requires_a_terminated_absolute_path() {
        for raw in [b"".as_slice(), b"\0", b"relative\0", b"/unterminated"] {
            assert_eq!(
                decode_cwd(&c_bytes(raw)).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            decode_cwd(&c_bytes(b"/\0ignored")).unwrap(),
            PathBuf::from("/")
        );
    }

    #[test]
    fn cwd_keeps_native_bytes_and_spaces_without_lossy_conversion() {
        assert_eq!(
            decode_cwd(&c_bytes(b"/tmp/worker-\xff path\0")).unwrap(),
            PathBuf::from(OsString::from_vec(b"/tmp/worker-\xff path".to_vec()))
        );
    }

    #[test]
    fn argument_record_length_is_bounded_without_overflow() {
        for length in [0, 1, 3, PROCESS_ARGUMENTS_MAX_BYTES + 1, usize::MAX] {
            assert!(validate_argument_length(length).is_err());
        }
        for length in [4, 1024, PROCESS_ARGUMENTS_MAX_BYTES] {
            validate_argument_length(length).unwrap();
        }
    }

    #[test]
    fn current_process_cwd_matches_the_native_directory() {
        let pid = i32::try_from(std::process::id()).unwrap();
        assert_eq!(
            std::fs::canonicalize(proc_pid_cwd(pid).unwrap()).unwrap(),
            std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap()
        );
    }

    #[test]
    fn a_child_exposes_its_cwd_and_environment_without_opening_that_cwd() {
        const HOLD: &str = "SBH_PROCESS_PATH_TEST";
        if std::env::var_os(HOLD).is_some() {
            // The child: stay alive until the parent has looked.
            std::thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
        // Not /bin/sleep: macOS withholds the environment of Apple platform
        // binaries from KERN_PROCARGS2, even for root. Build tools (rustup's
        // cargo and rustc, Homebrew's node and python) are third-party
        // binaries like this test executable, whose environment is readable.
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process_paths::tests::a_child_exposes_its_cwd_and_environment_without_opening_that_cwd",
                "--nocapture",
            ])
            .current_dir("/")
            .env(HOLD, "owned-fixture")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let child = ChildGuard(child);
        let pid = i32::try_from(child.0.id()).unwrap();
        assert_eq!(proc_pid_cwd(pid).unwrap(), PathBuf::from("/"));
        let raw = proc_pid_arguments(pid).unwrap();
        let expected = b"SBH_PROCESS_PATH_TEST=owned-fixture\0";
        assert!(raw.windows(expected.len()).any(|part| part == expected));
        assert!(raw.len() <= PROCESS_ARGUMENTS_MAX_BYTES);
    }
}
