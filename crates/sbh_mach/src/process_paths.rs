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

/// Maximum bytes copied from one process's KERN_PROCARGS2 buffer.
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

/// Read the kernel-held current directory through PROC_PIDVNODEPATHINFO.
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
    decode_cwd(&info.pvi_cdir.vip_path)
}

fn decode_cwd(raw: &[libc::c_char]) -> io::Result<PathBuf> {
    let end = raw.iter().position(|byte| *byte == 0).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unterminated process cwd")
    })?;
    let bytes: Vec<u8> = raw[..end].iter().map(|byte| byte.to_ne_bytes()[0]).collect();
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process cwd is not absolute",
        ));
    }
    Ok(path)
}

/// Read one complete, bounded KERN_PROCARGS2 record (argc, executable, argv,
/// environment). Callers should retain only the specific fields they need and
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
        bytes.iter().map(|byte| libc::c_char::from_ne_bytes([*byte])).collect()
    }

    #[test]
    fn nonpositive_pids_are_rejected_before_native_queries() {
        for pid in [i32::MIN, -1, 0] {
            assert_eq!(proc_pid_cwd(pid).unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(proc_pid_arguments(pid).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn cwd_requires_a_terminated_absolute_path() {
        for raw in [b"".as_slice(), b"\0", b"relative\0", b"/unterminated"] {
            assert_eq!(decode_cwd(&c_bytes(raw)).unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        assert_eq!(decode_cwd(&c_bytes(b"/\0ignored")).unwrap(), PathBuf::from("/"));
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
        let child = Command::new("/bin/sleep")
            .arg("30")
            .current_dir("/")
            .env("SBH_PROCESS_PATH_TEST", "owned-fixture")
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
