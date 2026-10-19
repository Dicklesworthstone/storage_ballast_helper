//! Error-preserving iteration over native file-backed memory mappings.
//!
//! libproc returns zero on syscall failure and leaves the reason in errno.
//! A zero result must not be converted to generic NotFound: callers need to
//! distinguish an exhausted vnode query from inaccessible process memory.

use std::io;
use std::mem::{MaybeUninit, size_of};

use crate::ProcRegionWithPathInfo;

// XNU bsd/sys/proc_info.h: same result layout as PROC_PIDREGIONPATHINFO,
// but skip anonymous regions instead of returning every VM allocation.
const PROC_PIDREGIONPATHINFO2: i32 = 22;

/// Observe the next file-backed region at or after `address`.
///
/// `None` is XNU's EINVAL termination signal for this specific, fixed-flavor
/// query. Other native failures retain their errno. This is not an atomic VM
/// snapshot: XNU can also terminate this query when a vnode disappears during
/// lookup. Callers must bound iteration and recheck process identity; neither
/// termination nor a successful record is a durable permission to mutate files.
#[allow(unsafe_code)]
pub fn proc_pid_next_mapped_region(
    pid: i32,
    address: u64,
) -> io::Result<Option<ProcRegionWithPathInfo>> {
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mapped-region inspection requires a positive process id",
        ));
    }
    let size = i32::try_from(size_of::<ProcRegionWithPathInfo>())
        .map_err(|_| io::Error::other("mapped-region buffer size overflow"))?;
    let mut region = MaybeUninit::<ProcRegionWithPathInfo>::zeroed();
    // SAFETY: region provides size bytes of writable, aligned storage for the
    // fixed proc_regionwithpathinfo ABI. No reference to uninitialized memory
    // escapes, and the exact returned byte count is checked before assume_init.
    let returned = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDREGIONPATHINFO2,
            address,
            region.as_mut_ptr().cast(),
            size,
        )
    };
    // Read errno immediately, before any other native call or diagnostic.
    // A successful response must not inherit stale errno from an earlier call.
    let errno = (returned <= 0)
        .then(|| io::Error::last_os_error().raw_os_error())
        .flatten();
    if !has_region(returned, size, errno)? {
        return Ok(None);
    }
    // SAFETY: has_region accepted only a fully populated fixed-size record.
    Ok(Some(unsafe { region.assume_init() }))
}

fn has_region(returned: i32, expected: i32, errno: Option<i32>) -> io::Result<bool> {
    if returned > 0 {
        if returned == expected {
            return Ok(true);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native mapped-region record had an unexpected byte count",
        ));
    }
    match errno {
        // This errno has meaning only at this native region-query boundary;
        // never apply it to PID discovery, identity checks or path decoding.
        Some(libc::EINVAL) if returned == 0 => Ok(false),
        Some(code) if code != 0 => Err(io::Error::from_raw_os_error(code)),
        _ => Err(io::Error::other(
            "native mapped-region query failed without errno",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_negative_returns_preserve_native_failures() {
        for returned in [0, -1] {
            for code in [
                libc::EACCES,
                libc::EPERM,
                libc::ESRCH,
                libc::EIO,
                libc::ENOENT,
            ] {
                assert_eq!(
                    has_region(returned, 64, Some(code))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(code)
                );
            }
        }
    }

    #[test]
    fn only_native_zero_einval_is_the_end_of_region_signal() {
        assert!(!has_region(0, 64, Some(libc::EINVAL)).unwrap());
        assert_eq!(
            has_region(-1, 64, Some(libc::EINVAL))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        for errno in [None, Some(0)] {
            assert!(has_region(0, 64, errno).is_err());
        }
    }

    #[test]
    fn short_or_oversized_records_are_not_complete_or_end_of_scan() {
        for returned in [1, 63, 65, i32::MAX] {
            assert_eq!(
                has_region(returned, 64, Some(libc::EINVAL))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert!(has_region(64, 64, Some(libc::EACCES)).unwrap());
    }

    #[test]
    fn invalid_process_ids_fail_before_a_native_query() {
        for pid in [i32::MIN, -1, 0] {
            assert_eq!(
                proc_pid_next_mapped_region(pid, 0).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn native_current_process_has_a_region_and_a_terminal_address() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let region = proc_pid_next_mapped_region(pid, 0)
            .unwrap()
            .expect("current executable must have a file-backed mapping");
        assert!(region.prp_prinfo.pri_size > 0);
        assert!(region.prp_vip.path().unwrap().is_absolute());
        assert!(
            proc_pid_next_mapped_region(pid, u64::MAX)
                .unwrap()
                .is_none()
        );
    }
}
