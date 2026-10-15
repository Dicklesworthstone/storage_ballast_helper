//! Reads that can block behind another process's memory-map lock.
//!
//! `/proc/PID/cmdline` and `environ` go through `access_remote_vm`, which
//! waits for the target's mmap lock. A process stuck in a fault or mmap under
//! memory pressure holds that lock for as long as it is stuck (ts2,
//! 2026-10-15: a rustc for 19 minutes), and no deadline check between reads
//! can interrupt the reader. Each read therefore runs on its own short-lived
//! thread, and the caller stops waiting at its deadline, abandoning the thread
//! in the kernel. Later reads of that process fail at once until the abandoned
//! read returns, so a wedged process costs one thread, not one per sweep.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Abandoned reads still blocked, by process directory. Past this many, every
/// read fails at once instead of leaving another thread in the kernel.
const MAX_ABANDONED: usize = 16;
const READER_STACK_BYTES: usize = 64 * 1024;

static ABANDONED: parking_lot::Mutex<Vec<PathBuf>> = parking_lot::Mutex::new(Vec::new());

/// Run `read` for `process`, giving up after `wait`.
pub(super) fn read(
    process: &Path,
    wait: Duration,
    read: impl FnOnce() -> io::Result<Vec<u8>> + Send + 'static,
) -> io::Result<Vec<u8>> {
    {
        let abandoned = ABANDONED.lock();
        if abandoned.len() >= MAX_ABANDONED || abandoned.iter().any(|path| path == process) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "an earlier read of this process's memory is still blocked",
            ));
        }
    }
    let (reply, result) = mpsc::sync_channel(1);
    let key = process.to_path_buf();
    std::thread::Builder::new()
        .name("sbh-procmem".to_string())
        .stack_size(READER_STACK_BYTES)
        .spawn(move || {
            let value = read();
            // Reply under the lock: a caller that timed out has either seen
            // this reply or recorded the process, which is cleared here.
            let mut abandoned = ABANDONED.lock();
            abandoned.retain(|path| *path != key);
            let _ = reply.send(value);
        })?;
    match result.recv_timeout(wait) {
        Ok(value) => value,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let mut abandoned = ABANDONED.lock();
            if let Ok(value) = result.try_recv() {
                return value;
            }
            abandoned.push(process.to_path_buf());
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process memory read blocked past the sweep deadline",
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
            "process memory reader exited without a result",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn key(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/sbh-memory-read-test/{}/{name}",
            std::process::id()
        ))
    }

    #[test]
    fn a_blocked_read_is_abandoned_once_and_cleared_when_it_returns() {
        let process = key("wedged");
        let (release, gate) = mpsc::channel::<()>();
        let started = Instant::now();
        let error = read(&process, Duration::from_millis(50), move || {
            let _ = gate.recv();
            Ok(b"late".to_vec())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));

        // While the first read is stuck, the process costs no new thread.
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let error = read(&process, Duration::from_secs(10), move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Other processes are unaffected.
        let other = read(&key("healthy"), Duration::from_secs(10), || {
            Ok(b"ok".to_vec())
        });
        assert_eq!(other.unwrap(), b"ok");

        // Once the stuck read returns, the process is readable again.
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match read(&process, Duration::from_secs(10), || Ok(b"again".to_vec())) {
                Ok(value) => {
                    assert_eq!(value, b"again");
                    break;
                }
                Err(error) if Instant::now() < deadline => {
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("abandoned read never cleared: {error}"),
            }
        }
    }

    #[test]
    fn read_errors_pass_through_unchanged() {
        let error = read(&key("denied"), Duration::from_secs(10), || {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }
}
