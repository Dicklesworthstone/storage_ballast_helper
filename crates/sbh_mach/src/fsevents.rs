//! Owned, bounded FSEvents delivery for the scanner.
//!
//! The callback only copies paths into a bounded inbox. It never invokes user
//! code, scans a directory, or authorizes deletion. Lost events invalidate the
//! entire view; root changes additionally require a new stream. The caller
//! must reconcile once after starting a stream and periodically thereafter.
//!
//! Native references and callback context ownership stay inside this module.
//! Invalidation and a serial-queue barrier precede releasing either one.

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::{CStr, c_char, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Maximum recursive roots in a stream, independent of descendant count.
pub const MAX_ROOTS: usize = 1024;
const MAX_PENDING_PATHS: usize = 2048;
const MAX_PENDING_BYTES: usize = 512 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_CALLBACK_EVENTS: usize = 4096;

// FSEvents.h: history is advisory; a lost/coalesced subtree event cannot be
// treated as a complete list of changes. FileEvents gives paths for writes
// to existing files too, unlike directory-only vnode watches.
const MUST_SCAN_SUBDIRS: u32 = 0x0000_0001;
const USER_DROPPED: u32 = 0x0000_0002;
const KERNEL_DROPPED: u32 = 0x0000_0004;
const IDS_WRAPPED: u32 = 0x0000_0008;
const HISTORY_DONE: u32 = 0x0000_0010;
const ROOT_CHANGED: u32 = 0x0000_0020;
const MOUNT: u32 = 0x0000_0040;
const UNMOUNT: u32 = 0x0000_0080;
const RESCAN_FLAGS: u32 = MUST_SCAN_SUBDIRS | USER_DROPPED | KERNEL_DROPPED | IDS_WRAPPED;
const RESTART_FLAGS: u32 = ROOT_CHANGED | MOUNT | UNMOUNT | IDS_WRAPPED;
const CREATE_FLAGS: u32 = 0x0000_0002 | 0x0000_0004 | 0x0000_0010; // NoDefer | WatchRoot | FileEvents
const UTF8: u32 = 0x0800_0100;

/// Changes since the last drain. Paths are sorted and deduplicated.
#[derive(Debug, Default)]
pub struct EventBatch {
    /// Changed paths. An empty list alone is not proof of an unchanged tree.
    pub paths: Vec<PathBuf>,
    /// Events were lost or coalesced: invalidate all cached generations and
    /// reconcile all configured roots, not only the paths in this batch.
    pub must_rescan: bool,
    /// A root/mount changed, or delivery lost information about root health.
    /// Replace the stream before trusting its coverage again.
    pub restart_required: bool,
}

#[derive(Debug, Default)]
struct Pending {
    paths: BTreeSet<PathBuf>,
    bytes: usize,
}

#[derive(Debug, Default)]
struct Inbox {
    pending: Mutex<Pending>,
    rescan: AtomicBool,
    restart: AtomicBool,
}

impl Inbox {
    fn lost(&self) {
        // A discarded event might have been RootChanged. Do not assume the
        // old stream still covers the configured path after local loss.
        self.restart.store(true, Ordering::Release);
        self.rescan.store(true, Ordering::Release);
    }

    fn drain(&self) -> EventBatch {
        let mut pending = self.pending.lock().unwrap_or_else(|err| err.into_inner());
        let restart_required = self.restart.swap(false, Ordering::AcqRel);
        let must_rescan = self.rescan.swap(false, Ordering::AcqRel) || restart_required;
        let paths = std::mem::take(&mut pending.paths).into_iter().collect();
        pending.bytes = 0;
        EventBatch {
            paths,
            must_rescan,
            restart_required,
        }
    }
}

type NativeRef = *const c_void;
type Callback = unsafe extern "C" fn(
    NativeRef,
    *mut c_void,
    usize,
    *mut c_void,
    *const u32,
    *const u64,
);

#[repr(C)]
struct StreamContext {
    version: isize,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(NativeRef) -> NativeRef>,
    release: Option<unsafe extern "C" fn(NativeRef)>,
    copy_description: Option<unsafe extern "C" fn(NativeRef) -> NativeRef>,
}

#[repr(C)]
struct ArrayCallbacks {
    version: isize,
    retain: Option<unsafe extern "C" fn(NativeRef, NativeRef) -> NativeRef>,
    release: Option<unsafe extern "C" fn(NativeRef, NativeRef)>,
    copy_description: Option<unsafe extern "C" fn(NativeRef) -> NativeRef>,
    equal: Option<unsafe extern "C" fn(NativeRef, NativeRef) -> u8>,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: ArrayCallbacks;
    fn CFStringCreateWithBytes(
        allocator: NativeRef,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> NativeRef;
    fn CFArrayCreate(
        allocator: NativeRef,
        values: *const NativeRef,
        count: isize,
        callbacks: *const ArrayCallbacks,
    ) -> NativeRef;
    fn CFRelease(value: NativeRef);
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: NativeRef,
        callback: Callback,
        context: *mut StreamContext,
        paths: NativeRef,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> *mut c_void;
    fn FSEventStreamSetDispatchQueue(stream: *mut c_void, queue: *mut c_void);
    fn FSEventStreamStart(stream: *mut c_void) -> u8;
    fn FSEventStreamStop(stream: *mut c_void);
    fn FSEventStreamInvalidate(stream: *mut c_void);
    fn FSEventStreamRelease(stream: *mut c_void);
}

#[link(name = "System")]
unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attributes: NativeRef) -> *mut c_void;
    fn dispatch_sync_f(queue: *mut c_void, context: *mut c_void, work: extern "C" fn(*mut c_void));
    fn dispatch_release(object: *mut c_void);
}

struct CfOwned(NonNull<c_void>);

impl CfOwned {
    fn checked(value: NativeRef, call: &str) -> io::Result<Self> {
        NonNull::new(value.cast_mut())
            .map(Self)
            .ok_or_else(|| io::Error::other(format!("{call} returned null")))
    }

    fn raw(&self) -> NativeRef {
        self.0.as_ptr()
    }
}

impl Drop for CfOwned {
    fn drop(&mut self) {
        // SAFETY: this is one owned +1 reference from a CF Create function.
        unsafe { CFRelease(self.raw()) };
    }
}

#[derive(Debug)]
struct Queue(NonNull<c_void>);

impl Drop for Queue {
    fn drop(&mut self) {
        // SAFETY: created with +1 ownership, never manually released elsewhere.
        unsafe { dispatch_release(self.0.as_ptr()) };
    }
}

#[derive(Debug)]
struct NativeStream {
    stream: NonNull<c_void>,
    queue: Queue,
    started: bool,
}

extern "C" fn barrier(_context: *mut c_void) {}

impl Drop for NativeStream {
    fn drop(&mut self) {
        // SAFETY: the stream was scheduled on this private serial queue before
        // construction completed. No callback calls user code, so destruction
        // cannot run on that queue. Stop only a successfully started stream;
        // invalidate before release even when Start failed. The barrier waits
        // for any in-flight callback before releasing the native ownership.
        unsafe {
            if self.started {
                FSEventStreamStop(self.stream.as_ptr());
            }
            FSEventStreamInvalidate(self.stream.as_ptr());
            dispatch_sync_f(self.queue.0.as_ptr(), ptr::null_mut(), barrier);
            FSEventStreamRelease(self.stream.as_ptr());
        }
    }
}

// SAFETY: the unique owner may move between threads. Native callbacks use
// only the retained synchronized Inbox; stream lifetime operations remain
// serialized by &mut/self ownership and the private dispatch queue barrier.
unsafe impl Send for NativeStream {}

/// A recursively watched set of absolute, canonical directory paths.
///
/// FSEvents uses one stream, not one descriptor per descendant directory.
/// Drains are nonblocking with respect to filesystem I/O; delivery is bounded
/// in count and bytes. Drop stops callbacks and releases native resources.
#[derive(Debug)]
pub struct Fsevents {
    // Drop the native stream before releasing our callback-state reference.
    _native: NativeStream,
    inbox: Arc<Inbox>,
}

impl Fsevents {
    /// Start watching canonical directory paths supplied by the caller.
    /// Unsupported paths and startup failures return errors for fallback.
    pub fn start(roots: &[PathBuf]) -> io::Result<Self> {
        if roots.is_empty() || roots.len() > MAX_ROOTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FSEvents root limit exceeded or no roots",
            ));
        }
        let mut strings = Vec::with_capacity(roots.len());
        for root in roots {
            let bytes = root.as_os_str().as_bytes();
            if !root.is_absolute()
                || root.to_str().is_none()
                || bytes.contains(&0)
                || bytes.len() > MAX_PATH_BYTES
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "FSEvents requires absolute UTF-8 paths without NUL bytes",
                ));
            }
            let length = isize::try_from(bytes.len()).map_err(|_| io::Error::other("path too long"))?;
            // SAFETY: bytes is live for length bytes. CF copies the string;
            // UTF-8 was validated above. Null uses the default allocator.
            strings.push(CfOwned::checked(
                unsafe {
                    CFStringCreateWithBytes(ptr::null(), bytes.as_ptr(), length, UTF8, 0)
                },
                "CFStringCreateWithBytes",
            )?);
        }
        let values: Vec<NativeRef> = strings.iter().map(CfOwned::raw).collect();
        let count =
            isize::try_from(values.len()).map_err(|_| io::Error::other("too many roots"))?;
        // SAFETY: every value is a live CFString. Type callbacks retain the
        // strings, so both the array and any stream-retained copy own them.
        let paths = CfOwned::checked(
            unsafe {
                CFArrayCreate(
                    ptr::null(),
                    values.as_ptr(),
                    count,
                    &raw const kCFTypeArrayCallBacks,
                )
            },
            "CFArrayCreate",
        )?;
        // SAFETY: static NUL-terminated label; null attributes request serial.
        let queue = Queue(
            NonNull::new(unsafe {
                dispatch_queue_create(c"sbh.scanner.fsevents".as_ptr(), ptr::null())
            })
            .ok_or_else(|| io::Error::other("dispatch_queue_create returned null"))?,
        );
        let inbox = Arc::new(Inbox::default());
        let mut context = StreamContext {
            version: 0,
            info: Arc::as_ptr(&inbox).cast_mut().cast(),
            retain: Some(retain_context),
            release: Some(release_context),
            copy_description: None,
        };
        // SAFETY: CF array and context are live. Retain/release callbacks give
        // the stream its own Arc reference. Paths are delivered as char**
        // because UseCFTypes is not set. SinceNow requires an initial scan.
        let stream = NonNull::new(unsafe {
            FSEventStreamCreate(
                ptr::null(),
                receive,
                &raw mut context,
                paths.raw(),
                u64::MAX,
                0.25,
                CREATE_FLAGS,
            )
        })
        .ok_or_else(|| io::Error::other("FSEventStreamCreate failed"))?;
        // SAFETY: stream and queue were successfully created. Schedule before
        // constructing NativeStream, whose Drop invalidates that scheduling.
        unsafe { FSEventStreamSetDispatchQueue(stream.as_ptr(), queue.0.as_ptr()) };
        let mut native = NativeStream {
            stream,
            queue,
            started: false,
        };
        // SAFETY: a valid, scheduled stream; callback ownership is established.
        if unsafe { FSEventStreamStart(native.stream.as_ptr()) } == 0 {
            return Err(io::Error::other("FSEventStreamStart failed"));
        }
        native.started = true;
        Ok(Self {
            _native: native,
            inbox,
        })
    }

    /// Drain observed changes without scanning the watched filesystem.
    pub fn drain(&mut self) -> EventBatch {
        self.inbox.drain()
    }

}

unsafe extern "C" fn retain_context(info: NativeRef) -> NativeRef {
    // SAFETY: context.info was made from Arc::as_ptr; creation keeps the
    // original alive and each native retain is paired with release_context.
    unsafe { Arc::increment_strong_count(info.cast::<Inbox>()) };
    info
}

unsafe extern "C" fn release_context(info: NativeRef) {
    // SAFETY: consumes precisely the reference acquired by retain_context.
    drop(unsafe { Arc::from_raw(info.cast::<Inbox>()) });
}

unsafe extern "C" fn receive(
    _stream: NativeRef,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    flags: *const u32,
    _ids: *const u64,
) {
    // SAFETY: the stream retains the Inbox for the callback's whole lifetime.
    let inbox = unsafe { &*info.cast::<Inbox>() };
    // Never unwind across the C boundary, including on a poisoned mutex.
    if catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: FSEvents supplies count entries in both arrays, with valid
        // NUL-terminated filesystem paths when UseCFTypes is disabled.
        unsafe { receive_inner(inbox, count, paths, flags) };
    }))
    .is_err()
    {
        inbox.lost();
    }
}

unsafe fn receive_inner(inbox: &Inbox, count: usize, paths: *mut c_void, flags: *const u32) {
    if count == 0 {
        return;
    }
    if count > MAX_CALLBACK_EVENTS || paths.is_null() || flags.is_null() {
        inbox.lost();
        return;
    }
    let Ok(mut pending) = inbox.pending.try_lock() else {
        inbox.lost();
        return;
    };
    for index in 0..count {
        // SAFETY: caller supplies count flag entries, and index < count.
        let flag = unsafe { *flags.add(index) };
        if flag & RESTART_FLAGS != 0 {
            inbox.restart.store(true, Ordering::Release);
            inbox.rescan.store(true, Ordering::Release);
        }
        if flag & RESCAN_FLAGS != 0 {
            inbox.rescan.store(true, Ordering::Release);
        }
        if flag == HISTORY_DONE {
            continue;
        }
        // SAFETY: same array contract, with char** rather than UseCFTypes.
        let name = unsafe { *paths.cast::<*const c_char>().add(index) };
        if name.is_null() {
            inbox.lost();
            continue;
        }
        // SAFETY: FSEvents owns a NUL-terminated C string for this callback.
        let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
        let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
        if !path.is_absolute() || bytes.len() > MAX_PATH_BYTES {
            inbox.lost();
            continue;
        }
        if pending.paths.contains(path) {
            continue;
        }
        if pending.paths.len() >= MAX_PENDING_PATHS
            || bytes.len() > MAX_PENDING_BYTES.saturating_sub(pending.bytes)
        {
            inbox.lost();
            continue;
        }
        pending.bytes += bytes.len();
        pending.paths.insert(path.to_path_buf());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn deliver(inbox: &Inbox, entries: &[(&str, u32)]) {
        let names: Vec<CString> = entries
            .iter()
            .map(|(path, _)| CString::new(*path).unwrap())
            .collect();
        let mut pointers: Vec<*const c_char> = names.iter().map(|path| path.as_ptr()).collect();
        let flags: Vec<u32> = entries.iter().map(|(_, flag)| *flag).collect();
        // SAFETY: these live arrays satisfy exactly the native callback ABI.
        unsafe {
            receive_inner(
                inbox,
                entries.len(),
                pointers.as_mut_ptr().cast(),
                flags.as_ptr(),
            )
        };
    }

    #[test]
    fn paths_are_copied_deduplicated_and_drained() {
        let inbox = Inbox::default();
        deliver(&inbox, &[("/root/b", 0), ("/root/a", 0), ("/root/b", 0)]);
        let batch = inbox.drain();
        assert_eq!(
            batch.paths,
            vec![PathBuf::from("/root/a"), PathBuf::from("/root/b")]
        );
        assert!(!batch.must_rescan);
        assert!(!batch.restart_required);
        assert!(inbox.drain().paths.is_empty());
    }

    #[test]
    fn kernel_loss_requires_full_reconciliation() {
        for flag in [MUST_SCAN_SUBDIRS, USER_DROPPED, KERNEL_DROPPED] {
            let inbox = Inbox::default();
            deliver(&inbox, &[("/root", flag)]);
            assert!(inbox.drain().must_rescan);
        }
    }

    #[test]
    fn root_and_mount_changes_require_restarting_the_stream() {
        for flag in [ROOT_CHANGED, MOUNT, UNMOUNT, IDS_WRAPPED] {
            let inbox = Inbox::default();
            deliver(&inbox, &[("/root", flag)]);
            let batch = inbox.drain();
            assert!(batch.must_rescan);
            assert!(batch.restart_required);
        }
    }

    #[test]
    fn full_inbox_stays_bounded_and_reports_loss() {
        let inbox = Inbox::default();
        for index in 0..=MAX_PENDING_PATHS {
            deliver(&inbox, &[(format!("/root/{index}").as_str(), 0)]);
        }
        let batch = inbox.drain();
        assert_eq!(batch.paths.len(), MAX_PENDING_PATHS);
        assert!(batch.must_rescan && batch.restart_required);
        deliver(&inbox, &[("/root/after-drain", 0)]);
        let next = inbox.drain();
        assert_eq!(next.paths.len(), 1);
        assert!(!next.must_rescan);
    }

    #[test]
    fn byte_budget_bounds_long_paths() {
        let inbox = Inbox::default();
        for index in 0..MAX_PENDING_PATHS {
            let path = format!("/root/{index}/{}", "x".repeat(2048));
            deliver(&inbox, &[(path.as_str(), 0)]);
        }
        let pending = inbox.pending.lock().unwrap();
        assert!(pending.bytes <= MAX_PENDING_BYTES);
        assert!(pending.paths.len() < MAX_PENDING_PATHS);
        drop(pending);
        assert!(inbox.drain().must_rescan);
    }

    #[test]
    fn callback_saturation_never_waits_for_consumer_lock() {
        let inbox = Inbox::default();
        let guard = inbox.pending.lock().unwrap();
        deliver(&inbox, &[("/root/file", 0)]);
        drop(guard);
        let batch = inbox.drain();
        assert!(batch.must_rescan && batch.restart_required);
    }

    #[test]
    fn oversized_callback_does_not_dereference_its_arrays() {
        let inbox = Inbox::default();
        // SAFETY: the oversized-count path rejects before reading arrays.
        unsafe {
            receive_inner(
                &inbox,
                MAX_CALLBACK_EVENTS + 1,
                ptr::null_mut(),
                ptr::null(),
            )
        };
        assert!(inbox.drain().must_rescan);
    }

    #[test]
    fn relative_paths_fail_closed_and_history_done_is_ignored() {
        let inbox = Inbox::default();
        deliver(&inbox, &[("/root", HISTORY_DONE)]);
        assert!(inbox.drain().paths.is_empty());
        deliver(&inbox, &[("relative/file", 0)]);
        let batch = inbox.drain();
        assert!(batch.paths.is_empty());
        assert!(batch.must_rescan);
    }

    #[test]
    fn native_owner_can_move_to_the_scanner_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<Fsevents>();
    }
}
