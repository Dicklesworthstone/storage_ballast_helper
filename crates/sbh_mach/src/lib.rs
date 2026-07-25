//! Safe wrappers around the small Mach surface `sbh` needs.
//!
//! The main `storage_ballast_helper` crate forbids unsafe code. This crate keeps
//! the platform FFI boundary narrow and exposes copied scalar values only.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, OsStr, c_void};
use std::fmt;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr;

use dispatch2::{
    _dispatch_source_type_memorypressure, DispatchObject, DispatchQoS, DispatchQueue,
    DispatchRetained, DispatchSource, GlobalQueueIdentifier,
    dispatch_source_memorypressure_flags_t,
};
use mach2::kern_return::{KERN_SUCCESS, kern_return_t};
use mach2::mach_init::{mach_host_self, mach_thread_self};
use mach2::mach_port::mach_port_deallocate;
use mach2::mach_types::thread_act_t;
use mach2::message::mach_msg_type_number_t;
use mach2::task::task_info;
use mach2::task_info::{
    MACH_TASK_BASIC_INFO, MACH_TASK_BASIC_INFO_COUNT, TASK_THREAD_TIMES_INFO,
    TASK_THREAD_TIMES_INFO_COUNT, mach_task_basic_info, task_thread_times_info,
};
use mach2::time_value::time_value_t;
use mach2::traps::mach_task_self;
use mach2::vm_types::{integer_t, natural_t};

const THREAD_BASIC_INFO: natural_t = 3;
const THREAD_BASIC_INFO_COUNT: mach_msg_type_number_t =
    (size_of::<MachThreadBasicInfoRaw>() / size_of::<natural_t>()) as mach_msg_type_number_t;
/// XNU's original `vm_statistics64` layout — the `HOST_VM_INFO64` rev0 ABI.
///
/// Declared locally, and used *only* to derive [`HOST_VM_INFO64_REV0_COUNT`];
/// the actual read buffer stays `libc::vm_statistics64`, which is a superset
/// with an identical prefix, so field offsets for everything we read match.
///
/// This mirror exists because the count is an **ABI revision selector**, not a
/// buffer size. `host_statistics64` validates it against the revisions the
/// kernel implements and rejects anything else with `KERN_INVALID_ARGUMENT` —
/// it will not simply fill "as much as you asked for". So the count must be a
/// number XNU recognises, which means we have to own the layout that defines
/// it rather than inheriting whatever size libc's struct happens to be today.
#[repr(C)]
struct VmStatistics64Rev0 {
    free_count: natural_t,
    active_count: natural_t,
    inactive_count: natural_t,
    wire_count: natural_t,
    zero_fill_count: u64,
    reactivations: u64,
    pageins: u64,
    pageouts: u64,
    faults: u64,
    cow_faults: u64,
    lookups: u64,
    hits: u64,
    purges: u64,
    purgeable_count: natural_t,
    speculative_count: natural_t,
    decompressions: u64,
    compressions: u64,
    swapins: u64,
    swapouts: u64,
    compressor_page_count: natural_t,
    throttled_count: natural_t,
    external_page_count: natural_t,
    internal_page_count: natural_t,
    total_uncompressed_pages_in_compressor: u64,
}

/// `HOST_VM_INFO64` rev0 count (38 `integer_t` slots).
///
/// Deliberately **not** `libc::HOST_VM_INFO64_COUNT`. That constant is
/// `size_of::<vm_statistics64_data_t>() / size_of::<integer_t>()`, so it grows
/// whenever libc widens the struct to track a newer XNU. libc 0.2.189 widened it
/// from 24 to 57 fields; the requested count went 38 -> 90, no kernel recognised
/// that revision, and `host_statistics64` returned `KERN_INVALID_ARGUMENT` —
/// silently killing *every* macOS memory read while the disk half of sbh kept
/// working. It reproduced on GitHub's Apple Silicon runners, not just locally.
///
/// Anchoring to the rev0 layout keeps the request at a revision every
/// `HOST_VM_INFO64`-capable kernel implements, and makes us immune to future
/// upstream struct growth. Every field [`host_vm_stats`] reads lives in rev0.
const HOST_VM_INFO64_REV0_COUNT: mach_msg_type_number_t =
    (size_of::<VmStatistics64Rev0>() / size_of::<integer_t>()) as mach_msg_type_number_t;

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDREGIONPATHINFO: i32 = 8;
const RUSAGE_INFO_V4: i32 = 4;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct MachThreadBasicInfoRaw {
    user_time: time_value_t,
    system_time: time_value_t,
    cpu_usage: integer_t,
    policy: integer_t,
    run_state: integer_t,
    flags: integer_t,
    suspend_count: integer_t,
    sleep_time: integer_t,
}

unsafe extern "C" {
    fn thread_info(
        target_act: thread_act_t,
        flavor: natural_t,
        thread_info_out: *mut integer_t,
        thread_info_out_count: *mut mach_msg_type_number_t,
    ) -> kern_return_t;
}

/// Error returned by a Mach adapter call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachError {
    call: &'static str,
    code: kern_return_t,
}

impl MachError {
    fn new(call: &'static str, code: kern_return_t) -> Self {
        Self { call, code }
    }

    /// Mach call name.
    pub fn call(&self) -> &'static str {
        self.call
    }

    /// Raw `kern_return_t` value.
    pub fn code(&self) -> kern_return_t {
        self.code
    }
}

impl fmt::Display for MachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed with kern_return_t {}", self.call, self.code)
    }
}

impl std::error::Error for MachError {}

/// Basic current-task memory and terminated-thread CPU counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskBasicInfo {
    /// Current virtual address space size in bytes.
    pub virtual_size_bytes: u64,
    /// Current resident memory size in bytes.
    pub resident_size_bytes: u64,
    /// Peak resident memory size in bytes.
    pub resident_size_max_bytes: u64,
    /// User CPU time for terminated threads, in microseconds.
    pub user_time_micros: u64,
    /// System CPU time for terminated threads, in microseconds.
    pub system_time_micros: u64,
}

/// Live-thread CPU counters for the current task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskThreadTimes {
    /// User CPU time for live threads, in microseconds.
    pub user_time_micros: u64,
    /// System CPU time for live threads, in microseconds.
    pub system_time_micros: u64,
}

/// Current-thread basic Mach counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadBasicInfo {
    /// User CPU time for the current thread, in microseconds.
    pub user_time_micros: u64,
    /// System CPU time for the current thread, in microseconds.
    pub system_time_micros: u64,
    /// Scaled CPU usage as reported by Mach `THREAD_BASIC_INFO`.
    pub cpu_usage_scaled: i32,
    /// Mach thread run-state value.
    pub run_state: i32,
    /// Mach thread flags bitset.
    pub flags: i32,
}

/// Combined current-task usage counters suitable for daemon self-monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentTaskUsage {
    /// Current resident memory size in bytes.
    pub rss_bytes: u64,
    /// Current virtual address space size in bytes.
    pub virtual_memory_bytes: u64,
    /// Combined user CPU time for terminated and live threads, in microseconds.
    pub cpu_user_micros: u64,
    /// Combined system CPU time for terminated and live threads, in microseconds.
    pub cpu_system_micros: u64,
}

/// Host-wide VM statistics from `host_statistics64(HOST_VM_INFO64)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmStats {
    /// Host VM page size in bytes.
    pub page_size_bytes: u64,
    /// Pages immediately available for allocation.
    pub free_count: u64,
    /// Active pages.
    pub active_count: u64,
    /// Inactive pages.
    pub inactive_count: u64,
    /// Wired pages.
    pub wire_count: u64,
    /// Speculative pages.
    pub speculative_count: u64,
    /// Pages occupied by the in-RAM compressor.
    pub compressor_page_count: u64,
    /// Throttled pages.
    pub throttled_count: u64,
}

/// Darwin `proc_regioninfo` layout used by `PROC_PIDREGIONPATHINFO`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcRegionInfo {
    /// Current VM protection bits.
    pub pri_protection: u32,
    /// Maximum VM protection bits.
    pub pri_max_protection: u32,
    /// VM inheritance value.
    pub pri_inheritance: u32,
    /// Region flags.
    pub pri_flags: u32,
    /// Region file offset.
    pub pri_offset: u64,
    /// VM behavior value.
    pub pri_behavior: u32,
    /// User wired page count.
    pub pri_user_wired_count: u32,
    /// User tag.
    pub pri_user_tag: u32,
    /// Resident page count.
    pub pri_pages_resident: u32,
    /// Shared pages that are now private.
    pub pri_pages_shared_now_private: u32,
    /// Swapped-out page count.
    pub pri_pages_swapped_out: u32,
    /// Dirtied page count.
    pub pri_pages_dirtied: u32,
    /// Object reference count.
    pub pri_ref_count: u32,
    /// Shadow chain depth.
    pub pri_shadow_depth: u32,
    /// Region sharing mode.
    pub pri_share_mode: u32,
    /// Private resident page count.
    pub pri_private_pages_resident: u32,
    /// Shared resident page count.
    pub pri_shared_pages_resident: u32,
    /// VM object identifier.
    pub pri_obj_id: u32,
    /// Region nesting depth.
    pub pri_depth: u32,
    /// Region start address.
    pub pri_address: u64,
    /// Region size in bytes.
    pub pri_size: u64,
}

/// Darwin `proc_regionwithpathinfo` layout used by mapped-region scans.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcRegionWithPathInfo {
    /// Region memory counters and address range.
    pub prp_prinfo: ProcRegionInfo,
    /// Backing vnode path information for the mapped region.
    pub prp_vip: proc_pidinfo::VnodeInfoPath,
}

/// Process resource usage counters from Darwin `RUSAGE_INFO_V4`.
pub type RUsageInfoV4 = libc::rusage_info_v4;

/// Memory-pressure transition delivered by macOS Grand Central Dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPressureEvent {
    /// System memory pressure returned to normal.
    Normal,
    /// System memory pressure reached the warning level.
    Warn,
    /// System memory pressure reached the critical level.
    Critical,
    /// Dispatch delivered an unrecognized bitmask.
    Unknown(usize),
}

impl MemoryPressureEvent {
    /// Map a raw `dispatch_source_get_data()` bitmask to the strongest event.
    pub fn from_dispatch_data(data: usize) -> Self {
        if data & memory_pressure_flag(
            dispatch_source_memorypressure_flags_t::DISPATCH_MEMORYPRESSURE_CRITICAL,
        ) != 0
        {
            Self::Critical
        } else if data
            & memory_pressure_flag(
                dispatch_source_memorypressure_flags_t::DISPATCH_MEMORYPRESSURE_WARN,
            )
            != 0
        {
            Self::Warn
        } else if data
            & memory_pressure_flag(
                dispatch_source_memorypressure_flags_t::DISPATCH_MEMORYPRESSURE_NORMAL,
            )
            != 0
        {
            Self::Normal
        } else {
            Self::Unknown(data)
        }
    }
}

/// Active native macOS memory-pressure dispatch source.
#[derive(Debug)]
pub struct MemoryPressureSource {
    source: DispatchRetained<DispatchSource>,
}

impl MemoryPressureSource {
    /// Whether the underlying dispatch source has been canceled.
    pub fn is_canceled(&self) -> bool {
        self.source.testcancel() != 0
    }
}

impl Drop for MemoryPressureSource {
    fn drop(&mut self) {
        self.source.cancel();
    }
}

struct MemoryPressureState {
    source: *const DispatchSource,
    callback: Box<dyn Fn(MemoryPressureEvent) + Send + Sync + 'static>,
}

impl VmStats {
    /// Pages represented by the core VM accounting buckets.
    pub fn accounted_pages(&self) -> u64 {
        self.free_count
            .saturating_add(self.active_count)
            .saturating_add(self.inactive_count)
            .saturating_add(self.wire_count)
            .saturating_add(self.compressor_page_count)
    }
}

/// Read `MACH_TASK_BASIC_INFO` for the current task.
///
/// Apple headers mark older `TASK_BASIC_INFO_64` flavors as compatibility
/// forms and recommend `MACH_TASK_BASIC_INFO`; this uses the recommended
/// always-64-bit flavor and copies out scalar values immediately.
pub fn current_task_basic_info() -> Result<TaskBasicInfo, MachError> {
    let mut info = MaybeUninit::<mach_task_basic_info>::zeroed();
    let mut count = MACH_TASK_BASIC_INFO_COUNT;

    let code = unsafe {
        task_info(
            mach_task_self(),
            MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast::<integer_t>(),
            &mut count,
        )
    };
    ensure_success("task_info(MACH_TASK_BASIC_INFO)", code)?;
    ensure_count(
        "task_info(MACH_TASK_BASIC_INFO)",
        count,
        MACH_TASK_BASIC_INFO_COUNT,
    )?;

    let info = unsafe { info.assume_init() };
    Ok(TaskBasicInfo {
        virtual_size_bytes: unsafe { ptr::addr_of!(info.virtual_size).read_unaligned() },
        resident_size_bytes: unsafe { ptr::addr_of!(info.resident_size).read_unaligned() },
        resident_size_max_bytes: unsafe { ptr::addr_of!(info.resident_size_max).read_unaligned() },
        user_time_micros: time_value_to_micros(unsafe {
            ptr::addr_of!(info.user_time).read_unaligned()
        }),
        system_time_micros: time_value_to_micros(unsafe {
            ptr::addr_of!(info.system_time).read_unaligned()
        }),
    })
}

/// Read `TASK_THREAD_TIMES_INFO` for live threads in the current task.
pub fn current_task_thread_times() -> Result<TaskThreadTimes, MachError> {
    let mut info = MaybeUninit::<task_thread_times_info>::zeroed();
    let mut count = TASK_THREAD_TIMES_INFO_COUNT;

    let code = unsafe {
        task_info(
            mach_task_self(),
            TASK_THREAD_TIMES_INFO,
            info.as_mut_ptr().cast::<integer_t>(),
            &mut count,
        )
    };
    ensure_success("task_info(TASK_THREAD_TIMES_INFO)", code)?;
    ensure_count(
        "task_info(TASK_THREAD_TIMES_INFO)",
        count,
        TASK_THREAD_TIMES_INFO_COUNT,
    )?;

    let info = unsafe { info.assume_init() };
    Ok(TaskThreadTimes {
        user_time_micros: time_value_to_micros(unsafe {
            ptr::addr_of!(info.user_time).read_unaligned()
        }),
        system_time_micros: time_value_to_micros(unsafe {
            ptr::addr_of!(info.system_time).read_unaligned()
        }),
    })
}

/// Read `THREAD_BASIC_INFO` for the calling thread.
pub fn current_thread_basic_info() -> Result<ThreadBasicInfo, MachError> {
    let thread = unsafe { mach_thread_self() };
    let result = thread_basic_info_for_port(thread);
    let _ = unsafe { mach_port_deallocate(mach_task_self(), thread) };
    result
}

/// Return combined current-task counters.
pub fn current_task_usage() -> Result<CurrentTaskUsage, MachError> {
    let basic = current_task_basic_info()?;
    let live_threads = current_task_thread_times()?;
    Ok(CurrentTaskUsage {
        rss_bytes: basic.resident_size_bytes,
        virtual_memory_bytes: basic.virtual_size_bytes,
        cpu_user_micros: basic
            .user_time_micros
            .saturating_add(live_threads.user_time_micros),
        cpu_system_micros: basic
            .system_time_micros
            .saturating_add(live_threads.system_time_micros),
    })
}

/// Read `HOST_VM_INFO64` for the current host.
pub fn host_vm_stats() -> Result<VmStats, MachError> {
    let mut info = MaybeUninit::<libc::vm_statistics64>::zeroed();
    let mut count = HOST_VM_INFO64_REV0_COUNT;

    let host = unsafe { mach_host_self() };
    let code = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            info.as_mut_ptr().cast::<libc::integer_t>(),
            &mut count,
        )
    };
    let _ = unsafe { mach_port_deallocate(mach_task_self(), host) };

    ensure_success("host_statistics64(HOST_VM_INFO64)", code)?;
    ensure_count(
        "host_statistics64(HOST_VM_INFO64)",
        count,
        HOST_VM_INFO64_REV0_COUNT,
    )?;

    let info = unsafe { info.assume_init() };
    Ok(VmStats {
        page_size_bytes: page_size_bytes()?,
        free_count: natural_to_u64(unsafe { ptr::addr_of!(info.free_count).read_unaligned() }),
        active_count: natural_to_u64(unsafe { ptr::addr_of!(info.active_count).read_unaligned() }),
        inactive_count: natural_to_u64(unsafe {
            ptr::addr_of!(info.inactive_count).read_unaligned()
        }),
        wire_count: natural_to_u64(unsafe { ptr::addr_of!(info.wire_count).read_unaligned() }),
        speculative_count: natural_to_u64(unsafe {
            ptr::addr_of!(info.speculative_count).read_unaligned()
        }),
        compressor_page_count: natural_to_u64(unsafe {
            ptr::addr_of!(info.compressor_page_count).read_unaligned()
        }),
        throttled_count: natural_to_u64(unsafe {
            ptr::addr_of!(info.throttled_count).read_unaligned()
        }),
    })
}

/// Return all process identifiers visible to the current process.
pub fn proc_listpids_all() -> io::Result<Vec<i32>> {
    let initial_bytes = unsafe {
        libc::proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0)
    };
    if initial_bytes < 0 {
        return Err(io::Error::last_os_error());
    }

    let pid_size = size_of::<libc::pid_t>();
    let initial_capacity = usize::try_from(initial_bytes)
        .ok()
        .filter(|bytes| *bytes > 0)
        .map_or(1024, |bytes| bytes / pid_size);
    let mut pids = Vec::<libc::pid_t>::with_capacity(initial_capacity.max(1));

    loop {
        let buffer_bytes = pids
            .capacity()
            .checked_mul(pid_size)
            .and_then(|bytes| i32::try_from(bytes).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pid buffer too large"))?;
        let returned_bytes = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                pids.as_mut_ptr().cast::<c_void>(),
                buffer_bytes,
            )
        };
        if returned_bytes < 0 {
            return Err(io::Error::last_os_error());
        }
        if returned_bytes == buffer_bytes {
            pids.reserve(pids.capacity().max(1));
            continue;
        }
        let returned_bytes = usize::try_from(returned_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative pid byte count"))?;
        if returned_bytes % pid_size != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pid byte count is not aligned",
            ));
        }
        let len = returned_bytes / pid_size;
        unsafe {
            pids.set_len(len);
        }
        return Ok(pids);
    }
}

/// Return the executable path for a process.
pub fn proc_pidpath(pid: i32) -> io::Result<PathBuf> {
    let buffer_size = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid pid path buffer size"))?;
    let mut buffer = vec![0_i8; buffer_size];
    let returned_bytes = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "pid path buffer too large")
            })?,
        )
    };
    if returned_bytes <= 0 {
        return Err(io::Error::last_os_error());
    }

    let path = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    Ok(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
}

/// Return Darwin `RUSAGE_INFO_V4` counters for a process.
pub fn proc_pid_rusage_v4(pid: i32) -> io::Result<RUsageInfoV4> {
    let mut usage = MaybeUninit::<RUsageInfoV4>::zeroed();
    let buffer_ptr = usage.as_mut_ptr().cast::<c_void>();
    let result = unsafe { libc::proc_pid_rusage(pid, RUSAGE_INFO_V4, buffer_ptr.cast()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { usage.assume_init() })
}

/// Return mapped-region path information for a process address.
pub fn proc_pid_region_path(pid: i32, address: u64) -> io::Result<ProcRegionWithPathInfo> {
    let mut info = MaybeUninit::<ProcRegionWithPathInfo>::zeroed();
    let buffer_size = i32::try_from(size_of::<ProcRegionWithPathInfo>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "region buffer too large"))?;
    let returned_bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDREGIONPATHINFO,
            address,
            info.as_mut_ptr().cast::<c_void>(),
            buffer_size,
        )
    };
    if returned_bytes < 0 {
        return Err(io::Error::last_os_error());
    }
    if returned_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("proc_pidinfo returned no region data for pid {pid}"),
        ));
    }
    if returned_bytes != buffer_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected region byte count {returned_bytes} != {buffer_size}"),
        ));
    }
    Ok(unsafe { info.assume_init() })
}

/// Subscribe to native `DISPATCH_SOURCE_TYPE_MEMORYPRESSURE` events.
pub fn subscribe_memory_pressure_events<F>(callback: F) -> Result<MemoryPressureSource, MachError>
where
    F: Fn(MemoryPressureEvent) + Send + Sync + 'static,
{
    let queue = DispatchQueue::global_queue(GlobalQueueIdentifier::QualityOfService(
        DispatchQoS::Utility,
    ));
    let mask = memory_pressure_event_mask();
    let source = unsafe {
        DispatchSource::new(
            ptr::addr_of!(_dispatch_source_type_memorypressure).cast_mut(),
            0,
            mask,
            Some(&queue),
        )
    };

    let state = Box::new(MemoryPressureState {
        source: &*source,
        callback: Box::new(callback),
    });
    let state_ptr = Box::into_raw(state).cast::<c_void>();

    unsafe {
        source.set_context(state_ptr);
    }
    source.set_event_handler_f(memory_pressure_event_handler);
    source.set_cancel_handler_f(memory_pressure_cancel_handler);
    source.activate();

    Ok(MemoryPressureSource { source })
}

fn thread_basic_info_for_port(thread: thread_act_t) -> Result<ThreadBasicInfo, MachError> {
    let mut info = MaybeUninit::<MachThreadBasicInfoRaw>::zeroed();
    let mut count = THREAD_BASIC_INFO_COUNT;

    let code = unsafe {
        thread_info(
            thread,
            THREAD_BASIC_INFO,
            info.as_mut_ptr().cast::<integer_t>(),
            &mut count,
        )
    };
    ensure_success("thread_info(THREAD_BASIC_INFO)", code)?;
    ensure_count(
        "thread_info(THREAD_BASIC_INFO)",
        count,
        THREAD_BASIC_INFO_COUNT,
    )?;

    let info = unsafe { info.assume_init() };
    Ok(ThreadBasicInfo {
        user_time_micros: time_value_to_micros(unsafe {
            ptr::addr_of!(info.user_time).read_unaligned()
        }),
        system_time_micros: time_value_to_micros(unsafe {
            ptr::addr_of!(info.system_time).read_unaligned()
        }),
        cpu_usage_scaled: unsafe { ptr::addr_of!(info.cpu_usage).read_unaligned() },
        run_state: unsafe { ptr::addr_of!(info.run_state).read_unaligned() },
        flags: unsafe { ptr::addr_of!(info.flags).read_unaligned() },
    })
}

fn ensure_success(call: &'static str, code: kern_return_t) -> Result<(), MachError> {
    if code == KERN_SUCCESS {
        Ok(())
    } else {
        Err(MachError::new(call, code))
    }
}

fn ensure_count(
    call: &'static str,
    actual: mach_msg_type_number_t,
    expected: mach_msg_type_number_t,
) -> Result<(), MachError> {
    if actual >= expected {
        Ok(())
    } else {
        Err(MachError::new(call, mach2::kern_return::KERN_INVALID_ARGUMENT))
    }
}

fn time_value_to_micros(value: mach2::time_value::time_value_t) -> u64 {
    let seconds = i64::from(value.seconds);
    let micros = i64::from(value.microseconds);
    if seconds < 0 || micros < 0 {
        return 0;
    }

    u64::try_from(seconds)
        .unwrap_or(u64::MAX / 1_000_000)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(micros).unwrap_or(0))
}

fn page_size_bytes() -> Result<u64, MachError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(page_size)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| MachError::new("sysconf(_SC_PAGESIZE)", libc::EINVAL))
}

fn natural_to_u64(value: libc::natural_t) -> u64 {
    u64::from(value)
}

const fn memory_pressure_flag(flag: dispatch_source_memorypressure_flags_t) -> usize {
    flag.0 as usize
}

const fn memory_pressure_event_mask() -> usize {
    memory_pressure_flag(dispatch_source_memorypressure_flags_t::DISPATCH_MEMORYPRESSURE_NORMAL)
        | memory_pressure_flag(dispatch_source_memorypressure_flags_t::DISPATCH_MEMORYPRESSURE_WARN)
        | memory_pressure_flag(
            dispatch_source_memorypressure_flags_t::DISPATCH_MEMORYPRESSURE_CRITICAL,
        )
}

extern "C" fn memory_pressure_event_handler(context: *mut c_void) {
    if context.is_null() {
        return;
    }

    let state = unsafe { &*context.cast::<MemoryPressureState>() };
    let source = unsafe { &*state.source };
    let event = MemoryPressureEvent::from_dispatch_data(source.data());
    let _ = catch_unwind(AssertUnwindSafe(|| (state.callback)(event)));
}

extern "C" fn memory_pressure_cancel_handler(context: *mut c_void) {
    if context.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(context.cast::<MemoryPressureState>()));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        current_task_basic_info, current_task_thread_times, current_task_usage, host_vm_stats,
        current_thread_basic_info, subscribe_memory_pressure_events, MemoryPressureEvent,
        HOST_VM_INFO64_REV0_COUNT,
    };

    /// REGRESSION: the `HOST_VM_INFO64` count must stay anchored to XNU's rev0
    /// ABI, never inherited from `libc::HOST_VM_INFO64_COUNT`.
    ///
    /// libc 0.2.189 widened `vm_statistics64` from 24 to 57 fields to track a
    /// newer XNU. Because the libc constant is `size_of::<struct>() /
    /// size_of::<integer_t>()`, the requested count went 38 -> 90. The count is
    /// an ABI *revision selector*, not a buffer size, so the kernel rejected the
    /// unrecognised revision with KERN_INVALID_ARGUMENT — silently killing every
    /// macOS memory read. Asserting the exact rev0 value means a future libc
    /// widening (or a typo in the mirror struct) fails loudly here instead of
    /// disabling memory monitoring in production.
    #[test]
    fn host_vm_info64_count_stays_anchored_to_rev0_abi() {
        assert_eq!(
            HOST_VM_INFO64_REV0_COUNT, 38,
            "HOST_VM_INFO64 rev0 is 38 integer_t slots; a different value means \
             VmStatistics64Rev0 no longer mirrors XNU's original layout"
        );
    }

    #[test]
    fn current_task_basic_info_reports_plausible_memory() {
        let info = current_task_basic_info().expect("current task basic info should be readable");
        assert!(info.resident_size_bytes > 1_048_576);
        assert!(info.virtual_size_bytes >= info.resident_size_bytes);
    }

    #[test]
    fn current_task_thread_times_are_readable() {
        let times = current_task_thread_times().expect("current task thread times should read");
        let total = times
            .user_time_micros
            .saturating_add(times.system_time_micros);
        assert!(total < 365 * 24 * 60 * 60 * 1_000_000);
    }

    #[test]
    fn current_thread_basic_info_reports_state() {
        let info = current_thread_basic_info().expect("current thread info should be readable");
        assert!((1..=5).contains(&info.run_state));
    }

    #[test]
    fn current_task_usage_combines_memory_and_cpu() {
        let usage = current_task_usage().expect("current task usage should be readable");
        assert!(usage.rss_bytes > 1_048_576);
        assert!(usage.virtual_memory_bytes >= usage.rss_bytes);
    }

    #[test]
    fn host_vm_stats_reports_plausible_page_accounting() {
        let stats = host_vm_stats().expect("host VM stats should be readable");
        assert!(stats.page_size_bytes >= 4096);
        assert!(stats.accounted_pages() > 0);
        assert!(stats.active_count.saturating_add(stats.wire_count) > 0);
    }

    #[test]
    fn memory_pressure_event_mapping_prefers_strongest_flag() {
        assert_eq!(
            MemoryPressureEvent::from_dispatch_data(0x1),
            MemoryPressureEvent::Normal
        );
        assert_eq!(
            MemoryPressureEvent::from_dispatch_data(0x2),
            MemoryPressureEvent::Warn
        );
        assert_eq!(
            MemoryPressureEvent::from_dispatch_data(0x4),
            MemoryPressureEvent::Critical
        );
        assert_eq!(
            MemoryPressureEvent::from_dispatch_data(0x1 | 0x2 | 0x4),
            MemoryPressureEvent::Critical
        );
        assert_eq!(
            MemoryPressureEvent::from_dispatch_data(0x8),
            MemoryPressureEvent::Unknown(0x8)
        );
    }

    #[test]
    fn memory_pressure_source_constructs_and_cancels() {
        let source = subscribe_memory_pressure_events(|_| {}).expect("dispatch source should start");
        assert!(!source.is_canceled());
        drop(source);
    }
}
