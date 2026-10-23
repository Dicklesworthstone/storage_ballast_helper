//! Linux memory readers for the PAL.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};

use crate::core::errors::{Result, SbhError};
use crate::platform::pal::MemoryInfo;
use crate::platform::types::{
    MemoryPressure, MemoryPressureCallback, MemoryPressureLevel, PalError, SubscriptionHandle,
};

const MEMORY_PSI_PATH: &str = "/proc/pressure/memory";
const MEMORY_PRESSURE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MEMORY_PRESSURE_EPOLL_TIMEOUT_MS: u16 = 1000;
const PSI_TRIGGER_WINDOW_US: u64 = 1_000_000;
const PSI_WARN_TRIGGER_STALL_US: u64 = 50_000;
const PSI_WARN_AVG10_CENTIPERCENT: u64 = 500;
const PSI_CRITICAL_AVG10_CENTIPERCENT: u64 = 2_000;

pub(super) fn read_memory_info() -> Result<MemoryInfo> {
    let raw = fs::read_to_string("/proc/meminfo").map_err(|source| SbhError::Io {
        path: PathBuf::from("/proc/meminfo"),
        source,
    })?;
    parse_meminfo(&raw)
}

pub(super) fn read_memory_pressure() -> Result<MemoryPressure> {
    let info = read_memory_info()?;
    Ok(memory_pressure_with_local(
        &info,
        read_memory_psi_avg10().ok(),
        super::cgroup::pressure::read(),
        system_page_size_bytes(),
    ))
}

/// Use the stronger observed stall signal, without adding percentages from
/// overlapping task populations. Byte/page counters remain host-wide. The PSI
/// value is the maximum known host/process-cgroup sample, also used by the exit
/// band. Missing v2 evidence can retain positive pressure but cannot say Normal.
fn memory_pressure_with_local(
    info: &MemoryInfo,
    host: Option<u64>,
    local: io::Result<Option<u64>>,
    page_size_bytes: u64,
) -> MemoryPressure {
    let complete = host.is_some() && local.is_ok();
    let strongest = host.into_iter().chain(local.ok().flatten()).max();
    let mut pressure = memory_pressure_from_info(info, strongest, page_size_bytes);
    if !complete && pressure.level == MemoryPressureLevel::Normal {
        pressure.level = MemoryPressureLevel::Unknown;
    }
    pressure
}

pub(super) fn subscribe_memory_pressure(
    callback: MemoryPressureCallback,
) -> Result<SubscriptionHandle> {
    let callback: Arc<dyn Fn(MemoryPressure) + Send + Sync + 'static> = Arc::from(callback);
    spawn_memory_pressure_epoll_subscription(Arc::clone(&callback), read_memory_pressure).or_else(
        |_| {
            let callback = Arc::clone(&callback);
            spawn_memory_pressure_subscription(
                "linux-memory-pressure-poll",
                MEMORY_PRESSURE_POLL_INTERVAL,
                Box::new(move |pressure| callback(pressure)),
                read_memory_pressure,
            )
        },
    )
}

pub(super) fn parse_meminfo(raw: &str) -> Result<MemoryInfo> {
    let mut values = HashMap::<String, u64>::new();

    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((key, rest)) = line.split_once(':') else {
            return Err(SbhError::MountParse {
                details: format!("invalid meminfo line (missing ':'): {line}"),
            });
        };
        let mut parts = rest.split_whitespace();
        let Some(value_raw) = parts.next() else {
            return Err(SbhError::MountParse {
                details: format!("missing meminfo value in line: {line}"),
            });
        };
        let value = value_raw
            .parse::<u64>()
            .map_err(|err| SbhError::MountParse {
                details: format!("invalid meminfo numeric value in line {line:?}: {err}"),
            })?;

        let bytes = match parts.next() {
            None => value,
            Some("kB") => value.saturating_mul(1024),
            Some(unit) => {
                return Err(SbhError::MountParse {
                    details: format!("unsupported meminfo unit in line {line:?}: {unit}"),
                });
            }
        };
        values.insert(key.trim().to_string(), bytes);
    }

    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| SbhError::MountParse {
                details: format!("missing required meminfo field: {key}"),
            })
    };

    Ok(MemoryInfo {
        total_bytes: required("MemTotal")?,
        available_bytes: required("MemAvailable")?,
        swap_total_bytes: required("SwapTotal")?,
        swap_free_bytes: required("SwapFree")?,
    })
}

fn read_memory_psi_avg10() -> Result<u64> {
    let mut raw = String::new();
    let limit = u64::try_from(super::cgroup::pressure::PSI_BYTES).unwrap_or(4096) + 1;
    File::open(MEMORY_PSI_PATH)
        .and_then(|file| file.take(limit).read_to_string(&mut raw))
        .map_err(|source| SbhError::Io {
            path: PathBuf::from(MEMORY_PSI_PATH),
            source,
        })?;
    parse_memory_psi_avg10(&raw).ok_or_else(|| {
        PalError::method_failed(
            "linux",
            "memory_pressure",
            "invalid or incomplete 'some' record in /proc/pressure/memory",
        )
        .into()
    })
}

fn parse_memory_psi_avg10(raw: &str) -> Option<u64> {
    super::cgroup::pressure::parse_avg10(raw)
}

fn memory_pressure_from_info(
    info: &MemoryInfo,
    psi_avg10_centipercent: Option<u64>,
    page_size_bytes: u64,
) -> MemoryPressure {
    let used_bytes = info.total_bytes.saturating_sub(info.available_bytes);
    let free_pages = info.available_bytes.checked_div(page_size_bytes);
    let used_pages = used_bytes.checked_div(page_size_bytes);
    let swap_used_bytes = info.swap_total_bytes.saturating_sub(info.swap_free_bytes);

    MemoryPressure {
        level: linux_pressure_level(psi_avg10_centipercent),
        free_pages,
        used_pages,
        page_size_bytes: Some(page_size_bytes),
        compressor_used_bytes: None,
        swap_total_bytes: Some(info.swap_total_bytes),
        swap_used_bytes: Some(swap_used_bytes),
        linux_psi_avg10: psi_avg10_centipercent,
    }
}

fn linux_pressure_level(psi_avg10_centipercent: Option<u64>) -> MemoryPressureLevel {
    match psi_avg10_centipercent {
        Some(avg10) if avg10 >= PSI_CRITICAL_AVG10_CENTIPERCENT => MemoryPressureLevel::Critical,
        Some(avg10) if avg10 >= PSI_WARN_AVG10_CENTIPERCENT => MemoryPressureLevel::Warn,
        Some(_) => MemoryPressureLevel::Normal,
        None => MemoryPressureLevel::Unknown,
    }
}

/// `level` with an exit band: a level is left only once PSI avg10 falls a
/// fifth below its threshold. avg10 hovering near 5% flipped the daemon
/// between Normal and Warn every 2-15 s on ts2 (2026-10-15, up to 31 behavior
/// changes an hour).
fn banded_level(
    previous: MemoryPressureLevel,
    psi_avg10_centipercent: Option<u64>,
    level: MemoryPressureLevel,
) -> MemoryPressureLevel {
    let Some(avg10) = psi_avg10_centipercent else {
        return level;
    };
    let holds = |threshold: u64| avg10 >= threshold - threshold / 5;
    match (previous, level) {
        (
            MemoryPressureLevel::Critical,
            MemoryPressureLevel::Warn | MemoryPressureLevel::Normal,
        ) if holds(PSI_CRITICAL_AVG10_CENTIPERCENT) => MemoryPressureLevel::Critical,
        (
            MemoryPressureLevel::Critical | MemoryPressureLevel::Warn,
            MemoryPressureLevel::Normal,
        ) if holds(PSI_WARN_AVG10_CENTIPERCENT) => MemoryPressureLevel::Warn,
        _ => level,
    }
}

fn system_page_size_bytes() -> u64 {
    nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .ok()
        .flatten()
        .and_then(|size| u64::try_from(size).ok())
        .filter(|size| *size > 0)
        .unwrap_or(4096)
}

fn memory_psi_trigger_spec() -> String {
    format!("some {PSI_WARN_TRIGGER_STALL_US} {PSI_TRIGGER_WINDOW_US}")
}

fn open_memory_psi_trigger(path: &Path, trigger: &str) -> Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    let mut trigger_bytes = trigger.as_bytes().to_vec();
    trigger_bytes.push(0);
    file.write_all(&trigger_bytes)
        .map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(file)
}

fn spawn_memory_pressure_epoll_subscription<F>(
    callback: Arc<dyn Fn(MemoryPressure) + Send + Sync + 'static>,
    sampler: F,
) -> Result<SubscriptionHandle>
where
    F: Fn() -> Result<MemoryPressure> + Send + 'static,
{
    let initial = sampler().unwrap_or_else(|_| unknown_memory_pressure());
    let trigger = memory_psi_trigger_spec();
    let psi_fd = open_memory_psi_trigger(Path::new(MEMORY_PSI_PATH), &trigger)?;
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).map_err(|error| {
        PalError::method_failed("linux", "subscribe_memory_pressure", error.to_string())
    })?;
    epoll
        .add(
            &psi_fd,
            EpollEvent::new(
                EpollFlags::EPOLLPRI | EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP,
                1,
            ),
        )
        .map_err(|error| {
            PalError::method_failed("linux", "subscribe_memory_pressure", error.to_string())
        })?;

    let liveness = Arc::new(());
    let weak_liveness = Arc::downgrade(&liveness);
    let thread = std::thread::Builder::new()
        .name("sbh-linux-memory-pressure-psi-epoll".to_string())
        .spawn(move || {
            let mut source = Some((epoll, psi_fd));
            pressure_subscription_loop(
                initial,
                &weak_liveness,
                || {
                    wait_for_pressure(
                        &mut source,
                        |(epoll, _)| {
                            let mut events = [EpollEvent::empty()];
                            let result = epoll.wait(&mut events, MEMORY_PRESSURE_EPOLL_TIMEOUT_MS);
                            epoll_wake(result, events[0].events())
                        },
                        std::thread::sleep,
                    )
                },
                sampler,
                |pressure| callback(pressure),
            );
        })
        .map_err(|error| {
            PalError::method_failed("linux", "subscribe_memory_pressure", error.to_string())
        })?;
    drop(thread);

    Ok(SubscriptionHandle::active_with_liveness(
        "linux-memory-pressure-psi-epoll",
        liveness,
    ))
}

fn spawn_memory_pressure_subscription<F>(
    source: &'static str,
    interval: Duration,
    callback: MemoryPressureCallback,
    sampler: F,
) -> Result<SubscriptionHandle>
where
    F: Fn() -> Result<MemoryPressure> + Send + 'static,
{
    let initial = sampler().unwrap_or_else(|_| unknown_memory_pressure());
    let liveness = Arc::new(());
    let weak_liveness = Arc::downgrade(&liveness);
    let thread_name = format!("sbh-{source}");
    let thread = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            pressure_subscription_loop(
                initial,
                &weak_liveness,
                || {
                    std::thread::sleep(interval);
                    true
                },
                sampler,
                callback,
            );
        })
        .map_err(|error| {
            PalError::method_failed("linux", "subscribe_memory_pressure", error.to_string())
        })?;
    drop(thread);

    Ok(SubscriptionHandle::active_with_liveness(source, liveness))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PressureWake {
    Sample,
    Interrupted,
    Failed,
}

fn epoll_wake(result: std::result::Result<usize, Errno>, flags: EpollFlags) -> PressureWake {
    match result {
        Ok(0) => PressureWake::Sample,
        Ok(1)
            if flags.contains(EpollFlags::EPOLLPRI)
                && !flags.intersects(EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP) =>
        {
            PressureWake::Sample
        }
        Err(Errno::EINTR) => PressureWake::Interrupted,
        _ => PressureWake::Failed,
    }
}

/// A broken event source is dropped once, including its trigger descriptor.
/// The same worker then samples on paced timeouts; no retry/spawn loop is needed.
fn wait_for_pressure<S>(
    source: &mut Option<S>,
    wait: impl FnOnce(&S) -> PressureWake,
    delay: impl FnOnce(Duration),
) -> bool {
    let Some(active) = source.as_ref() else {
        delay(MEMORY_PRESSURE_POLL_INTERVAL);
        return true;
    };
    match wait(active) {
        PressureWake::Sample => true,
        PressureWake::Interrupted => false,
        PressureWake::Failed => {
            // Closing the fd deregisters the kernel PSI trigger. First sample
            // immediately; all subsequent waits use the polling interval.
            *source = None;
            true
        }
    }
}

fn unknown_memory_pressure() -> MemoryPressure {
    MemoryPressure {
        level: MemoryPressureLevel::Unknown,
        free_pages: None,
        used_pages: None,
        page_size_bytes: None,
        compressor_used_bytes: None,
        swap_total_bytes: None,
        swap_used_bytes: None,
        linux_psi_avg10: None,
    }
}

/// Both event-backed and polling subscriptions use the same coverage/lifetime
/// rules. Failed samples cannot leave a stale Normal verdict latched forever.
/// Always deliver the subscription's initial observation: the daemon's earlier
/// startup sample may differ, and a steady level would otherwise never correct
/// it. After that handoff, deliver level changes only.
fn pressure_subscription_loop(
    initial: MemoryPressure,
    liveness: &Weak<()>,
    mut wait: impl FnMut() -> bool,
    mut sampler: impl FnMut() -> Result<MemoryPressure>,
    mut callback: impl FnMut(MemoryPressure),
) {
    let mut last_level = initial.level;
    if liveness.upgrade().is_some() {
        callback(initial);
    }
    while liveness.upgrade().is_some() {
        if !wait() {
            continue;
        }
        if liveness.upgrade().is_none() {
            break;
        }
        let mut pressure = sampler().unwrap_or_else(|_| unknown_memory_pressure());
        // A slow sample may finish after shutdown. Do not publish that late
        // observation or acquire another sample on an abandoned subscription.
        if liveness.upgrade().is_none() {
            break;
        }
        pressure.level = banded_level(last_level, pressure.linux_psi_avg10, pressure.level);
        if pressure.level != last_level {
            last_level = pressure.level;
            callback(pressure);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, mpsc};

    use crate::core::errors::SbhError;
    use crate::platform::types::{MemoryPressure, MemoryPressureLevel};

    use super::{
        banded_level, memory_pressure_from_info, memory_psi_trigger_spec, parse_meminfo,
        parse_memory_psi_avg10, spawn_memory_pressure_subscription,
    };

    #[test]
    fn levels_are_left_only_a_fifth_below_their_threshold() {
        use MemoryPressureLevel::{Critical, Normal, Unknown, Warn};
        let banded = |previous, avg10: u64, level| banded_level(previous, Some(avg10), level);
        // Entering is unchanged.
        assert_eq!(banded(Normal, 500, Warn), Warn);
        assert_eq!(banded(Warn, 2_000, Critical), Critical);
        // Warn holds down to 4%, then recovers.
        assert_eq!(banded(Warn, 450, Normal), Warn);
        assert_eq!(banded(Warn, 400, Normal), Warn);
        assert_eq!(banded(Warn, 399, Normal), Normal);
        // Critical holds down to 16%, then falls to the level PSI shows,
        // still banded against Warn.
        assert_eq!(banded(Critical, 1_700, Warn), Critical);
        assert_eq!(banded(Critical, 1_599, Warn), Warn);
        assert_eq!(banded(Critical, 450, Normal), Warn);
        assert_eq!(banded(Critical, 100, Normal), Normal);
        // No PSI, or no prior level, means no band.
        assert_eq!(banded_level(Warn, None, Normal), Normal);
        assert_eq!(banded(Unknown, 450, Normal), Normal);
    }

    #[test]
    fn parses_meminfo_with_kib_units() {
        let info = parse_meminfo(
            "MemTotal:       32768000 kB\n\
             MemAvailable:   16384000 kB\n\
             SwapTotal:       8192000 kB\n\
             SwapFree:        4096000 kB\n",
        )
        .expect("meminfo should parse");
        assert_eq!(info.total_bytes, 33_554_432_000);
        assert_eq!(info.available_bytes, 16_777_216_000);
        assert_eq!(info.swap_total_bytes, 8_388_608_000);
        assert_eq!(info.swap_free_bytes, 4_194_304_000);
    }

    #[test]
    fn parses_meminfo_without_unit_suffix() {
        let info = parse_meminfo(
            "MemTotal:       1024 kB\n\
             MemAvailable:   512 kB\n\
             SwapTotal:      0\n\
             SwapFree:       0\n",
        )
        .expect("meminfo should parse");
        assert_eq!(info.total_bytes, 1_048_576);
        assert_eq!(info.available_bytes, 524_288);
        assert_eq!(info.swap_total_bytes, 0);
        assert_eq!(info.swap_free_bytes, 0);
    }

    #[test]
    fn rejects_meminfo_with_unknown_unit_suffix() {
        let error = parse_meminfo(
            "MemTotal:       1024 blocks\n\
             MemAvailable:   512 kB\n\
             SwapTotal:      0 kB\n\
             SwapFree:       0 kB\n",
        )
        .expect_err("unknown unit suffix should fail");

        assert!(
            matches!(error, SbhError::MountParse { .. }),
            "expected mount-parse error, got: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("unsupported meminfo unit in line"),
            "expected unsupported-unit context, got: {error}"
        );
    }

    #[test]
    fn parses_memory_psi_avg10_as_centipercent() {
        let raw = "some avg10=12.34 avg60=5.67 avg300=1.23 total=456\n\
                   full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(parse_memory_psi_avg10(raw), Some(1_234));
    }

    #[test]
    fn maps_linux_psi_avg10_to_pressure_levels() {
        let info = parse_meminfo(
            "MemTotal:       32768000 kB\n\
             MemAvailable:   16384000 kB\n\
             SwapTotal:       8192000 kB\n\
             SwapFree:        4096000 kB\n",
        )
        .expect("meminfo should parse");

        assert_eq!(
            memory_pressure_from_info(&info, Some(499), 4096).level,
            MemoryPressureLevel::Normal
        );
        assert_eq!(
            memory_pressure_from_info(&info, Some(500), 4096).level,
            MemoryPressureLevel::Warn
        );
        assert_eq!(
            memory_pressure_from_info(&info, Some(2_000), 4096).level,
            MemoryPressureLevel::Critical
        );
        assert_eq!(
            memory_pressure_from_info(&info, None, 4096).level,
            MemoryPressureLevel::Unknown
        );
    }

    #[test]
    fn memory_psi_trigger_spec_tracks_warn_threshold() {
        assert_eq!(memory_psi_trigger_spec(), "some 50000 1000000");
    }

    #[test]
    fn subscribe_memory_pressure_uses_epoll_or_polling_fallback() {
        let handle = super::subscribe_memory_pressure(Box::new(|_| {}))
            .expect("memory pressure subscription should start or fall back");
        assert!(
            matches!(
                handle.source.as_str(),
                "linux-memory-pressure-psi-epoll" | "linux-memory-pressure-poll"
            ),
            "unexpected subscription source: {}",
            handle.source
        );
    }

    #[test]
    fn memory_pressure_subscription_reports_initial_state_and_level_transitions() {
        let samples = Arc::new(Mutex::new(VecDeque::from([
            test_memory_pressure(MemoryPressureLevel::Normal),
            test_memory_pressure(MemoryPressureLevel::Warn),
            test_memory_pressure(MemoryPressureLevel::Warn),
            test_memory_pressure(MemoryPressureLevel::Critical),
        ])));
        let sampler_samples = Arc::clone(&samples);
        let (tx, rx) = mpsc::channel();

        let handle = spawn_memory_pressure_subscription(
            "linux-memory-pressure-test",
            std::time::Duration::from_millis(10),
            Box::new(move |pressure| {
                tx.send(pressure.level)
                    .expect("receiver should remain open for test");
            }),
            move || {
                Ok(sampler_samples
                    .lock()
                    .expect("samples mutex should not be poisoned")
                    .pop_front()
                    .unwrap_or_else(|| test_memory_pressure(MemoryPressureLevel::Critical)))
            },
        )
        .expect("subscription should start");

        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .expect("subscription's initial state should arrive"),
            MemoryPressureLevel::Normal
        );
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .expect("warn transition should arrive"),
            MemoryPressureLevel::Warn
        );
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .expect("critical transition should arrive"),
            MemoryPressureLevel::Critical
        );
        drop(handle);
    }

    #[test]
    fn local_stalls_raise_pressure_without_rewriting_host_capacity() {
        let info = super::MemoryInfo {
            total_bytes: 1024 * 1024,
            available_bytes: 512 * 1024,
            swap_total_bytes: 8192,
            swap_free_bytes: 4096,
        };
        let host = memory_pressure_from_info(&info, Some(0), 4096);
        let local = super::memory_pressure_with_local(&info, Some(0), Ok(Some(7350)), 4096);
        assert_eq!(local.level, MemoryPressureLevel::Critical);
        assert_eq!(local.linux_psi_avg10, Some(7350));
        assert_eq!(local.free_pages, host.free_pages);
        assert_eq!(local.used_pages, host.used_pages);
        assert_eq!(local.swap_total_bytes, host.swap_total_bytes);
        assert_eq!(local.swap_used_bytes, host.swap_used_bytes);
        let host_pressure =
            super::memory_pressure_with_local(&info, Some(2500), Ok(Some(500)), 4096);
        assert_eq!(
            host_pressure.linux_psi_avg10,
            Some(2500),
            "do not add overlapping PSI percentages"
        );
        assert_eq!(host_pressure.level, MemoryPressureLevel::Critical);
    }

    #[test]
    fn missing_v2_evidence_is_unknown_unless_a_known_signal_already_shows_pressure() {
        let info = super::MemoryInfo {
            total_bytes: 100,
            available_bytes: 50,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        };
        for (host, local, expected) in [
            (
                Some(0),
                Err(std::io::ErrorKind::PermissionDenied.into()),
                MemoryPressureLevel::Unknown,
            ),
            (
                Some(500),
                Err(std::io::ErrorKind::PermissionDenied.into()),
                MemoryPressureLevel::Warn,
            ),
            (
                Some(2000),
                Err(std::io::ErrorKind::PermissionDenied.into()),
                MemoryPressureLevel::Critical,
            ),
            (None, Ok(Some(0)), MemoryPressureLevel::Unknown),
            (None, Ok(Some(2000)), MemoryPressureLevel::Critical),
            (Some(0), Ok(None), MemoryPressureLevel::Normal),
            (None, Ok(None), MemoryPressureLevel::Unknown),
        ] {
            assert_eq!(
                super::memory_pressure_with_local(&info, host, local, 1).level,
                expected
            );
        }
    }

    #[test]
    fn exit_band_uses_local_stalls_even_when_the_host_is_quiet() {
        let info = super::MemoryInfo {
            total_bytes: 100,
            available_bytes: 50,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        };
        let mut last = MemoryPressureLevel::Critical;
        for (local, expected) in [
            (1700, MemoryPressureLevel::Critical),
            (450, MemoryPressureLevel::Warn),
            (399, MemoryPressureLevel::Normal),
        ] {
            let sample = super::memory_pressure_with_local(&info, Some(0), Ok(Some(local)), 1);
            last = banded_level(last, sample.linux_psi_avg10, sample.level);
            assert_eq!(last, expected);
        }
    }

    fn subscription_updates(
        initial: MemoryPressure,
        samples: Vec<super::Result<MemoryPressure>>,
    ) -> Vec<MemoryPressure> {
        use std::cell::RefCell;

        let owner = RefCell::new(Some(Arc::new(())));
        let liveness = Arc::downgrade(owner.borrow().as_ref().unwrap());
        let samples = RefCell::new(VecDeque::from(samples));
        let updates = RefCell::new(Vec::new());
        let mut source = Some(());
        super::pressure_subscription_loop(
            initial,
            &liveness,
            || {
                if samples.borrow().is_empty() {
                    drop(owner.borrow_mut().take());
                }
                super::wait_for_pressure(
                    &mut source,
                    |()| super::epoll_wake(Ok(0), super::EpollFlags::empty()),
                    |_| panic!("a live timeout must not discard its event source"),
                )
            },
            || samples.borrow_mut().pop_front().unwrap(),
            |pressure| updates.borrow_mut().push(pressure),
        );
        updates.into_inner()
    }

    fn unavailable_sample() -> super::Result<MemoryPressure> {
        Err(SbhError::MountParse {
            details: "injected memory read failure".to_owned(),
        })
    }

    #[test]
    fn a_steady_subscription_corrects_a_different_daemon_startup_sample_once() {
        for (daemon_seed, subscription_seed) in [
            (MemoryPressureLevel::Normal, MemoryPressureLevel::Critical),
            (MemoryPressureLevel::Unknown, MemoryPressureLevel::Normal),
            (MemoryPressureLevel::Critical, MemoryPressureLevel::Normal),
        ] {
            let updates = subscription_updates(
                test_memory_pressure(subscription_seed),
                (0..3)
                    .map(|_| Ok(test_memory_pressure(subscription_seed)))
                    .collect(),
            );
            // The consumer already has its daemon startup sample. The live
            // subscription must correct it even if every later read is steady.
            let mut observed = daemon_seed;
            for sample in &updates {
                observed = sample.level;
            }
            assert_eq!(observed, subscription_seed, "startup was {daemon_seed:?}");
            assert_eq!(updates.len(), 1, "steady samples must not spam callbacks");
            assert_eq!(updates[0].free_pages, Some(10));
            assert_eq!(updates[0].used_pages, Some(90));
        }
    }

    #[test]
    fn idle_subscription_reports_local_only_stalls_and_banded_recovery() {
        let info = super::MemoryInfo {
            total_bytes: 100,
            available_bytes: 50,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        };
        let samples = [7350, 1700, 450, 399]
            .into_iter()
            .map(|local| {
                Ok(super::memory_pressure_with_local(
                    &info,
                    Some(0),
                    Ok(Some(local)),
                    1,
                ))
            })
            .collect();
        let updates =
            subscription_updates(test_memory_pressure(MemoryPressureLevel::Normal), samples);
        assert_eq!(
            updates
                .iter()
                .map(|sample| sample.level)
                .collect::<Vec<_>>(),
            vec![
                MemoryPressureLevel::Normal,
                MemoryPressureLevel::Critical,
                MemoryPressureLevel::Warn,
                MemoryPressureLevel::Normal,
            ]
        );
        assert_eq!(
            updates
                .iter()
                .map(|sample| sample.linux_psi_avg10)
                .collect::<Vec<_>>(),
            vec![None, Some(7350), Some(450), Some(399),]
        );
    }

    #[test]
    fn failed_samples_emit_unknown_once_then_report_recovery_without_stale_counters() {
        let updates = subscription_updates(
            test_memory_pressure(MemoryPressureLevel::Normal),
            vec![
                unavailable_sample(),
                unavailable_sample(),
                Ok(test_memory_pressure(MemoryPressureLevel::Normal)),
                Ok(test_memory_pressure(MemoryPressureLevel::Normal)),
            ],
        );
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0].level, MemoryPressureLevel::Normal);
        assert_eq!(updates[1].level, MemoryPressureLevel::Unknown);
        assert!(updates[1].free_pages.is_none());
        assert!(updates[1].used_pages.is_none());
        assert!(updates[1].page_size_bytes.is_none());
        assert!(updates[1].swap_total_bytes.is_none());
        assert!(updates[1].swap_used_bytes.is_none());
        assert!(updates[1].linux_psi_avg10.is_none());
        assert_eq!(updates[2].level, MemoryPressureLevel::Normal);
        assert_eq!(updates[2].free_pages, Some(10));
    }

    #[test]
    fn lost_event_source_is_dropped_once_and_replaced_by_paced_sampling() {
        use std::cell::{Cell, RefCell};

        struct Trigger<'a>(&'a Cell<usize>);
        impl Drop for Trigger<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let calls = Cell::new(0);
        let delays = RefCell::new(Vec::new());
        let mut source = Some(Trigger(&drops));
        for _ in 0..3 {
            assert!(super::wait_for_pressure(
                &mut source,
                |_| {
                    calls.set(calls.get() + 1);
                    super::epoll_wake(Err(super::Errno::EIO), super::EpollFlags::empty())
                },
                |interval| delays.borrow_mut().push(interval),
            ));
        }
        assert!(source.is_none());
        assert_eq!(drops.get(), 1);
        assert_eq!(
            calls.get(),
            1,
            "never retry a permanently failed event source"
        );
        assert_eq!(*delays.borrow(), vec![std::time::Duration::from_secs(1); 2]);
    }

    #[test]
    fn epoll_timeouts_and_faults_have_distinct_subscription_actions() {
        use super::{EpollFlags, Errno, PressureWake, epoll_wake};

        assert_eq!(epoll_wake(Ok(0), EpollFlags::empty()), PressureWake::Sample);
        assert_eq!(
            epoll_wake(Ok(1), EpollFlags::EPOLLPRI),
            PressureWake::Sample
        );
        assert_eq!(
            epoll_wake(Err(Errno::EINTR), EpollFlags::empty()),
            PressureWake::Interrupted
        );
        for flags in [
            EpollFlags::EPOLLERR,
            EpollFlags::EPOLLHUP,
            EpollFlags::EPOLLPRI | EpollFlags::EPOLLERR,
            EpollFlags::empty(),
        ] {
            assert_eq!(epoll_wake(Ok(1), flags), PressureWake::Failed);
        }
        assert_eq!(
            epoll_wake(Err(Errno::EBADF), EpollFlags::empty()),
            PressureWake::Failed
        );
    }

    #[test]
    fn interrupted_wait_keeps_the_source_without_sampling_or_entering_fallback() {
        let mut source = Some(());
        assert!(!super::wait_for_pressure(
            &mut source,
            |()| super::epoll_wake(Err(super::Errno::EINTR), super::EpollFlags::empty()),
            |_| panic!("EINTR is not a broken event source"),
        ));
        assert!(source.is_some());
    }

    #[test]
    fn shutdown_during_wait_does_not_start_another_sample() {
        let mut owner = Some(Arc::new(()));
        let liveness = Arc::downgrade(owner.as_ref().unwrap());
        let mut updates = Vec::new();
        super::pressure_subscription_loop(
            test_memory_pressure(MemoryPressureLevel::Normal),
            &liveness,
            || {
                drop(owner.take());
                true
            },
            || panic!("subscription ended while waiting"),
            |pressure| updates.push(pressure.level),
        );
        assert_eq!(updates, vec![MemoryPressureLevel::Normal]);
    }

    #[test]
    fn shutdown_during_sampling_discards_the_late_result() {
        let mut owner = Some(Arc::new(()));
        let liveness = Arc::downgrade(owner.as_ref().unwrap());
        let mut updates = Vec::new();
        super::pressure_subscription_loop(
            test_memory_pressure(MemoryPressureLevel::Normal),
            &liveness,
            || true,
            || {
                drop(owner.take());
                Ok(test_memory_pressure(MemoryPressureLevel::Critical))
            },
            |pressure| updates.push(pressure.level),
        );
        assert_eq!(updates, vec![MemoryPressureLevel::Normal]);
    }

    #[test]
    fn shutdown_before_subscription_start_discards_even_the_initial_sample() {
        let owner = Arc::new(());
        let liveness = Arc::downgrade(&owner);
        drop(owner);
        super::pressure_subscription_loop(
            test_memory_pressure(MemoryPressureLevel::Critical),
            &liveness,
            || panic!("an abandoned subscription must not wait"),
            || panic!("an abandoned subscription must not sample"),
            |_| panic!("an abandoned subscription must not publish its seed"),
        );
    }

    #[test]
    fn shutdown_from_initial_callback_stops_before_waiting_or_sampling() {
        let mut owner = Some(Arc::new(()));
        let liveness = Arc::downgrade(owner.as_ref().unwrap());
        let mut updates = Vec::new();
        super::pressure_subscription_loop(
            test_memory_pressure(MemoryPressureLevel::Critical),
            &liveness,
            || panic!("initial callback ended the subscription before waiting"),
            || panic!("initial callback ended the subscription before sampling"),
            |pressure| {
                updates.push(pressure.level);
                drop(owner.take());
            },
        );
        assert_eq!(updates, vec![MemoryPressureLevel::Critical]);
    }

    #[test]
    fn polling_subscription_survives_an_unreadable_initial_sample() {
        let samples = Arc::new(Mutex::new(VecDeque::from([
            unavailable_sample(),
            Ok(test_memory_pressure(MemoryPressureLevel::Normal)),
        ])));
        let (tx, rx) = mpsc::channel();
        let handle = spawn_memory_pressure_subscription(
            "linux-memory-pressure-recovery-test",
            std::time::Duration::from_millis(1),
            Box::new(move |pressure| {
                let _ = tx.send(pressure.level);
            }),
            move || {
                samples
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Ok(test_memory_pressure(MemoryPressureLevel::Normal)))
            },
        )
        .expect("a transient read failure must not prevent the subscription from starting");
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            MemoryPressureLevel::Unknown
        );
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            MemoryPressureLevel::Normal
        );
        drop(handle);
    }

    fn test_memory_pressure(level: MemoryPressureLevel) -> MemoryPressure {
        MemoryPressure {
            level,
            free_pages: Some(10),
            used_pages: Some(90),
            page_size_bytes: Some(4096),
            compressor_used_bytes: None,
            swap_total_bytes: Some(0),
            swap_used_bytes: Some(0),
            linux_psi_avg10: None,
        }
    }
}
