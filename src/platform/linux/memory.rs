//! Linux memory readers for the PAL.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    let psi_avg10 = read_memory_psi_avg10().ok();
    Ok(memory_pressure_from_info(
        &info,
        psi_avg10,
        system_page_size_bytes(),
    ))
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
    let raw = fs::read_to_string(MEMORY_PSI_PATH).map_err(|source| SbhError::Io {
        path: PathBuf::from(MEMORY_PSI_PATH),
        source,
    })?;
    parse_memory_psi_avg10(&raw).ok_or_else(|| {
        PalError::method_failed(
            "linux",
            "memory_pressure",
            "missing 'some avg10=' in /proc/pressure/memory",
        )
        .into()
    })
}

fn parse_memory_psi_avg10(raw: &str) -> Option<u64> {
    raw.lines()
        .find_map(|line| line.strip_prefix("some "))
        .and_then(|rest| {
            rest.split_whitespace()
                .find_map(|field| field.strip_prefix("avg10="))
        })
        .and_then(parse_centipercent)
}

fn parse_centipercent(raw: &str) -> Option<u64> {
    let (whole, fractional) = raw.split_once('.').unwrap_or((raw, ""));
    let whole = whole.parse::<u64>().ok()?;
    let mut cents = fractional
        .chars()
        .take(2)
        .collect::<String>()
        .parse::<u64>()
        .unwrap_or(0);
    if fractional.len() == 1 {
        cents = cents.saturating_mul(10);
    }
    Some(whole.saturating_mul(100).saturating_add(cents))
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
    let initial = sampler()?;
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
            // The kernel removes the PSI trigger when its file descriptor closes.
            let _psi_fd = psi_fd;
            let mut last_level = initial.level;
            let mut events = [EpollEvent::empty()];
            loop {
                if weak_liveness.upgrade().is_none() {
                    break;
                }

                let count = match epoll.wait(&mut events, MEMORY_PRESSURE_EPOLL_TIMEOUT_MS) {
                    Ok(count) => count,
                    Err(Errno::EINTR) => continue,
                    Err(_) => break,
                };
                if count > 0 {
                    let flags = events[0].events();
                    if flags.intersects(EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP) {
                        break;
                    }
                    if !flags.contains(EpollFlags::EPOLLPRI) {
                        continue;
                    }
                } else if last_level == MemoryPressureLevel::Normal {
                    continue;
                }
                // The trigger fires only on stalls, so a host that goes
                // quiet after pressure never fires it again: above Normal,
                // the timeout samples too, or recovery would go unseen.

                let Ok(mut pressure) = sampler() else {
                    continue;
                };
                pressure.level = banded_level(last_level, pressure.linux_psi_avg10, pressure.level);
                if pressure.level != last_level {
                    last_level = pressure.level;
                    callback(pressure);
                }
            }
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
    let initial = sampler()?;
    let liveness = Arc::new(());
    let weak_liveness = Arc::downgrade(&liveness);
    let thread_name = format!("sbh-{source}");
    let thread = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            let mut last_level = initial.level;
            loop {
                std::thread::sleep(interval);
                if weak_liveness.upgrade().is_none() {
                    break;
                }
                let Ok(mut pressure) = sampler() else {
                    continue;
                };
                pressure.level = banded_level(last_level, pressure.linux_psi_avg10, pressure.level);
                if pressure.level != last_level {
                    last_level = pressure.level;
                    callback(pressure);
                }
            }
        })
        .map_err(|error| {
            PalError::method_failed("linux", "subscribe_memory_pressure", error.to_string())
        })?;
    drop(thread);

    Ok(SubscriptionHandle::active_with_liveness(source, liveness))
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
    fn memory_pressure_subscription_reports_level_transitions() {
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
