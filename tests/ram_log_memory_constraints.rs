//! Exercise RAM-log admission through the real shared policy and PAL dispatch.
//!
//! Deterministic local-limit evidence avoids changing the test runner's cgroups.
//! These tests verify policy integration, not the native cgroup filesystem ABI.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use storage_ballast_helper::core::errors::Result;
use storage_ballast_helper::monitor::ram_scratch::{
    RamLogHeadroom, ram_log_mirror_refusal, ram_log_mirror_refusal_for,
};
use storage_ballast_helper::platform::pal::{
    FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
};
use storage_ballast_helper::platform::test_overlay::{InjectedFsTable, TestOverlayPlatform};
use storage_ballast_helper::platform::types::PalError;

const LOG: &str = "/scratch/activity.jsonl";

struct LocalMemory {
    ram: bool,
    readonly: bool,
    host_available: u64,
    mount_available: u64,
    classification_error: bool,
    host_error: bool,
    local_available: AtomicU8,
    local_error: AtomicBool,
    local_queries: Mutex<Vec<u8>>,
    host_queries: AtomicUsize,
}

impl Default for LocalMemory {
    fn default() -> Self {
        Self {
            ram: true,
            readonly: false,
            host_available: 50,
            mount_available: 50,
            classification_error: false,
            host_error: false,
            local_available: AtomicU8::new(50),
            local_error: AtomicBool::new(false),
            local_queries: Mutex::new(Vec::new()),
            host_queries: AtomicUsize::new(0),
        }
    }
}

impl Platform for LocalMemory {
    fn name(&self) -> &'static str {
        "local-memory-fixture"
    }

    fn fs_stats(&self, _: &Path) -> Result<FsStats> {
        Ok(FsStats {
            total_bytes: 100,
            free_bytes: self.mount_available,
            available_bytes: self.mount_available,
            fs_type: if self.ram { "tmpfs" } else { "ext4" }.to_owned(),
            mount_point: PathBuf::from("/scratch"),
            is_readonly: self.readonly,
        })
    }

    fn mount_points(&self) -> Result<Vec<MountPoint>> {
        Ok(Vec::new())
    }

    fn is_ram_backed(&self, _: &Path) -> Result<bool> {
        if self.classification_error {
            return Err(PalError::method_failed(
                self.name(),
                "is_ram_backed",
                "unknown filesystem",
            )
            .into());
        }
        Ok(self.ram)
    }

    fn default_paths(&self) -> PlatformPaths {
        PlatformPaths::default()
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        self.host_queries.fetch_add(1, Ordering::SeqCst);
        if self.host_error {
            return Err(
                PalError::method_failed(self.name(), "memory_info", "host unavailable").into(),
            );
        }
        Ok(MemoryInfo {
            total_bytes: 100,
            available_bytes: self.host_available,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        })
    }

    fn service_manager(&self) -> Box<dyn ServiceManager> {
        panic!("memory admission must not control services")
    }

    fn ram_write_memory_refusal(&self, minimum_available_percent: u8) -> Result<Option<String>> {
        self.local_queries
            .lock()
            .unwrap()
            .push(minimum_available_percent);
        if self.local_error.load(Ordering::SeqCst) {
            return Err(PalError::method_failed(
                self.name(),
                "ram_write_memory_refusal",
                "cgroup evidence denied",
            )
            .into());
        }
        Ok(
            (self.local_available.load(Ordering::SeqCst) < minimum_available_percent)
                .then(|| "cgroup memory.max lacks headroom".to_owned()),
        )
    }
}

#[test]
fn healthy_host_does_not_override_process_local_memory_refusal() {
    let platform = LocalMemory::default();
    let host = platform.memory_info().unwrap();
    platform.local_available.store(1, Ordering::SeqCst);
    assert_eq!(
        ram_log_mirror_refusal(&platform, Path::new(LOG)).as_deref(),
        Some("cgroup memory.max lacks headroom"),
    );
    assert_eq!(
        platform.memory_info().unwrap(),
        host,
        "local limits must not rewrite host counters"
    );
    assert_eq!(*platform.local_queries.lock().unwrap(), vec![10]);
}

#[test]
fn unreadable_local_limits_refuse_both_admission_modes() {
    let platform = LocalMemory::default();
    platform.local_error.store(true, Ordering::SeqCst);
    for headroom in [RamLogHeadroom::Keep, RamLogHeadroom::Start] {
        let reason = ram_log_mirror_refusal_for(&platform, Path::new(LOG), headroom).unwrap();
        assert!(
            reason.starts_with("process memory limits are unreadable:"),
            "{reason}"
        );
        assert!(reason.contains("cgroup evidence denied"), "{reason}");
    }
    assert_eq!(*platform.local_queries.lock().unwrap(), vec![10, 15]);
}

#[test]
fn local_start_margin_and_keep_floor_are_distinct() {
    let platform = LocalMemory::default();
    platform.local_available.store(12, Ordering::SeqCst);
    assert!(ram_log_mirror_refusal_for(&platform, Path::new(LOG), RamLogHeadroom::Keep).is_none());
    assert!(ram_log_mirror_refusal_for(&platform, Path::new(LOG), RamLogHeadroom::Start).is_some());
    platform.local_available.store(15, Ordering::SeqCst);
    assert!(ram_log_mirror_refusal_for(&platform, Path::new(LOG), RamLogHeadroom::Start).is_none());
    assert_eq!(*platform.local_queries.lock().unwrap(), vec![10, 15, 15]);
}

#[test]
fn verified_disk_routes_do_not_query_host_or_local_memory() {
    let platform = LocalMemory {
        ram: false,
        host_error: true,
        local_error: AtomicBool::new(true),
        ..LocalMemory::default()
    };
    for headroom in [RamLogHeadroom::Keep, RamLogHeadroom::Start] {
        assert!(ram_log_mirror_refusal_for(&platform, Path::new(LOG), headroom).is_none());
    }
    assert_eq!(platform.host_queries.load(Ordering::SeqCst), 0);
    assert!(platform.local_queries.lock().unwrap().is_empty());
}

#[test]
fn existing_host_and_destination_refusals_avoid_local_io() {
    for platform in [
        LocalMemory {
            host_available: 1,
            ..LocalMemory::default()
        },
        LocalMemory {
            mount_available: 1,
            ..LocalMemory::default()
        },
        LocalMemory {
            readonly: true,
            ..LocalMemory::default()
        },
        LocalMemory {
            host_error: true,
            ..LocalMemory::default()
        },
        LocalMemory {
            classification_error: true,
            ..LocalMemory::default()
        },
    ] {
        assert!(ram_log_mirror_refusal(&platform, Path::new(LOG)).is_some());
        assert!(platform.local_queries.lock().unwrap().is_empty());
    }
}

#[test]
fn local_pressure_and_missing_evidence_can_recover_on_the_next_check() {
    let platform = LocalMemory::default();
    assert!(ram_log_mirror_refusal(&platform, Path::new(LOG)).is_none());
    platform.local_available.store(0, Ordering::SeqCst);
    assert!(
        ram_log_mirror_refusal(&platform, Path::new(LOG))
            .unwrap()
            .contains("memory.max")
    );
    platform.local_error.store(true, Ordering::SeqCst);
    platform.local_available.store(50, Ordering::SeqCst);
    assert!(
        ram_log_mirror_refusal(&platform, Path::new(LOG))
            .unwrap()
            .contains("unreadable")
    );
    platform.local_error.store(false, Ordering::SeqCst);
    assert!(ram_log_mirror_refusal(&platform, Path::new(LOG)).is_none());
    assert_eq!(
        *platform.local_queries.lock().unwrap(),
        vec![10, 10, 10, 10]
    );
}

#[test]
fn nested_filesystem_overlays_preserve_local_limits_errors_and_margins() {
    let inner = Arc::new(LocalMemory::default());
    inner.local_available.store(12, Ordering::SeqCst);
    let first = Arc::new(TestOverlayPlatform::new(
        inner.clone(),
        InjectedFsTable::default(),
    ));
    let outer = TestOverlayPlatform::new(first, InjectedFsTable::default());
    assert!(ram_log_mirror_refusal_for(&outer, Path::new(LOG), RamLogHeadroom::Keep).is_none());
    assert!(ram_log_mirror_refusal_for(&outer, Path::new(LOG), RamLogHeadroom::Start).is_some());
    inner.local_error.store(true, Ordering::SeqCst);
    let reason = ram_log_mirror_refusal(&outer, Path::new(LOG)).unwrap();
    assert!(reason.contains("cgroup evidence denied"));
    assert_eq!(*inner.local_queries.lock().unwrap(), vec![10, 15, 10]);
    assert_eq!(outer.memory_info().unwrap().total_bytes, 100);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_pal_dispatches_to_the_native_guard_instead_of_the_default() {
    use storage_ballast_helper::platform::linux::LinuxPal;

    // Invalid percentages fail before any native file reads. This verifies
    // dispatch without requiring or mutating the runner's cgroup environment.
    for percent in [0, 101] {
        let error = LinuxPal::new()
            .ram_write_memory_refusal(percent)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid memory headroom percentage"),
            "{error}"
        );
    }
}
