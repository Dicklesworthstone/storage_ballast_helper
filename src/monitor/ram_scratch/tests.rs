use super::*;

const GIB: u64 = 1024 * 1024 * 1024;

fn memory(ram: u64, swap: u64, free: u64) -> MemoryInfo {
    MemoryInfo {
        total_bytes: ram * GIB,
        available_bytes: ram * GIB / 4,
        swap_total_bytes: swap * GIB,
        swap_free_bytes: free * GIB,
    }
}

fn mount(path: &str, id: u64, total: u64, used: u64) -> ScratchMount {
    ScratchMount {
        path: path.into(),
        filesystem_id: id,
        total_bytes: total * GIB,
        used_bytes: used * GIB,
        available_bytes: (total - used) * GIB,
    }
}

fn process_swap(gib: u64) -> ProcessSwap {
    ProcessSwap {
        bytes: gib * GIB,
        inspected: 42,
        unreadable: 0,
        complete: true,
    }
}

#[test]
fn fmd_fixture_produces_one_host_warning_naming_all_four_mounts() {
    let assessment = assess(
        memory(62, 64, 0),
        vec![
            mount("/dev/shm", 1, 32, 26),
            mount("/tmp", 2, 32, 26),
            mount("/run", 3, 7, 6),
            mount("/run/user/1000", 4, 7, 6),
        ],
        process_swap(4),
    )
    .unwrap();
    assert!(assessment.warning());
    assert_eq!(assessment.tmpfs_used_bytes, 64 * GIB);
    assert_eq!(assessment.nominal_ram_plus_swap_bytes, 126 * GIB);
    assert_eq!(
        assessment.reasons,
        [
            "tmpfs_exceeds_half_ram",
            "low_swap_tmpfs_exceeds_process_swap",
            "runtime_tmpfs_pressure"
        ]
    );
    let summary = assessment.summary();
    for path in ["/dev/shm", "/tmp", "/run", "/run/user/1000"] {
        assert!(summary.contains(path), "{summary}");
    }
    assert!(!summary.contains('\n'));
}

#[test]
fn huge_empty_tmpfs_limits_do_not_look_like_memory_usage() {
    let assessment = assess(
        memory(30, 16, 16),
        vec![
            mount("/tmp", 1, 1024, 0),
            mount("/dev/shm", 2, 1024, 0),
            mount("/run", 3, 1024, 0),
        ],
        process_swap(0),
    )
    .unwrap();
    assert!(!assessment.warning());
    assert_eq!(assessment.tmpfs_used_bytes, 0);
}

#[test]
fn bind_aliases_count_once_without_hiding_their_names() {
    let assessment = assess(
        memory(64, 32, 32),
        vec![
            mount("/tmp", 1, 32, 8),
            mount("/bind/tmp", 1, 32, 9),
            mount("/dev/shm", 2, 32, 8),
        ],
        process_swap(0),
    )
    .unwrap();
    assert_eq!(assessment.tmpfs_used_bytes, 17 * GIB);
    assert_eq!(assessment.unique_filesystems, 2);
    assert_eq!(assessment.mounts.len(), 3);
    assert!(!assessment.warning());
}

#[test]
fn runtime_fullness_alerts_even_without_host_ram_pressure() {
    let mut runtime = mount("/run/user/1000", 1, 1, 0);
    runtime.used_bytes = GIB * 95 / 100;
    runtime.available_bytes = GIB - runtime.used_bytes;
    let assessment = assess(memory(64, 32, 32), vec![runtime], process_swap(0)).unwrap();
    assert_eq!(assessment.reasons, ["runtime_tmpfs_pressure"]);
    let assessment = assess(
        memory(64, 32, 32),
        vec![mount("/run/credentials/service", 1, 1, 1)],
        process_swap(0),
    )
    .unwrap();
    assert!(!assessment.warning());
}

#[test]
fn incomplete_process_visibility_never_establishes_swap_attribution() {
    let mut process = process_swap(0);
    process.complete = false;
    process.unreadable = 1;
    let assessment = assess(memory(64, 32, 0), vec![mount("/tmp", 1, 32, 1)], process).unwrap();
    assert_eq!(
        assessment.reasons,
        ["low_swap_process_visibility_incomplete"]
    );
}

#[test]
fn thresholds_are_strict_and_no_swap_is_not_full_swap() {
    assert!(!swap_nearly_full(&memory(64, 0, 0)));
    assert!(!swap_nearly_full(&memory(64, 10, 1)));
    assert!(swap_nearly_full(&memory(64, 10, 0)));
    assert!(
        !assess(
            memory(64, 0, 0),
            vec![mount("/tmp", 1, 64, 32)],
            process_swap(0)
        )
        .unwrap()
        .warning()
    );
    assert!(
        assess(
            memory(64, 0, 0),
            vec![mount("/tmp", 1, 64, 33)],
            process_swap(0)
        )
        .unwrap()
        .warning()
    );
}

#[test]
fn contradictory_or_overflowing_observations_are_not_healthy() {
    let mut bad = memory(64, 32, 32);
    bad.swap_free_bytes += 1;
    assert!(assess(bad, vec![], process_swap(0)).is_err());
    let mut bad = memory(64, 0, 0);
    bad.total_bytes = u64::MAX;
    bad.swap_total_bytes = 1;
    assert!(assess(bad, vec![], process_swap(0)).is_err());
    let huge = ScratchMount {
        path: "/tmp".into(),
        filesystem_id: 1,
        total_bytes: u64::MAX,
        used_bytes: u64::MAX,
        available_bytes: 0,
    };
    let other = ScratchMount {
        filesystem_id: 2,
        ..huge.clone()
    };
    assert!(assess(memory(64, 0, 0), vec![huge, other], process_swap(0)).is_err());
}

#[test]
fn ram_log_destination_predicate_refuses_low_swap_or_full_mount() {
    assert!(ram_log_destination_healthy(&memory(64, 32, 32), 100, 20));
    assert!(!ram_log_destination_healthy(&memory(64, 32, 32), 100, 19));
    assert!(!ram_log_destination_healthy(&memory(64, 32, 0), 100, 90));
    assert!(!ram_log_destination_healthy(&memory(64, 32, 32), 0, 0));
}
