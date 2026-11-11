use super::*;
use std::collections::HashMap;

use crate::daemon::policy::BehaviorPreset;
use crate::platform::pal::{FsStats, MemoryInfo, MockPlatform, MountPoint, PlatformPaths};
use crate::scanner::patterns::ArtifactClassification;
use crate::scanner::scoring::{DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors};
use crate::scanner::walker::identity_for_path;

fn scanner(root: &Path) -> ScannerConfig {
    ScannerConfig {
        root_paths: vec![root.to_path_buf()],
        excluded_paths: Vec::new(),
        protected_paths: Vec::new(),
        ..ScannerConfig::default()
    }
}

fn response(mount: &Path, level: PressureLevel) -> PressureResponse {
    PressureResponse {
        level,
        urgency: if level == PressureLevel::Green {
            0.0
        } else {
            0.9
        },
        scan_interval: Duration::from_secs(1),
        release_ballast_files: 0,
        max_delete_batch: 10,
        fallback_active: false,
        causing_mount: mount.to_path_buf(),
        free_pct: if level == PressureLevel::Green {
            70.0
        } else {
            1.0
        },
        predicted_seconds: None,
    }
}

fn queue_policy(queue: &ScanNowQueue, preset: BehaviorPreset) {
    queue.update_policy(
        BehaviorDispatchTable::from_preset(preset),
        MemoryPressureLevel::Normal,
        PidConfig::from(&crate::core::config::PressureConfig::default()),
    );
}

fn scopes(
    paths: &[PathBuf],
    force: bool,
    scanner: &ScannerConfig,
    mount: &Path,
) -> Vec<ScanNowScope> {
    ScanNowScope::capture(paths, force, scanner)
        .unwrap()
        .partition(|_| Some(mount.to_path_buf()))
        .unwrap()
}

#[test]
fn selection_never_expands_to_configured_ancestors_and_invalid_requests_are_atomic() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("configured");
    let child = root.join("selected");
    let sibling = root.join("unselected");
    let outside = temp.path().join("outside");
    for path in [&child, &sibling, &outside] {
        fs::create_dir_all(path).unwrap();
    }
    let config = scanner(&root);
    let scope = ScanNowScope::capture(std::slice::from_ref(&child), false, &config).unwrap();
    assert_eq!(scope.paths(), vec![child.clone()]);
    assert!(scope.contains_path(&child.join("target")));
    assert!(!scope.contains_path(&sibling));
    assert!(!scope.contains_path(&root));
    assert!(ScanNowScope::capture(&[child, outside], true, &config).is_err());
    assert!(ScanNowScope::capture(&[PathBuf::from("relative")], true, &config).is_err());
    let file = root.join("file");
    fs::write(&file, b"work").unwrap();
    assert!(ScanNowScope::capture(&[file], false, &config).is_err());
}

#[cfg(unix)]
#[test]
fn configured_aliases_remain_bound_and_descendant_links_cannot_escape_scope() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    let other = temp.path().join("other");
    fs::create_dir_all(real.join("selected")).unwrap();
    fs::create_dir_all(other.join("selected")).unwrap();
    let alias = temp.path().join("configured-alias");
    symlink(&real, &alias).unwrap();
    let mut config = scanner(&alias);
    let scope = ScanNowScope::capture(&[real.join("selected")], false, &config).unwrap();
    assert_eq!(scope.paths(), vec![alias.join("selected")]);
    assert!(scope.authorized(&config));
    symlink(&other, real.join("escape")).unwrap();
    assert!(ScanNowScope::capture(&[alias.join("escape/selected")], true, &config).is_err());
    symlink(real.join("selected"), real.join("inside-link")).unwrap();
    assert!(ScanNowScope::capture(&[alias.join("inside-link")], false, &config).is_err());
    config.follow_symlinks = true;
    assert!(ScanNowScope::capture(&[alias.join("inside-link")], false, &config).is_ok());
    assert!(ScanNowScope::capture(&[alias.join("escape/selected")], true, &config).is_err());
    config.follow_symlinks = false;
    fs::remove_file(&alias).unwrap();
    symlink(&other, &alias).unwrap();
    assert!(!scope.authorized(&config));
}

#[test]
fn protected_excluded_marked_replaced_and_reloaded_scope_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("selected");
    fs::create_dir(&child).unwrap();
    let config = scanner(temp.path());
    let scope = ScanNowScope::capture(std::slice::from_ref(&child), true, &config).unwrap();
    let mut changed = config.clone();
    changed.root_paths.clear();
    assert!(!scope.authorized(&changed));
    changed = config.clone();
    changed.excluded_paths.push(child.clone());
    assert!(!scope.authorized(&changed));
    assert!(ScanNowScope::capture(std::slice::from_ref(&child), true, &changed).is_err());
    changed = config.clone();
    changed.protected_paths.push(child.display().to_string());
    assert!(ScanNowScope::capture(std::slice::from_ref(&child), true, &changed).is_err());
    fs::write(temp.path().join(".sbh-protect"), b"protected").unwrap();
    assert!(!scope.authorized(&config));
    fs::remove_file(temp.path().join(".sbh-protect")).unwrap();
    fs::rename(&child, temp.path().join("old-selection")).unwrap();
    fs::create_dir(&child).unwrap();
    assert!(!scope.authorized(&config));
}

#[test]
fn nested_mount_selection_survives_dedup_and_never_borrows_its_neighbors_pressure() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("nested");
    let leaf = nested.join("leaf");
    fs::create_dir_all(&leaf).unwrap();
    let config = scanner(temp.path());
    let mount_for = |path: &Path| {
        Some(if path.starts_with(&nested) {
            nested.clone()
        } else {
            temp.path().to_path_buf()
        })
    };
    let partitions = ScanNowScope::capture(
        &[temp.path().to_path_buf(), nested.clone(), leaf],
        true,
        &config,
    )
    .unwrap()
    .partition(mount_for)
    .unwrap();
    assert_eq!(partitions.len(), 2);
    let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
    queue_policy(&queue.lock(), BehaviorPreset::V0_6);
    queue.lock().enqueue(partitions, 2).unwrap();
    queue.lock().refresh(
        &config,
        &[
            response(temp.path(), PressureLevel::Green),
            response(&nested, PressureLevel::Red),
        ],
        mount_for,
    );
    let first = ScanNowClaim::take(&queue, Instant::now()).unwrap();
    let second = ScanNowClaim::take(&queue, Instant::now()).unwrap();
    let requests = [first.request(), second.request()];
    assert!(
        requests
            .iter()
            .any(|request| request.paths == vec![temp.path().to_path_buf()]
                && request.pressure_level == PressureLevel::Green
                && request.free_pct == Some(70.0))
    );
    assert!(
        requests
            .iter()
            .any(|request| request.paths == vec![nested.clone()]
                && request.pressure_level == PressureLevel::Red
                && request.free_pct == Some(1.0))
    );
    assert!(
        requests
            .iter()
            .all(|request| request.ram_reclaim.is_none() && request.inode_reclaim.is_none())
    );
}

#[test]
fn reservation_survives_pacing_and_admission_is_bounded_and_atomic() {
    let temp = tempfile::tempdir().unwrap();
    let config = scanner(temp.path());
    let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
    queue_policy(&queue.lock(), BehaviorPreset::V0_6);
    let admitted = || scopes(&[], false, &config, temp.path());
    queue.lock().enqueue(admitted(), 1).unwrap();
    queue.lock().refresh(
        &config,
        &[response(temp.path(), PressureLevel::Green)],
        |_| Some(temp.path().to_path_buf()),
    );
    let mut claim = ScanNowClaim::take(&queue, Instant::now()).unwrap();
    assert!(!claim.request().scan_now.unwrap().force());
    assert!(
        queue.lock().enqueue(admitted(), 1).is_err(),
        "in-flight work retains its slot"
    );
    claim.defer(Duration::from_secs(1));
    drop(claim);
    assert!(ScanNowClaim::take(&queue, Instant::now()).is_none());
    let claim = ScanNowClaim::take(&queue, Instant::now() + Duration::from_secs(2)).unwrap();
    assert_eq!(claim.request().paths, vec![temp.path().to_path_buf()]);
    drop(claim);
    let mut too_many = admitted();
    too_many.extend(admitted());
    assert!(queue.lock().enqueue(too_many, 1).is_err());
    assert!(
        queue.lock().pending.is_empty(),
        "a rejected selection is never partially queued"
    );
}

#[test]
fn pressure_loss_pauses_pending_and_deferred_scans_until_fresh_observation() {
    for claimed_before_failure in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let config = scanner(temp.path());
        let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
        queue_policy(&queue.lock(), BehaviorPreset::V0_6);
        queue
            .lock()
            .enqueue(scopes(&[], true, &config, temp.path()), 1)
            .unwrap();
        queue.lock().refresh(
            &config,
            &[response(temp.path(), PressureLevel::Critical)],
            |_| Some(temp.path().to_path_buf()),
        );
        let claim =
            claimed_before_failure.then(|| ScanNowClaim::take(&queue, Instant::now()).unwrap());
        queue.lock().withdraw_pressure();
        // Recovery while a paced claim is still outside the queue must not
        // let its eventual deferral restore the old Critical observation.
        if let Some(mut claim) = claim {
            queue.lock().refresh(
                &config,
                &[response(temp.path(), PressureLevel::Green)],
                |_| Some(temp.path().to_path_buf()),
            );
            claim.defer(Duration::ZERO);
            drop(claim);
        }
        assert!(ScanNowClaim::take(&queue, Instant::now()).is_none());
        assert_eq!(queue.lock().paths(), vec![temp.path().to_path_buf()]);
        assert!(
            queue
                .lock()
                .enqueue(scopes(&[], true, &config, temp.path()), 1)
                .is_err(),
            "the accepted request still owns its bounded queue slot",
        );

        queue.lock().refresh(
            &config,
            &[response(temp.path(), PressureLevel::Green)],
            |_| Some(temp.path().to_path_buf()),
        );
        let refreshed = ScanNowClaim::take(&queue, Instant::now()).unwrap();
        assert_eq!(refreshed.request().pressure_level, PressureLevel::Green);
        assert!(refreshed.request().scan_now.unwrap().authorized(&config));
    }
}

#[test]
fn forced_requests_can_run_while_an_earlier_selection_waits_for_pacing() {
    let temp = tempfile::tempdir().unwrap();
    let config = scanner(temp.path());
    let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
    queue_policy(&queue.lock(), BehaviorPreset::V0_6);
    queue
        .lock()
        .enqueue(scopes(&[], false, &config, temp.path()), 2)
        .unwrap();
    queue.lock().refresh(
        &config,
        &[response(temp.path(), PressureLevel::Green)],
        |_| Some(temp.path().to_path_buf()),
    );
    let mut paced = ScanNowClaim::take(&queue, Instant::now()).unwrap();
    paced.defer(Duration::from_secs(60));
    drop(paced);
    queue
        .lock()
        .enqueue(scopes(&[], true, &config, temp.path()), 2)
        .unwrap();
    queue.lock().refresh(
        &config,
        &[response(temp.path(), PressureLevel::Green)],
        |_| Some(temp.path().to_path_buf()),
    );
    let forced = ScanNowClaim::take(&queue, Instant::now()).unwrap();
    assert!(forced.request().scan_now.unwrap().force());
    assert_eq!(queue.lock().pending.len(), 1);
}

#[test]
fn missing_observations_wait_and_reload_revokes_even_already_claimed_work() {
    let temp = tempfile::tempdir().unwrap();
    let config = scanner(temp.path());
    let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
    queue_policy(&queue.lock(), BehaviorPreset::V0_6);
    queue
        .lock()
        .enqueue(scopes(&[], true, &config, temp.path()), 1)
        .unwrap();
    queue
        .lock()
        .refresh(&config, &[], |_| Some(temp.path().to_path_buf()));
    assert!(ScanNowClaim::take(&queue, Instant::now()).is_none());
    assert_eq!(queue.lock().pending.len(), 1);
    queue.lock().refresh(
        &config,
        &[response(temp.path(), PressureLevel::Critical)],
        |_| Some(temp.path().to_path_buf()),
    );
    let claim = ScanNowClaim::take(&queue, Instant::now()).unwrap();
    let request = claim.request();
    assert!(request.scan_now.as_ref().unwrap().authorized(&config));
    assert_eq!(queue.lock().revoke(), 1);
    assert!(!request.scan_now.unwrap().authorized(&config));
}

#[test]
fn force_cannot_override_local_identify_only_or_no_cleanup_cells() {
    let temp = tempfile::tempdir().unwrap();
    let config = scanner(temp.path());
    let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
    queue_policy(&queue.lock(), BehaviorPreset::V0_5);
    for level in [PressureLevel::Green, PressureLevel::Orange] {
        queue
            .lock()
            .enqueue(scopes(&[], true, &config, temp.path()), 1)
            .unwrap();
        queue
            .lock()
            .refresh(&config, &[response(temp.path(), level)], |_| {
                Some(temp.path().to_path_buf())
            });
        let claim = ScanNowClaim::take(&queue, Instant::now()).unwrap();
        assert_eq!(claim.request().max_delete_batch, 0);
        assert!(claim.request().force_full_scan);
    }
}

fn candidate(path: PathBuf) -> CandidacyScore {
    fs::create_dir(&path).unwrap();
    CandidacyScore {
        identity: identity_for_path(&path, false).ok(),
        path,
        total_score: 0.9,
        factors: ScoreFactors {
            location: 1.0,
            name: 1.0,
            age: 1.0,
            size: 1.0,
            structure: 1.0,
            pressure_multiplier: 1.0,
        },
        vetoed: false,
        veto_reason: None,
        classification: ArtifactClassification::unknown(),
        size_bytes: 4096,
        age: Duration::from_hours(24),
        decision: DecisionOutcome {
            action: DecisionAction::Delete,
            posterior_abandoned: 0.99,
            expected_loss_keep: 1.0,
            expected_loss_delete: 0.01,
            calibration_score: 1.0,
            fallback_active: false,
            certainty: ArtifactCertainty::Definite,
            posterior_floor_applied: false,
            regret_calibration: 1.0,
            category_suspended: false,
        },
        ledger: EvidenceLedger {
            terms: Vec::new(),
            summary: "fixture".to_string(),
        },
    }
}

fn platform(mount: &Path, available_bytes: u64) -> MockPlatform {
    MockPlatform::new(
        vec![MountPoint {
            path: mount.to_path_buf(),
            device: "fixture".to_string(),
            fs_type: "ext4".to_string(),
            is_ram_backed: false,
        }],
        HashMap::from([(
            mount.to_path_buf(),
            FsStats {
                total_bytes: 1_000_000_000_000,
                free_bytes: available_bytes,
                available_bytes,
                fs_type: "ext4".to_string(),
                mount_point: mount.to_path_buf(),
                is_readonly: false,
            },
        )]),
        MemoryInfo {
            total_bytes: 64_000,
            available_bytes: 32_000,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        },
        PlatformPaths::default(),
    )
}

#[test]
fn mutation_renews_local_pressure_and_refuses_other_scopes_or_devices() {
    let temp = tempfile::tempdir().unwrap();
    let selected = temp.path().join("selected");
    fs::create_dir(&selected).unwrap();
    let mut chosen = candidate(selected.join("target"));
    let outside = candidate(temp.path().join("other-target"));
    let config = scanner(temp.path());
    let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
    queue_policy(&queue.lock(), BehaviorPreset::V0_5);
    queue
        .lock()
        .enqueue(scopes(&[selected], true, &config, temp.path()), 1)
        .unwrap();
    queue.lock().refresh(
        &config,
        &[response(temp.path(), PressureLevel::Critical)],
        |_| Some(temp.path().to_path_buf()),
    );
    let claim = ScanNowClaim::take(&queue, Instant::now()).unwrap();
    let scope = claim.request().scan_now.unwrap();
    let pressured = platform(temp.path(), 1_000_000_000);
    assert!(scope.permits_mutation(&chosen, &config, &pressured, PressureLevel::Critical));
    assert!(
        !scope.permits_mutation(
            &chosen,
            &config,
            &platform(temp.path(), 700_000_000_000),
            PressureLevel::Critical
        ),
        "a recovered mount cannot keep the old Critical permission"
    );
    queue_policy(&queue.lock(), BehaviorPreset::V0_6);
    assert!(
        !scope.permits_mutation(
            &chosen,
            &config,
            &platform(temp.path(), 700_000_000_000),
            PressureLevel::Critical
        ),
        "even a Definite candidate needs a fresh Green quarantine plan"
    );
    assert!(!scope.permits_mutation(&outside, &config, &pressured, PressureLevel::Critical));
    chosen.identity.as_mut().unwrap().device_id ^= 1;
    assert!(!scope.permits_mutation(&chosen, &config, &pressured, PressureLevel::Critical));
}

#[test]
#[allow(clippy::too_many_lines)]
fn completing_a_selected_root_preserves_its_sibling_but_replacement_revokes_the_matching_path() {
    use crate::scanner::deletion::{DeletionConfig, DeletionExecutor, SkipReason};

    for replace_second in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut first = candidate(temp.path().join("first-target"));
        first.total_score = 1.0;
        let second = candidate(temp.path().join("second-target"));
        let config = scanner(temp.path());
        let queue = Arc::new(Mutex::new(ScanNowQueue::default()));
        queue_policy(&queue.lock(), BehaviorPreset::V0_6);
        queue
            .lock()
            .enqueue(
                scopes(
                    &[first.path.clone(), second.path.clone()],
                    true,
                    &config,
                    temp.path(),
                ),
                1,
            )
            .unwrap();
        queue.lock().refresh(
            &config,
            &[response(temp.path(), PressureLevel::Critical)],
            |_| Some(temp.path().to_path_buf()),
        );
        let claim = ScanNowClaim::take(&queue, Instant::now()).unwrap();
        let scope = claim.request().scan_now.unwrap();
        let pressured = platform(temp.path(), 1_000_000_000);
        let executor = DeletionExecutor::new(
            DeletionConfig {
                min_score: 0.0,
                check_open_files: false,
                require_identity: true,
                ..DeletionConfig::default()
            },
            None,
        );
        let plan = executor.plan(vec![first.clone(), second.clone()]);
        let report = executor.execute_with_hooks(
            &plan,
            None,
            Some(&|candidate| {
                scope
                    .permits_mutation(candidate, &config, &pressured, PressureLevel::Critical)
                    .then_some(())
                    .ok_or(SkipReason::PolicyChanged)
            }),
            Some(&|candidate: &CandidacyScore, _| {
                if candidate.path == first.path {
                    assert!(!first.path.exists());
                    assert!(scope.authorizes_candidate(&second.path, &config));
                    if replace_second {
                        fs::rename(&second.path, temp.path().join("saved-second")).unwrap();
                        fs::create_dir(&second.path).unwrap();
                        assert!(!scope.authorizes_candidate(&second.path, &config));
                    }
                }
            }),
        );
        assert_eq!(report.items_deleted, if replace_second { 1 } else { 2 });
        assert_eq!(report.items_failed, 0);
        assert!(!first.path.exists());
        assert_eq!(second.path.exists(), replace_second);
        if replace_second {
            assert!(temp.path().join("saved-second").exists());
        }
    }
}
