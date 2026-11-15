//! Executor boundaries for the filesystem authority carried by queued scans.

use super::*;
use std::cell::Cell;
use std::fs;

use crate::daemon::filesystem_reclaim::FilesystemReclaimScope;
use crate::monitor::fs_stats::FsStatsCollector;
use crate::platform::pal::{FsStats, MockPlatform, MountPoint, PlatformPaths};
use crate::scanner::patterns::ArtifactClassification;
use crate::scanner::quarantine::QuarantineStore;
use crate::scanner::scoring::{DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors};
use crate::scanner::walker::identity_for_path;

struct Fixture {
    _temp: tempfile::TempDir,
    mount: PathBuf,
    root: PathBuf,
    other_root: PathBuf,
    scanner: ScannerConfig,
    platform: Arc<MockPlatform>,
    scope: Arc<FilesystemReclaimScope>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().canonicalize().unwrap().join("mount");
        let root = mount.join("admitted");
        let other_root = mount.join("other-configured-root");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&other_root).unwrap();
        let scanner = ScannerConfig {
            root_paths: vec![root.clone(), other_root.clone()],
            ..ScannerConfig::default()
        };
        let platform = Arc::new(platform(std::slice::from_ref(&mount), false));
        let collector = FsStatsCollector::new(platform.clone(), Duration::ZERO);
        let mount_sample = collector.collect_admission_sample(&mount).unwrap();
        let root_sample = collector.collect_admission_sample(&root).unwrap();
        let scope = Arc::new(
            FilesystemReclaimScope::from_observed_roots(
                &mount_sample,
                std::slice::from_ref(&root),
                &[root_sample],
                &scanner,
                false,
            )
            .expect("complete observed mount and root must admit a scope"),
        );
        Self {
            _temp: temp,
            mount,
            root,
            other_root,
            scanner,
            platform,
            scope,
        }
    }

    fn batch(&self, candidates: Vec<CandidacyScore>) -> DeletionBatch {
        DeletionBatch {
            candidates,
            admitted_scanner: Arc::new(self.scanner.clone()),
            pressure_level: PressureLevel::Green,
            urgency: 0.5,
            scan_now: None,
            filesystem_reclaim: Some(Arc::clone(&self.scope)),
            predictive_reclaim: None,
            target_bytes: None,
            ram_reclaim: None,
            inode_reclaim: None,
            target_only_root: None,
            target_only_consent: None,
        }
    }

    fn request(&self) -> ScanRequest {
        ScanRequest {
            paths: vec![self.root.clone()],
            admitted_scanner: Arc::new(self.scanner.clone()),
            filesystem_reclaim: Some(Arc::clone(&self.scope)),
            predictive_reclaim: None,
            urgency: 0.5,
            pressure_level: PressureLevel::Green,
            free_pct: Some(30.0),
            max_delete_batch: 10,
            force_full_scan: false,
            scan_now: None,
            config_update: None,
            catalog_roots: Vec::new(),
            maintenance: false,
            target_bytes: None,
            ram_reclaim: None,
            inode_reclaim: None,
        }
    }

    fn executor(&self, mode: DeletionMode) -> DeletionExecutor {
        DeletionExecutor::new(
            DeletionConfig {
                check_open_files: false,
                require_identity: true,
                mode,
                quarantine_roots: vec![self.root.clone()],
                ..DeletionConfig::default()
            },
            None,
        )
    }
}

fn platform(mounts: &[PathBuf], is_readonly: bool) -> MockPlatform {
    MockPlatform::new(
        mounts
            .iter()
            .map(|mount| MountPoint {
                path: mount.clone(),
                device: mount.display().to_string(),
                fs_type: "mockfs".to_string(),
                is_ram_backed: false,
            })
            .collect(),
        mounts
            .iter()
            .map(|mount| {
                (
                    mount.clone(),
                    FsStats {
                        total_bytes: 100_000,
                        free_bytes: 30_000,
                        available_bytes: 30_000,
                        fs_type: "mockfs".to_string(),
                        mount_point: mount.clone(),
                        is_readonly,
                    },
                )
            })
            .collect(),
        MockPlatform::healthy().memory_info().unwrap(),
        PlatformPaths::default(),
    )
}

fn candidate(path: PathBuf) -> CandidacyScore {
    fs::create_dir_all(path.join("debug/deps")).unwrap();
    fs::write(path.join("debug/deps/artifact.o"), b"keep until authorized").unwrap();
    CandidacyScore {
        identity: identity_for_path(&path, false).ok(),
        path,
        total_score: 0.95,
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
        size_bytes: 21,
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
            summary: "filesystem admission regression".to_string(),
        },
    }
}

#[test]
fn filesystem_reclaim_filters_foreign_and_nested_candidates_before_policy() {
    let fixture = Fixture::new();
    let admitted = candidate(fixture.root.join("target"));
    let other = candidate(fixture.other_root.join("target"));
    let nested_mount = fixture.root.join("nested");
    let nested = candidate(nested_mount.join("target"));
    let mut unidentified = admitted.clone();
    unidentified.identity = None;
    let platform = platform(&[fixture.mount.clone(), nested_mount], false);
    let mut batch = fixture.batch(vec![
        other.clone(),
        nested.clone(),
        unidentified,
        admitted.clone(),
    ]);

    assert_eq!(
        retain_filesystem_reclaim_candidates(&mut batch, &fixture.scanner, &platform),
        3,
    );
    assert_eq!(batch.candidates.len(), 1);
    assert_eq!(batch.candidates[0].path, admitted.path);
    assert_eq!(
        admitted.identity.unwrap().device_id,
        other.identity.unwrap().device_id,
        "a shared device number must not grant authority to another root",
    );
    assert!(other.path.exists());
    assert!(nested.path.exists());
}

#[test]
fn filesystem_authority_survives_event_templates_and_dispatch() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let mut templates = EventPassTemplates::default();
    templates.remember(&request, &fixture.scanner);
    let pending = PendingScannerEvents {
        reconciliation: BTreeSet::from([fixture.root.clone()]),
        ..PendingScannerEvents::default()
    };
    let events =
        EventSourceConfig::from_scanner_config(&fixture.scanner.root_paths, &fixture.scanner);
    let event_request = templates
        .next_request(&pending, &events, &fixture.scanner)
        .expect("dirty work has its admitted event template");
    assert!(Arc::ptr_eq(
        event_request.filesystem_reclaim.as_ref().unwrap(),
        &fixture.scope,
    ));
    let admitted = candidate(fixture.root.join("target"));
    let unrelated = candidate(fixture.other_root.join("target"));
    assert!(!event_request.permits_reclaim_candidate(&unrelated));
    let mut candidates = vec![unrelated.clone(), admitted.clone()];
    let (send, receive) = bounded(1);
    let executor_config = SharedExecutorConfig::new(false, 10, 0.5, 60, 3600, false, 0);
    let mut dispatched = PassDispatch::default();
    assert!(dispatch_top_candidates(
        &mut candidates,
        &event_request,
        &send,
        &mut dispatched,
        &executor_config,
    ));
    let batch = receive
        .try_recv()
        .expect("the authorized candidate dispatches");
    assert!(Arc::ptr_eq(
        batch.filesystem_reclaim.as_ref().unwrap(),
        &fixture.scope,
    ));
    assert_eq!(batch.candidates.len(), 1);
    assert_eq!(batch.candidates[0].path, admitted.path);
    assert_eq!(dispatched.count, 1);
    assert_eq!(dispatched.bytes, admitted.size_bytes);
    assert!(unrelated.path.exists());
}

#[test]
fn one_traversal_root_preserves_distinct_filesystem_queue_and_event_scopes() {
    let fixture = Fixture::new();
    let first_mount = fixture.root.join("first-mount");
    let second_mount = fixture.root.join("second-mount");
    fs::create_dir(&first_mount).unwrap();
    fs::create_dir(&second_mount).unwrap();
    let platform = Arc::new(platform(
        &[
            fixture.mount.clone(),
            first_mount.clone(),
            second_mount.clone(),
        ],
        false,
    ));
    let scanner = ScannerConfig {
        root_paths: vec![fixture.root.clone()],
        cross_devices: true,
        ..fixture.scanner.clone()
    };
    let collector = FsStatsCollector::new(platform, Duration::ZERO);
    let root_sample = collector.collect_admission_sample(&fixture.root).unwrap();
    let scope_for = |mount: &Path| {
        Arc::new(
            FilesystemReclaimScope::from_observed_roots(
                &collector.collect_admission_sample(mount).unwrap(),
                std::slice::from_ref(&fixture.root),
                std::slice::from_ref(&root_sample),
                &scanner,
                false,
            )
            .expect("a cross-device parent may lead to its mounted child"),
        )
    };
    let mut first = fixture.request();
    first.admitted_scanner = Arc::new(scanner.clone());
    first.filesystem_reclaim = Some(scope_for(&first_mount));
    let mut second = first.clone();
    second.filesystem_reclaim = Some(scope_for(&second_mount));

    assert_eq!(first.paths, second.paths);
    assert!(!same_queued_scan_scope(&first, &second));
    assert!(first.permits_reclaim_path(&fixture.root));
    assert!(first.permits_reclaim_candidate(&candidate(first_mount.join("target"))));
    assert!(second.permits_reclaim_candidate(&candidate(second_mount.join("target"))));
    assert!(!first.permits_reclaim_candidate(&candidate(fixture.root.join("target"))));
    assert!(!first.permits_reclaim_candidate(&candidate(second_mount.join("target"))));
    let mut templates = EventPassTemplates::default();
    templates.remember(&first, &scanner);
    templates.remember(&second, &scanner);
    assert_eq!(
        templates.templates.len(),
        2,
        "overlapping traversal roots must retain each mount's event authority",
    );
}

#[derive(Clone, Copy, Debug)]
enum Revocation {
    RootAlias,
    MountOwner,
    ReadOnly,
}

#[test]
fn filesystem_reclaim_is_renewed_after_final_inspection_for_both_backends() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        for revocation in [
            Revocation::RootAlias,
            Revocation::MountOwner,
            Revocation::ReadOnly,
        ] {
            let fixture = Fixture::new();
            let artifact = candidate(fixture.root.join("target"));
            let executor = fixture.executor(mode);
            let plan = executor.plan(vec![artifact.clone()]);
            assert_eq!(plan.candidates.len(), 1);
            let changed_owner = platform(&[fixture.mount.clone(), fixture.root.clone()], false);
            let readonly = platform(std::slice::from_ref(&fixture.mount), true);
            let checks = Cell::new(0);
            let authorize = |candidate: &CandidacyScore| {
                checks.set(checks.get() + 1);
                let mut current: &dyn Platform = fixture.platform.as_ref();
                if checks.get() >= 2 {
                    match revocation {
                        Revocation::RootAlias if checks.get() == 2 => {
                            let moved = fixture.mount.join("moved-root");
                            fs::rename(&fixture.root, &moved).unwrap();
                            std::os::unix::fs::symlink(&moved, &fixture.root).unwrap();
                        }
                        Revocation::RootAlias => {}
                        Revocation::MountOwner => current = &changed_owner,
                        Revocation::ReadOnly => current = &readonly,
                    }
                }
                fixture
                    .scope
                    .authorize_candidate(candidate, &fixture.scanner, current)
                    .map(|_| ())
            };
            let report = executor.execute_with_guard(&plan, None, Some(&authorize));

            assert!(checks.get() >= 2, "{mode:?} {revocation:?}: {report:?}");
            assert_eq!(
                report.items_deleted, 0,
                "{mode:?} {revocation:?}: {report:?}"
            );
            assert_eq!(report.items_quarantined, 0);
            assert_eq!(report.items_failed, 0);
            assert_eq!(report.items_skipped, 1);
            assert_eq!(report.skipped_by_reason.get("policy_changed"), Some(&1));
            assert!(report.backoff_candidates.is_empty());
            assert_eq!(report.bytes_freed, 0);
            assert_eq!(report.bytes_quarantined, 0);
            assert_eq!(
                identity_for_path(&artifact.path, false).ok(),
                artifact.identity
            );
            assert_eq!(
                fs::read(artifact.path.join("debug/deps/artifact.o")).unwrap(),
                b"keep until authorized",
            );
            assert!(!QuarantineStore::under(&fixture.root).root().exists());
        }
    }
}

#[test]
fn current_filesystem_authority_reaches_unlink_and_quarantine() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let fixture = Fixture::new();
        let artifact = candidate(fixture.root.join("target"));
        let executor = fixture.executor(mode);
        let authorize = |candidate: &CandidacyScore| {
            fixture
                .scope
                .authorize_candidate(candidate, &fixture.scanner, fixture.platform.as_ref())
                .map(|_| ())
        };
        let report = executor.execute_with_guard(
            &executor.plan(vec![artifact.clone()]),
            None,
            Some(&authorize),
        );

        assert_eq!(report.items_deleted, 1, "{mode:?}: {report:?}");
        assert_eq!(report.items_skipped, 0);
        assert_eq!(report.items_failed, 0);
        assert!(!artifact.path.exists());
        match mode {
            DeletionMode::Unlink => {
                assert_eq!(report.items_quarantined, 0);
                assert_eq!(report.bytes_freed, artifact.size_bytes);
            }
            DeletionMode::Quarantine => {
                assert_eq!(report.items_quarantined, 1);
                assert_eq!(report.bytes_freed, 0);
                let records = QuarantineStore::under(&fixture.root).records().unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(
                    fs::read(records[0].quarantine_path.join("debug/deps/artifact.o")).unwrap(),
                    b"keep until authorized",
                );
            }
        }
    }
}
