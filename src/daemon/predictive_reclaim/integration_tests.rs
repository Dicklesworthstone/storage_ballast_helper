//! Request, queue and mutation boundaries for forecast-local scoring.

use super::*;
use std::borrow::Cow;
use std::cell::Cell;
use std::fs;

use crate::core::config::{PredictionConfig, ScoringConfig};
use crate::daemon::filesystem_reclaim::FilesystemReclaimScope;
use crate::daemon::predictive_reclaim::{PredictiveReclaimPolicy, PredictiveScanAdmission};
use crate::monitor::fs_stats::FsStatsCollector;
use crate::platform::pal::{FsStats, MockPlatform, MountPoint, PlatformPaths};
use crate::scanner::patterns::ArtifactClassification;
use crate::scanner::quarantine::QuarantineStore;
use crate::scanner::scoring::{
    CandidateInput, DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors,
};
use crate::scanner::walker::identity_for_path;

struct Fixture {
    _temp: tempfile::TempDir,
    mount: PathBuf,
    root: PathBuf,
    peer_root: PathBuf,
    scanner: ScannerConfig,
    scoring: ScoringConfig,
    prediction: PredictionConfig,
    shared: Arc<SharedExecutorConfig>,
    platform: Arc<MockPlatform>,
    scope: Arc<FilesystemReclaimScope>,
    peer_scope: Arc<FilesystemReclaimScope>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let base = temp.path().canonicalize().unwrap();
        let mount = base.join("filling");
        let peer_mount = base.join("steady");
        let root = mount.join("artifacts");
        let peer_root = peer_mount.join("artifacts");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&peer_root).unwrap();
        let scanner = ScannerConfig {
            root_paths: vec![root.clone(), peer_root.clone()],
            ..ScannerConfig::default()
        };
        let platform = Arc::new(platform(&[mount.clone(), peer_mount.clone()]));
        let collector = FsStatsCollector::new(platform.clone(), Duration::ZERO);
        let scope_for = |mount: &Path, root: &PathBuf| {
            Arc::new(
                FilesystemReclaimScope::from_observed_roots(
                    &collector.collect_admission_sample(mount).unwrap(),
                    std::slice::from_ref(root),
                    &[collector.collect_admission_sample(root).unwrap()],
                    &scanner,
                    false,
                )
                .unwrap(),
            )
        };
        let scope = scope_for(&mount, &root);
        let peer_scope = scope_for(&peer_mount, &peer_root);
        let scoring = ScoringConfig::default();
        let prediction = PredictionConfig::default();
        let shared = Arc::new(SharedExecutorConfig::new(
            false,
            10,
            scoring.min_score,
            60,
            3600,
            false,
            0,
        ));
        *shared.predictive_reclaim.write() = PredictiveReclaimPolicy::new(&prediction, &scoring);
        Self {
            _temp: temp,
            mount,
            root,
            peer_root,
            scanner,
            scoring,
            prediction,
            shared,
            platform,
            scope,
            peer_scope,
        }
    }

    fn request(&self, predictive: bool) -> ScanRequest {
        let now = Instant::now();
        ScanRequest {
            paths: vec![self.root.clone()],
            admitted_scanner: Arc::new(self.scanner.clone()),
            filesystem_reclaim: Some(Arc::clone(&self.scope)),
            predictive_reclaim: predictive.then(|| self.admit(now, Duration::from_secs(60))),
            urgency: 0.0,
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

    fn peer_request(&self) -> ScanRequest {
        let mut request = self.request(false);
        request.paths = vec![self.peer_root.clone()];
        request.filesystem_reclaim = Some(Arc::clone(&self.peer_scope));
        request
    }

    fn admit(&self, observed_at: Instant, max_age: Duration) -> PredictiveScanAdmission {
        self.shared
            .predictive_reclaim
            .write()
            .admit(
                &PredictiveAction::PreemptiveCleanup {
                    mount: self.mount.clone(),
                    minutes_remaining: 10.0,
                    confidence: 0.95,
                    rate_bytes_per_second: 1_000_000.0,
                    recommended_min_score: 0.30,
                    recommended_free_target_pct: 20.0,
                },
                observed_at,
                max_age,
                observed_at,
            )
            .unwrap()
    }

    fn executor(&self, min_score: f64) -> DeletionExecutor {
        DeletionExecutor::new(
            DeletionConfig {
                min_score,
                check_open_files: false,
                require_identity: true,
                quarantine_roots: self.scanner.root_paths.clone(),
                ..DeletionConfig::default()
            },
            None,
        )
        .with_platform(self.platform.clone())
    }
}

fn platform(mounts: &[PathBuf]) -> MockPlatform {
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
                        is_readonly: false,
                    },
                )
            })
            .collect(),
        MockPlatform::healthy().memory_info().unwrap(),
        PlatformPaths::default(),
    )
}

fn batch(request: &ScanRequest, candidates: Vec<CandidacyScore>) -> DeletionBatch {
    DeletionBatch {
        candidates,
        admitted_scanner: Arc::clone(&request.admitted_scanner),
        filesystem_reclaim: request.filesystem_reclaim.clone(),
        predictive_reclaim: request.predictive_reclaim.clone(),
        pressure_level: request.pressure_level,
        urgency: request.urgency,
        scan_now: None,
        target_bytes: None,
        ram_reclaim: None,
        inode_reclaim: None,
        target_only_root: None,
        target_only_consent: None,
    }
}

fn candidate(path: PathBuf) -> CandidacyScore {
    fs::write(&path, b"retained object").unwrap();
    CandidacyScore {
        identity: identity_for_path(&path, false).ok(),
        path,
        total_score: 0.32,
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
        size_bytes: 15,
        age: Duration::from_hours(24),
        decision: DecisionOutcome {
            action: DecisionAction::Delete,
            posterior_abandoned: 0.99,
            expected_loss_keep: 1.0,
            expected_loss_delete: 0.01,
            calibration_score: 1.0,
            fallback_active: false,
            certainty: ArtifactCertainty::Definite,
            posterior_floor_applied: true,
            regret_calibration: 1.0,
            category_suspended: false,
        },
        ledger: EvidenceLedger {
            terms: Vec::new(),
            summary: "predictive admission regression".to_string(),
        },
    }
}

#[test]
fn predictive_scoring_and_executor_floors_are_local_to_the_admitted_filesystem() {
    let fixture = Fixture::new();
    let request = fixture.request(true);
    let peer = fixture.peer_request();
    let now = Instant::now();
    let mut expected = fixture.scoring.clone();
    expected.min_score = 0.30;
    assert_eq!(
        request
            .scoring_config(&fixture.scoring, &fixture.shared, now)
            .unwrap(),
        expected
    );
    assert_eq!(
        peer.scoring_config(&fixture.scoring, &fixture.shared, now)
            .unwrap(),
        fixture.scoring
    );

    let selected = candidate(fixture.root.join("selected.o"));
    let retained = candidate(fixture.peer_root.join("retained.o"));
    let predictive = batch(&request, vec![selected]);
    let ordinary = batch(&peer, vec![retained.clone()]);
    let selected_plan = fixture
        .executor(predictive.min_score(&fixture.shared, now).unwrap())
        .plan(predictive.candidates);
    let ordinary_plan = fixture
        .executor(ordinary.min_score(&fixture.shared, now).unwrap())
        .plan(ordinary.candidates);
    assert_eq!(selected_plan.candidates.len(), 1);
    assert!(ordinary_plan.candidates.is_empty());
    assert!(ordinary_plan.refusal_summary().contains("below_threshold"));
    assert_eq!(
        fixture.shared.min_score().to_bits(),
        fixture.scoring.min_score.to_bits()
    );
    assert_eq!(fs::read(retained.path).unwrap(), b"retained object");
}

#[test]
fn predictive_scoring_requires_matching_filesystem_scope_at_both_queue_stages() {
    let fixture = Fixture::new();
    for missing in [false, true] {
        let mut request = fixture.request(true);
        request.filesystem_reclaim = if missing {
            None
        } else {
            Some(Arc::clone(&fixture.peer_scope))
        };
        let now = Instant::now();
        assert_eq!(
            request.scoring_config(&fixture.scoring, &fixture.shared, now),
            Err(SkipReason::PolicyChanged)
        );
        assert_eq!(
            batch(&request, Vec::new()).min_score(&fixture.shared, now),
            Err(SkipReason::PolicyChanged)
        );
    }
}

#[test]
fn predictive_dispatch_carries_authority_without_charging_withdrawn_or_expired_work() {
    for state in ["current", "withdrawn", "expired"] {
        let fixture = Fixture::new();
        let mut request = fixture.request(state != "expired");
        if state == "expired" {
            request.predictive_reclaim = Some(
                fixture.admit(
                    Instant::now()
                        .checked_sub(Duration::from_secs(2))
                        .expect("the expired observation timestamp is representable"),
                    Duration::from_secs(1),
                ),
            );
        } else if state == "withdrawn" {
            fixture
                .shared
                .predictive_reclaim
                .write()
                .observe(&[], Instant::now());
        }
        let selected = candidate(fixture.root.join("selected.o"));
        let retained = candidate(fixture.peer_root.join("retained.o"));
        let mut scored = vec![selected.clone(), retained.clone()];
        let mut dispatched = PassDispatch::default();
        let (send, receive) = bounded(2);
        assert!(dispatch_with_behavior_gate(
            &mut scored,
            &request,
            &send,
            &mut dispatched,
            &fixture.shared
        ));
        if state == "current" {
            let queued = receive
                .try_recv()
                .expect("current forecast must dispatch its artifact");
            assert_eq!(queued.candidates.len(), 1);
            assert_eq!(queued.candidates[0].path, selected.path);
            assert_eq!(dispatched.count, 1);
            assert_eq!(dispatched.bytes, selected.size_bytes);
            assert_eq!(
                queued
                    .min_score(&fixture.shared, Instant::now())
                    .unwrap()
                    .to_bits(),
                0.30_f64.to_bits()
            );
            fixture.shared.predictive_reclaim.write().revoke_all();
            assert_eq!(
                queued.min_score(&fixture.shared, Instant::now()),
                Err(SkipReason::PolicyChanged)
            );
        } else {
            assert!(receive.is_empty(), "{state} forecast cannot dispatch");
            assert_eq!(dispatched.count, 0, "{state}");
            assert_eq!(dispatched.bytes, 0, "{state}");
        }
        assert_eq!(fs::read(selected.path).unwrap(), b"retained object");
        assert_eq!(fs::read(retained.path).unwrap(), b"retained object");
    }
}

#[test]
fn predictive_batches_renew_forecast_policy_after_final_inspection_before_mutation() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        for change in ["unchanged", "disabled", "scoring", "expired", "withdrawn"] {
            let fixture = Fixture::new();
            let request = fixture.request(true);
            let selected = candidate(fixture.root.join("selected.o"));
            let batch = batch(&request, vec![selected.clone()]);
            let now = Instant::now();
            let executor = fixture.executor(batch.min_score(&fixture.shared, now).unwrap());
            let mut plan = executor.plan(batch.candidates.clone());
            plan.mode = mode;
            assert_eq!(plan.candidates.len(), 1);
            let mut current_prediction = fixture.prediction.clone();
            let mut current_scoring = fixture.scoring.clone();
            match change {
                "disabled" => current_prediction.enabled = false,
                "scoring" => current_scoring.false_positive_loss += 1.0,
                _ => {}
            }
            let checks = Cell::new(0);
            let authorize = |candidate: &CandidacyScore| {
                checks.set(checks.get() + 1);
                fixture.scope.authorize_candidate(
                    candidate,
                    &fixture.scanner,
                    fixture.platform.as_ref(),
                )?;
                if checks.get() == 2 {
                    let mut policy = fixture.shared.predictive_reclaim.write();
                    if change == "withdrawn" {
                        policy.revoke_all();
                    } else {
                        policy.update(&current_prediction, &current_scoring);
                    }
                }
                let check_at = if change == "expired" && checks.get() >= 2 {
                    now + Duration::from_secs(61)
                } else {
                    Instant::now()
                };
                let min_score = batch.min_score(&fixture.shared, check_at)?;
                if candidate.total_score < min_score {
                    return Err(SkipReason::PolicyChanged);
                }
                Ok(())
            };
            let report = executor.execute_with_hooks(&plan, None, Some(&authorize), None);
            let allowed = change == "unchanged";
            assert!(
                checks.get() >= 2,
                "{change}: the first admission must succeed"
            );
            assert_eq!(
                report.items_deleted,
                usize::from(allowed),
                "{change}: {report:?}"
            );
            assert_eq!(report.items_failed, 0, "{change}: {report:?}");
            assert!(
                report.backoff_candidates.is_empty(),
                "policy withdrawal is not an artifact failure"
            );
            if allowed {
                assert!(!selected.path.exists());
                assert_eq!(
                    report.items_quarantined,
                    usize::from(mode == DeletionMode::Quarantine),
                );
                if mode == DeletionMode::Quarantine {
                    let records = QuarantineStore::under(&fixture.root).records().unwrap();
                    assert_eq!(records.len(), 1);
                    assert_eq!(
                        fs::read(&records[0].quarantine_path).unwrap(),
                        b"retained object"
                    );
                    assert_eq!(report.bytes_freed, 0);
                }
            } else {
                assert_eq!(report.skipped_by_reason.get("policy_changed"), Some(&1));
                assert_eq!(fs::read(selected.path).unwrap(), b"retained object");
            }
        }
    }
}

#[test]
fn predictive_scan_checkpoints_stop_withdrawn_work_and_preserve_cpu_accounting() {
    for expires in [false, true] {
        let fixture = Fixture::new();
        let request = fixture.request(true);
        let now = Instant::now();
        let cpu = Arc::new(Mutex::new(0.0));
        let sampled = Arc::clone(&cpu);
        let guard = PassCpuGuard::new(Some(100.0), now, move || Some(*sampled.lock()));
        let mut limits =
            PassLimits::new(now, now + Duration::from_secs(120), Duration::ZERO, guard)
                .with_predictive_authority(&request, &fixture.shared);
        assert_eq!(limits.prescan_stop(), None);
        assert_eq!(limits.walk_stop(), None);
        *cpu.lock() = 3.5;
        if expires {
            assert!(limits.policy_changed_at(now + Duration::from_secs(61)));
        } else {
            fixture.shared.predictive_reclaim.write().revoke_all();
        }
        assert_eq!(limits.prescan_stop(), Some(PassStop::PolicyChanged));
        assert_eq!(limits.walk_stop(), Some(PassStop::PolicyChanged));
        assert!(PassStop::PolicyChanged.ends_pass());
        assert_eq!(limits.cpu.finish().to_bits(), 3.5_f64.to_bits());

        let renewed = fixture.request(true);
        assert!(
            renewed
                .authorize_predictive(&fixture.shared, Instant::now())
                .is_ok()
        );
        assert_eq!(
            limits.walk_stop(),
            Some(PassStop::PolicyChanged),
            "a fresh request cannot revive an interrupted pass",
        );
    }
}

#[test]
fn withdrawn_forecast_cannot_acknowledge_events_or_train_an_empty_full_scan() {
    for withdraw in [false, true] {
        let fixture = Fixture::new();
        let request = fixture.request(true);
        let now = Instant::now();
        let mut limits = PassLimits::new(
            now,
            now + Duration::from_secs(120),
            Duration::ZERO,
            PassCpuGuard::unlimited(now),
        )
        .with_predictive_authority(&request, &fixture.shared);
        let mut pending = PendingScannerEvents {
            reconciliation: BTreeSet::from([fixture.root.clone()]),
            ..PendingScannerEvents::default()
        };
        let mut roots = HashMap::from([(
            fixture.root.clone(),
            RootScanResult::unvisited(fixture.root.clone(), false),
        )]);
        assert_eq!(limits.walk_stop(), None);
        if withdraw {
            fixture.shared.predictive_reclaim.write().revoke_all();
        }
        let stopped = finish_authorized_scanner_walk(
            &mut limits,
            &mut pending,
            std::slice::from_ref(&fixture.root),
            &mut roots,
            Some(&[]),
            Instant::now(),
        );
        assert_eq!(stopped, withdraw.then_some(PassStop::PolicyChanged));
        assert_eq!(roots[&fixture.root].coverage_complete, !withdraw);
        assert_eq!(pending.has_work_within(&request.paths), withdraw);

        let mut scheduler = VoiScheduler::new(crate::core::config::VoiConfig::default());
        scheduler.register_path(fixture.root.clone());
        roots[&fixture.root].record_scheduler_feedback(&mut scheduler, now);
        let observed = scheduler.path_stats(&fixture.root).unwrap();
        assert_eq!(observed.scan_count, u32::from(!withdraw));
        assert_eq!(observed.last_scanned, (!withdraw).then_some(now));
    }
}

#[test]
fn withdrawn_queued_dispatch_is_not_confirmed_as_an_empty_pass() {
    let fixture = Fixture::new();
    let request = fixture.request(true);
    let admission = request.predictive_reclaim.as_ref();
    let before = fixture.shared.reclaim_events();
    assert_eq!(
        confirm_scanner_dispatch(before, admission, &fixture.shared, Instant::now()),
        Some(false),
    );
    fixture.shared.predictive_reclaim.write().revoke_all();
    assert_eq!(
        confirm_scanner_dispatch(before, admission, &fixture.shared, Instant::now()),
        None,
        "withdrawn queue authority is inconclusive, not an empty-pass escalation",
    );
    assert_eq!(
        confirm_scanner_dispatch(before, None, &fixture.shared, Instant::now()),
        Some(false),
        "ordinary dispatch confirmation keeps its existing behavior",
    );
    fixture.shared.note_reclaim();
    assert_eq!(
        confirm_scanner_dispatch(before, admission, &fixture.shared, Instant::now()),
        Some(true),
        "actual reclaim still counts even if the forecast is later withdrawn",
    );
}

#[test]
fn predictive_passes_reconcile_without_dirty_events_and_never_become_idle_event_templates() {
    let fixture = Fixture::new();
    let ordinary = fixture.request(false);
    let predictive = fixture.request(true);
    let peer = fixture.peer_request();
    let clean = BTreeSet::new();
    assert_eq!(v2_active_scan_paths(&ordinary, &clean), Some(Vec::new()));
    assert!(v2_active_scan_paths(&predictive, &clean).is_none());
    assert!(!predictive.force_full_scan);
    assert!(
        !predictive.bypass_scan_pacing(),
        "a forecast does not acquire operator pacing privileges"
    );

    let mut templates = EventPassTemplates::default();
    templates.remember(&ordinary, &fixture.scanner);
    templates.remember(&peer, &fixture.scanner);
    assert_eq!(templates.templates.len(), 2);
    templates.remember(&predictive, &fixture.scanner);
    assert_eq!(
        templates.templates.len(),
        1,
        "the old ordinary scope must not outlive its predictive replacement"
    );
    assert_eq!(templates.templates[0].paths, peer.paths);
}

#[test]
fn predictive_effective_scoring_preserves_maintenance_idleness_and_hard_vetoes() {
    let fixture = Fixture::new();
    let request = fixture.request(true);
    let scoring = request
        .scoring_config(&fixture.scoring, &fixture.shared, Instant::now())
        .unwrap();
    let mut engine = ScoringEngine::from_config(&scoring, fixture.scanner.min_file_age_minutes);
    engine.set_maintenance_pass(true);
    let input = CandidateInput {
        path: fixture.root.join("target"),
        size_bytes: 64 * 1_048_576,
        age: Duration::from_hours(24),
        classification: ArtifactClassification {
            pattern_name: Cow::Borrowed("opaque-cargo-target"),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.65,
            structural_confidence: 0.95,
            combined_confidence: 0.65,
        },
        signals: StructuralSignals {
            has_cachedir_tag: true,
            has_fingerprint: true,
            has_incremental: true,
            has_deps: true,
            ..StructuralSignals::default()
        },
        active_references: ActiveReferenceSummary::default(),
        is_open: false,
        excluded: false,
    };
    assert_eq!(
        engine.score_candidate(&input, 0.0).decision.action,
        DecisionAction::Delete
    );
    let mut young = input.clone();
    young.age = Duration::from_hours(1);
    assert_ne!(
        engine.score_candidate(&young, 0.0).decision.action,
        DecisionAction::Delete
    );
    let mut open = input.clone();
    open.is_open = true;
    assert!(engine.score_candidate(&open, 0.0).vetoed);
    let mut protected = input.clone();
    protected.excluded = true;
    assert!(engine.score_candidate(&protected, 0.0).vetoed);
    let mut source = input.clone();
    source.signals.has_git = true;
    assert!(engine.score_candidate(&source, 0.0).vetoed);
    engine.set_regret(HashMap::new(), HashSet::from(["RustTarget".to_string()]));
    assert_eq!(
        engine.score_candidate(&input, 0.0).decision.action,
        DecisionAction::Review
    );
}
