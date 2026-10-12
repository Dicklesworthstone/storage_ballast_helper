//! Exercise the public mutation APIs, not just the planner's filters.
//! A forged/stale plan must not bypass a refusal, and a recoverable cleanup
//! must not become an irreversible unlink when its recovery store is busy.

#![cfg(unix)]

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use storage_ballast_helper::scanner::decision_record::stable_decision_id;
use storage_ballast_helper::scanner::deletion::{
    CheckedDeletion, DeletionConfig, DeletionExecutor, DeletionMode, DeletionPlan, SkipReason,
};
use storage_ballast_helper::scanner::patterns::{ArtifactCategory, ArtifactClassification};
use storage_ballast_helper::scanner::quarantine::QuarantineStore;
use storage_ballast_helper::scanner::scoring::{
    ArtifactCertainty, CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger,
    ScoreFactors,
};
use storage_ballast_helper::scanner::walker::identity_for_path;

const PAYLOAD: &[u8] = b"artifact data";

fn scratch() -> tempfile::TempDir {
    // Do not inherit a TMPDIR redirected under the protected source roots.
    tempfile::tempdir_in("/tmp").expect("neutral filesystem fixture")
}

fn candidate(path: &Path) -> CandidacyScore {
    CandidacyScore {
        path: path.to_path_buf(),
        identity: Some(identity_for_path(path, false).unwrap()),
        total_score: 0.9,
        factors: ScoreFactors {
            location: 0.8,
            name: 0.9,
            age: 0.7,
            size: 0.6,
            structure: 0.85,
            pressure_multiplier: 1.0,
        },
        vetoed: false,
        veto_reason: None,
        classification: ArtifactClassification {
            pattern_name: Cow::Borrowed("target"),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.95,
            structural_confidence: 0.90,
            combined_confidence: 0.92,
        },
        size_bytes: PAYLOAD.len() as u64,
        age: Duration::from_secs(3600),
        decision: DecisionOutcome {
            action: DecisionAction::Delete,
            posterior_abandoned: 0.92,
            expected_loss_keep: 1.5,
            expected_loss_delete: 0.3,
            calibration_score: 0.85,
            fallback_active: false,
            certainty: ArtifactCertainty::Definite,
            posterior_floor_applied: false,
            regret_calibration: 1.0,
            category_suspended: false,
        },
        ledger: EvidenceLedger {
            terms: Vec::new(),
            summary: "execution boundary fixture".to_string(),
        },
    }
}

fn artifact(root: &Path, name: &str) -> CandidacyScore {
    let path = root.join(name);
    fs::write(&path, PAYLOAD).unwrap();
    candidate(&path)
}

fn config(root: &Path, mode: DeletionMode) -> DeletionConfig {
    DeletionConfig {
        mode,
        check_open_files: false,
        require_identity: true,
        quarantine_roots: vec![root.to_path_buf()],
        ..DeletionConfig::default()
    }
}

fn raw_plan(candidates: Vec<CandidacyScore>, mode: DeletionMode) -> DeletionPlan {
    DeletionPlan {
        estimated_items: candidates.len(),
        total_reclaimable_bytes: candidates
            .iter()
            .map(|item| item.size_bytes)
            .fold(0, u64::saturating_add),
        candidates,
        mode,
        refused: Vec::new(),
    }
}

#[test]
fn direct_tree_cleanup_does_not_follow_links_or_open_special_entries() {
    let dir = scratch();
    let root = dir.path().join("target");
    let nested = root.join("debug/deps");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("artifact.o"), PAYLOAD).unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("precious"), b"outside data").unwrap();
    fs::write(dir.path().join("sibling"), b"unrelated sibling").unwrap();
    symlink(&outside, nested.join("directory-link")).unwrap();
    symlink(outside.join("precious"), root.join("file-link")).unwrap();
    symlink("absent", root.join("dangling-link")).unwrap();
    nix::unistd::mkfifo(
        &root.join("pipe"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();

    let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);
    assert_eq!(
        executor
            .delete_candidate_checked(&candidate(&root), None)
            .unwrap(),
        CheckedDeletion::Deleted
    );
    assert!(fs::symlink_metadata(&root).is_err());
    assert_eq!(fs::read(outside.join("precious")).unwrap(), b"outside data");
    assert_eq!(
        fs::read(dir.path().join("sibling")).unwrap(),
        b"unrelated sibling"
    );
    // Direct and emergency cleanup cannot allocate a recovery store first.
    assert!(!dir.path().join(".sbh").exists());
}

#[test]
fn direct_cache_cleanup_preserves_external_hardlink_permissions() {
    for (name, pattern, category) in [
        ("gomodcache", "go-module-cache", ArtifactCategory::GoCache),
        (
            "cargo-cache",
            "opaque-cargo-cache",
            ArtifactCategory::CacheDir,
        ),
    ] {
        let dir = scratch();
        let root = dir.path().join(name);
        let module = root.join("module");
        fs::create_dir_all(&module).unwrap();
        let leaf = module.join("artifact.bin");
        fs::write(&leaf, PAYLOAD).unwrap();
        let retained = dir.path().join("retained-hardlink");
        fs::hard_link(&leaf, &retained).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&module, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
        let original_mode = fs::metadata(&retained).unwrap().permissions().mode();
        let mut item = candidate(&root);
        item.classification.pattern_name = Cow::Borrowed(pattern);
        item.classification.category = category;
        let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);

        let report = executor.execute(&executor.plan(vec![item]), None);
        // Restore fixture directories on failure so a failed regression still
        // leaves TempDir able to clean up. Never change the hardlinked file.
        let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o755));
        let _ = fs::set_permissions(&module, fs::Permissions::from_mode(0o755));
        assert_eq!(report.items_deleted, 1, "{pattern}: {:?}", report.errors);
        assert_eq!(report.items_failed, 0, "{pattern}");
        assert_eq!(report.items_skipped, 0, "{pattern}");
        assert_eq!(report.items_quarantined, 0, "{pattern}");
        assert!(fs::symlink_metadata(&root).is_err(), "{pattern}");
        assert_eq!(fs::read(&retained).unwrap(), PAYLOAD, "{pattern}");
        assert_eq!(
            fs::metadata(&retained).unwrap().permissions().mode(),
            original_mode,
            "cleanup must not chmod surviving hardlinks: {pattern}"
        );
        assert!(!dir.path().join(".sbh").exists(), "{pattern}");
    }
}

#[test]
fn ordinary_direct_cleanup_keeps_readonly_directories_as_a_permission_boundary() {
    let dir = scratch();
    let root = dir.path().join("target");
    let locked = root.join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::write(locked.join("artifact.bin"), PAYLOAD).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    // UID 0 can still lack DAC override in a user namespace. Probe the actual
    // permission boundary rather than skipping a meaningful test by UID alone.
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(locked.join("permission-probe"))
    {
        Ok(_) => {
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("TEST SKIP: this process bypasses readonly directory permissions");
            return;
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => panic!("readonly-directory fixture probe failed: {error}"),
    }
    let item = candidate(&root);
    let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);
    let preflight = executor.explain_preflight(&item, None);
    let report = executor.execute(&executor.plan(vec![item]), None);
    let unchanged_mode = fs::metadata(&locked).map(|meta| meta.permissions().mode() & 0o777);
    let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));

    assert!(
        preflight.is_ok(),
        "the fixture must reach removal: {preflight:?}"
    );
    assert_eq!(report.items_deleted, 0);
    assert_eq!(report.items_failed, 1);
    assert_eq!(report.items_skipped, 0);
    assert_eq!(report.bytes_freed, 0);
    assert_eq!(unchanged_mode.unwrap(), 0o555);
    assert_eq!(fs::read(locked.join("artifact.bin")).unwrap(), PAYLOAD);
    assert!(!dir.path().join(".sbh").exists());
}

#[test]
fn live_category_refusal_is_a_typed_skip_in_both_modes_and_dry_runs() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        for dry_run in [false, true] {
            for include_review in [false, true] {
                let dir = scratch();
                let target = dir.path().join("target");
                fs::create_dir(&target).unwrap();
                fs::write(target.join("artifact.o"), PAYLOAD).unwrap();
                let mut item = candidate(&target);
                if include_review {
                    item.decision.action = DecisionAction::Review;
                }
                let mut cfg = config(dir.path(), mode);
                cfg.dry_run = dry_run;
                cfg.include_review = include_review;
                let executor = DeletionExecutor::new(cfg, None);
                let plan = executor.plan(vec![item]);
                assert_eq!(plan.estimated_items, 1);
                let calls = Cell::new(0);
                let authorize = |item: &CandidacyScore| {
                    assert_eq!(item.path, target);
                    assert_eq!(item.classification.category, ArtifactCategory::RustTarget);
                    calls.set(calls.get() + 1);
                    Err(SkipReason::CategorySuspended)
                };

                let report = executor.execute_with_guard(&plan, None, Some(&authorize));
                assert_eq!(calls.get(), 1);
                assert_eq!(
                    report.sacred_scans, 1,
                    "full preflight must precede the guard"
                );
                assert_eq!(report.items_skipped, 1);
                assert_eq!(report.skipped_by_reason.get("category_suspended"), Some(&1));
                assert!(!report.skipped_by_reason.contains_key("target_free_reached"));
                assert_eq!(report.items_deleted, 0);
                assert_eq!(report.items_failed, 0);
                assert_eq!(report.items_would_delete, 0);
                assert_eq!(report.items_quarantined, 0);
                assert_eq!(report.quarantine_unavailable, 0);
                assert_eq!(report.bytes_freed, 0);
                assert_eq!(report.bytes_freed_observed, Some(0));
                assert_eq!(report.bytes_would_free, 0);
                assert_eq!(report.bytes_quarantined, 0);
                assert!(report.errors.is_empty());
                assert!(report.deleted_paths.is_empty());
                assert!(report.backoff_candidates.is_empty());
                assert!(!report.circuit_breaker_tripped);
                assert_eq!(fs::read(target.join("artifact.o")).unwrap(), PAYLOAD);
                assert!(!dir.path().join(".sbh").exists());
            }
        }
    }
}

#[test]
fn live_authorization_cannot_bypass_preflight_protection() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let target = dir.path().join("target");
        let nested = target.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(target.join("artifact.o"), PAYLOAD).unwrap();
        let executor = DeletionExecutor::new(config(dir.path(), mode), None);
        let plan = executor.plan(vec![candidate(&target)]);
        assert_eq!(plan.estimated_items, 1);
        // Descendant protection appears after planning. It must be found
        // by the full preflight before any live authorization is requested.
        fs::write(nested.join(".sbh-protect"), b"").unwrap();
        let calls = Cell::new(0);
        let authorize = |_: &CandidacyScore| {
            calls.set(calls.get() + 1);
            Ok(())
        };

        let report = executor.execute_with_guard(&plan, None, Some(&authorize));
        assert_eq!(calls.get(), 0);
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(report.skipped_by_reason.get("sacred_stowaway"), Some(&1));
        assert_eq!(report.bytes_freed, 0);
        assert!(nested.join(".sbh-protect").exists());
        assert_eq!(fs::read(target.join("artifact.o")).unwrap(), PAYLOAD);
        assert!(!dir.path().join(".sbh").exists());
    }
}

#[test]
fn unlink_observer_runs_before_the_next_candidate_with_its_completion_time() {
    let dir = scratch();
    let first = artifact(dir.path(), "first");
    let second = artifact(dir.path(), "second");
    let plan = raw_plan(vec![first.clone(), second.clone()], DeletionMode::Unlink);
    let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);
    let observed = RefCell::new(Vec::new());
    let started = Instant::now();
    let on_unlinked = |item: &CandidacyScore, completed_at: Instant| {
        assert!(completed_at >= started);
        assert!(completed_at <= Instant::now());
        assert!(!item.path.exists());
        if observed.borrow().is_empty() {
            assert_eq!(item.path, first.path);
            assert!(
                second.path.exists(),
                "observer must run before the next deletion"
            );
            // Registration may wait for a detector lock. The timestamp
            // handed to it must remain the earlier removal completion.
            let delay = Duration::from_millis(10);
            std::thread::sleep(delay);
            assert!(completed_at.elapsed() >= delay);
        } else {
            assert_eq!(item.path, second.path);
        }
        observed
            .borrow_mut()
            .push((item.path.clone(), completed_at));
    };

    let report = executor.execute_with_hooks(&plan, None, None, Some(&on_unlinked));
    assert_eq!(report.items_deleted, 2);
    assert_eq!(report.items_failed, 0);
    assert_eq!(report.items_skipped, 0);
    let observed = observed.into_inner();
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].0, first.path);
    assert_eq!(observed[1].0, second.path);
    assert!(observed[0].1 < observed[1].1);
    assert_eq!(report.deleted_paths, vec![first.path, second.path]);
}

#[test]
fn unlink_observer_notifies_only_successful_real_permanent_removals() {
    for (mode, dry_run, refuse, replace_before_mutation) in [
        (DeletionMode::Unlink, false, false, false),
        (DeletionMode::Quarantine, false, false, false),
        (DeletionMode::Unlink, true, false, false),
        (DeletionMode::Quarantine, true, false, false),
        (DeletionMode::Unlink, false, true, false),
        (DeletionMode::Quarantine, false, true, false),
        (DeletionMode::Unlink, false, false, true),
        (DeletionMode::Quarantine, false, false, true),
    ] {
        let dir = scratch();
        let item = artifact(dir.path(), "target");
        let original = dir.path().join("original");
        let mut cfg = config(dir.path(), mode);
        cfg.dry_run = dry_run;
        let executor = DeletionExecutor::new(cfg, None);
        let plan = executor.plan(vec![item.clone()]);
        assert_eq!(plan.estimated_items, 1);
        let authorize = |candidate: &CandidacyScore| {
            if refuse {
                return Err(SkipReason::CategorySuspended);
            }
            if replace_before_mutation {
                // Deterministic backend failure, independent of uid and
                // permission overrides: keep the original inode alive and
                // substitute a different one after preflight has passed.
                fs::rename(&candidate.path, &original).unwrap();
                fs::write(&candidate.path, b"replacement data").unwrap();
            }
            Ok(())
        };
        let notifications = Cell::new(0);
        let on_unlinked = |candidate: &CandidacyScore, _: Instant| {
            assert_eq!(candidate.path, item.path);
            notifications.set(notifications.get() + 1);
        };

        let report = executor.execute_with_hooks(&plan, None, Some(&authorize), Some(&on_unlinked));
        let removed = !dry_run && !refuse && !replace_before_mutation;
        assert_eq!(report.items_deleted, usize::from(removed));
        assert_eq!(report.items_failed, usize::from(replace_before_mutation));
        assert_eq!(report.items_skipped, usize::from(refuse));
        assert_eq!(report.items_would_delete, usize::from(dry_run));
        assert_eq!(
            report.items_quarantined,
            usize::from(removed && mode == DeletionMode::Quarantine)
        );
        assert_eq!(
            notifications.get(),
            usize::from(removed && mode == DeletionMode::Unlink)
        );
        if replace_before_mutation {
            assert_eq!(fs::read(original).unwrap(), PAYLOAD);
            assert_eq!(fs::read(item.path).unwrap(), b"replacement data");
        } else if !removed {
            assert_eq!(fs::read(item.path).unwrap(), PAYLOAD);
        }
    }
}

type RefusalCase = (&'static str, fn(&mut CandidacyScore), SkipReason);

#[test]
#[allow(clippy::too_many_lines)] // one table of refusal cases
fn public_plans_and_direct_calls_cannot_bypass_decision_refusals() {
    let cases: &[RefusalCase] = &[
        ("veto", |c| c.vetoed = true, SkipReason::Vetoed),
        (
            "veto-reason",
            |c| c.veto_reason = Some("protected by scorer".into()),
            SkipReason::Vetoed,
        ),
        (
            "suspended",
            |c| c.decision.category_suspended = true,
            SkipReason::Vetoed,
        ),
        (
            "keep",
            |c| c.decision.action = DecisionAction::Keep,
            SkipReason::Vetoed,
        ),
        (
            "review",
            |c| c.decision.action = DecisionAction::Review,
            SkipReason::Vetoed,
        ),
        ("weak", |c| c.total_score = 0.1, SkipReason::BelowThreshold),
        (
            "nan-score",
            |c| c.total_score = f64::NAN,
            SkipReason::BelowThreshold,
        ),
        (
            "infinite-score",
            |c| c.total_score = f64::INFINITY,
            SkipReason::BelowThreshold,
        ),
        (
            "negative-score",
            |c| c.total_score = -1.0,
            SkipReason::BelowThreshold,
        ),
        (
            "nan-posterior",
            |c| c.decision.posterior_abandoned = f64::NAN,
            SkipReason::Vetoed,
        ),
        (
            "large-posterior",
            |c| c.decision.posterior_abandoned = 1.1,
            SkipReason::Vetoed,
        ),
        (
            "negative-posterior",
            |c| c.decision.posterior_abandoned = -0.1,
            SkipReason::Vetoed,
        ),
        (
            "negative-loss",
            |c| c.decision.expected_loss_delete = -1.0,
            SkipReason::Vetoed,
        ),
        (
            "infinite-loss",
            |c| c.decision.expected_loss_keep = f64::INFINITY,
            SkipReason::Vetoed,
        ),
        (
            "nan-calibration",
            |c| c.decision.calibration_score = f64::NAN,
            SkipReason::Vetoed,
        ),
        (
            "nan-regret",
            |c| c.decision.regret_calibration = f64::NAN,
            SkipReason::Vetoed,
        ),
    ];
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let executor = DeletionExecutor::new(config(dir.path(), mode), None);
        for &(name, corrupt, expected) in cases {
            let mut item = artifact(dir.path(), name);
            corrupt(&mut item);
            assert!(
                executor.plan(vec![item.clone()]).candidates.is_empty(),
                "{name}"
            );
            // Deliberately bypass plan() and supply an otherwise plausible plan.
            let report = executor.execute(&raw_plan(vec![item.clone()], mode), None);
            assert_eq!(report.items_deleted, 0, "{name} {mode:?}");
            assert_eq!(report.items_skipped, 1, "{name} {mode:?}");
            assert_eq!(
                report.skipped_by_reason.get(expected.as_str()),
                Some(&1),
                "{name}"
            );
            assert_eq!(report.bytes_freed, 0, "{name}");
            assert_eq!(
                executor.delete_candidate_checked(&item, None).unwrap(),
                CheckedDeletion::Skipped(expected),
                "{name} {mode:?}"
            );
            assert_eq!(fs::read(&item.path).unwrap(), PAYLOAD, "{name}");
        }
        assert!(!QuarantineStore::under(dir.path()).root().exists());
    }
}

#[test]
fn receiving_executor_rechecks_a_plan_made_under_a_weaker_policy() {
    let dir = scratch();
    let mut item = artifact(dir.path(), "review-target");
    item.decision.action = DecisionAction::Review;
    let mut emergency_config = config(dir.path(), DeletionMode::Unlink);
    emergency_config.include_review = true;
    let emergency = DeletionExecutor::new(emergency_config, None);
    let plan = emergency.plan(vec![item.clone()]);
    assert_eq!(plan.estimated_items, 1);

    let normal = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);
    let refused = normal.execute(&plan, None);
    assert_eq!(refused.items_deleted, 0);
    assert_eq!(refused.skipped_by_reason.get("vetoed"), Some(&1));
    assert_eq!(fs::read(&item.path).unwrap(), PAYLOAD);

    // Explicit emergency consent still works; it cannot bypass suspension.
    item.decision.category_suspended = true;
    assert_eq!(
        emergency.delete_candidate_checked(&item, None).unwrap(),
        CheckedDeletion::Skipped(SkipReason::Vetoed)
    );
    item.decision.category_suspended = false;
    assert_eq!(
        emergency.delete_candidate_checked(&item, None).unwrap(),
        CheckedDeletion::Deleted
    );
    assert!(!item.path.exists());
}

#[test]
fn changing_the_threshold_invalidates_previously_planned_candidates() {
    let dir = scratch();
    let item = artifact(dir.path(), "target");
    let old = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);
    let plan = old.plan(vec![item.clone()]);
    let mut strict = config(dir.path(), DeletionMode::Unlink);
    strict.min_score = 0.95;
    let executor = DeletionExecutor::new(strict, None);
    let report = executor.execute(&plan, None);
    assert_eq!(report.skipped_by_reason.get("below_threshold"), Some(&1));
    assert_eq!(report.items_deleted, 0);
    assert_eq!(fs::read(item.path).unwrap(), PAYLOAD);
}

#[test]
fn invalid_thresholds_fail_closed_at_both_public_entry_points() {
    let dir = scratch();
    let item = artifact(dir.path(), "target");
    for threshold in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1] {
        let mut cfg = config(dir.path(), DeletionMode::Unlink);
        cfg.min_score = threshold;
        let executor = DeletionExecutor::new(cfg, None);
        assert!(executor.plan(vec![item.clone()]).candidates.is_empty());
        let report = executor.execute(&raw_plan(vec![item.clone()], DeletionMode::Unlink), None);
        assert_eq!(report.skipped_by_reason.get("below_threshold"), Some(&1));
        assert_eq!(
            executor.delete_candidate_checked(&item, None).unwrap(),
            CheckedDeletion::Skipped(SkipReason::BelowThreshold)
        );
        assert_eq!(fs::read(&item.path).unwrap(), PAYLOAD);
    }
}

#[test]
fn dry_run_does_not_count_ineligible_candidates_as_would_delete() {
    let dir = scratch();
    let mut refused = artifact(dir.path(), "refused");
    refused.vetoed = true;
    let good = artifact(dir.path(), "good");
    let mut cfg = config(dir.path(), DeletionMode::Unlink);
    cfg.dry_run = true;
    cfg.check_open_files = true;
    let executor = DeletionExecutor::new(cfg, None);
    let report = executor.execute(
        &raw_plan(vec![refused.clone(), good.clone()], DeletionMode::Unlink),
        None,
    );
    assert_eq!(report.items_deleted, 0);
    assert_eq!(report.items_would_delete, 1);
    assert_eq!(report.bytes_would_free, good.size_bytes);
    assert_eq!(report.skipped_by_reason.get("vetoed"), Some(&1));
    assert!(executor.delete_candidate_checked(&good, None).is_err());
    assert_eq!(fs::read(refused.path).unwrap(), PAYLOAD);
    assert_eq!(fs::read(good.path).unwrap(), PAYLOAD);
}

#[test]
fn required_open_file_evidence_is_not_optional_for_direct_mutations() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let item = artifact(dir.path(), "target");
        let mut cfg = config(dir.path(), mode);
        cfg.check_open_files = true;
        let executor = DeletionExecutor::new(cfg, None);
        assert_eq!(
            executor.delete_candidate_checked(&item, None).unwrap(),
            CheckedDeletion::Skipped(SkipReason::OpenScanIncomplete)
        );
        assert_eq!(fs::read(&item.path).unwrap(), PAYLOAD);
        assert!(!QuarantineStore::under(dir.path()).root().exists());
        let empty_complete_scan = HashSet::new();
        let outcome = executor
            .delete_candidate_checked(&item, Some(&empty_complete_scan))
            .unwrap();
        match mode {
            DeletionMode::Unlink => assert_eq!(outcome, CheckedDeletion::Deleted),
            DeletionMode::Quarantine => {
                assert_eq!(outcome, CheckedDeletion::Quarantined);
                let store = QuarantineStore::under(dir.path());
                let id = stable_decision_id(&item.path, item.identity, item.size_bytes);
                store.restore(&id, false).unwrap();
                assert_eq!(fs::read(item.path).unwrap(), PAYLOAD);
            }
        }
    }
}

#[test]
fn a_known_open_path_remains_a_veto_with_explicit_review_consent() {
    let dir = scratch();
    let mut item = artifact(dir.path(), "target");
    item.decision.action = DecisionAction::Review;
    let mut cfg = config(dir.path(), DeletionMode::Unlink);
    cfg.check_open_files = true;
    cfg.include_review = true;
    let executor = DeletionExecutor::new(cfg, None);
    let handle = fs::File::open(&item.path).unwrap();
    let open = HashSet::from([fs::canonicalize(&item.path).unwrap()]);
    assert_eq!(
        executor
            .delete_candidate_checked(&item, Some(&open))
            .unwrap(),
        CheckedDeletion::Skipped(SkipReason::FileOpen)
    );
    assert_eq!(fs::read(&item.path).unwrap(), PAYLOAD);
    drop(handle);
}

#[test]
fn a_busy_quarantine_store_preserves_the_candidate_and_can_be_retried() {
    use rustix::fs::{FlockOperation, flock};

    let dir = scratch();
    let item = artifact(dir.path(), "target");
    let store = QuarantineStore::under(dir.path());
    fs::create_dir_all(store.root()).unwrap();
    let lock = fs::File::open(store.root()).unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Quarantine), None);
    let plan = executor.plan(vec![item.clone()]);

    let report = executor.execute(&plan, None);
    assert_eq!(report.items_failed, 1);
    assert_eq!(report.quarantine_unavailable, 1);
    assert_eq!(report.items_deleted, 0);
    assert_eq!(report.bytes_freed, 0);
    assert_eq!(report.backoff_candidates.len(), 1);
    assert!(report.errors[0].error.contains("candidate retained"));
    assert!(executor.delete_candidate_checked(&item, None).is_err());
    assert_eq!(fs::read(&item.path).unwrap(), PAYLOAD);

    drop(lock);
    let retried = executor.execute(&plan, None);
    assert_eq!(retried.items_failed, 0);
    assert_eq!(retried.items_quarantined, 1);
    assert_eq!(retried.bytes_freed, 0);
    let id = stable_decision_id(&item.path, item.identity, item.size_bytes);
    store.restore(&id, false).unwrap();
    assert_eq!(fs::read(item.path).unwrap(), PAYLOAD);
}

#[test]
fn duplicate_recovery_ids_never_delete_the_rebuilt_original() {
    let dir = scratch();
    let mut item = artifact(dir.path(), "target");
    // Legacy callers may omit identities. Equal path/size then produces an
    // equal decision id when a build recreates the candidate.
    item.identity = None;
    let mut cfg = config(dir.path(), DeletionMode::Quarantine);
    cfg.require_identity = false;
    let executor = DeletionExecutor::new(cfg, None);
    assert_eq!(
        executor.delete_candidate_checked(&item, None).unwrap(),
        CheckedDeletion::Quarantined
    );
    let rebuilt = b"rebuilt bytes";
    fs::write(&item.path, rebuilt).unwrap();
    let report = executor.execute(
        &raw_plan(vec![item.clone()], DeletionMode::Quarantine),
        None,
    );
    assert_eq!(report.items_deleted, 0);
    assert_eq!(report.quarantine_unavailable, 1);
    assert!(executor.delete_candidate_checked(&item, None).is_err());
    assert_eq!(fs::read(&item.path).unwrap(), rebuilt);

    let store = QuarantineStore::under(dir.path());
    let id = stable_decision_id(&item.path, item.identity, item.size_bytes);
    let held = store.record(&id).unwrap().unwrap();
    assert_eq!(fs::read(&held.quarantine_path).unwrap(), PAYLOAD);
    let restored = store.restore(&id, true).unwrap();
    assert_eq!(fs::read(restored.restored_to).unwrap(), PAYLOAD);
    assert_eq!(fs::read(item.path).unwrap(), rebuilt);
}

fn block_store(root: &Path) -> PathBuf {
    let store = QuarantineStore::under(root);
    fs::create_dir_all(store.root().parent().unwrap()).unwrap();
    fs::write(store.root(), b"unusable store").unwrap();
    store.root().to_path_buf()
}

#[test]
fn unavailable_quarantine_needs_an_explicit_unlink_plan_to_remove() {
    let dir = scratch();
    let item = artifact(dir.path(), "target");
    let blocked = block_store(dir.path());
    let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Quarantine), None);
    let error = executor.delete_candidate_checked(&item, None).unwrap_err();
    assert!(error.to_string().contains("candidate retained"));
    assert_eq!(fs::read(&item.path).unwrap(), PAYLOAD);

    let mut plan = executor.plan(vec![item.clone()]);
    let refused = executor.execute(&plan, None);
    assert_eq!(refused.items_failed, 1);
    assert!(refused.deleted_paths.is_empty());
    assert_eq!(refused.bytes_freed, 0);
    // Preserve the existing explicit pressure/emergency path. A failure
    // must not choose it on the caller's behalf.
    plan.mode = DeletionMode::Unlink;
    let removed = executor.execute(&plan, None);
    assert_eq!(removed.items_deleted, 1);
    assert_eq!(removed.bytes_freed, item.size_bytes);
    assert_eq!(removed.quarantine_unavailable, 0);
    assert!(!item.path.exists());
    assert_eq!(fs::read(blocked).unwrap(), b"unusable store");
}

#[test]
fn repeated_quarantine_failures_trip_the_breaker_without_losing_payloads() {
    let dir = scratch();
    block_store(dir.path());
    let items = (0..5)
        .map(|i| artifact(dir.path(), &format!("target-{i}")))
        .collect::<Vec<_>>();
    let mut cfg = config(dir.path(), DeletionMode::Quarantine);
    cfg.circuit_breaker_threshold = 2;
    let executor = DeletionExecutor::new(cfg, None);
    let report = executor.execute(&executor.plan(items.clone()), None);
    assert!(report.circuit_breaker_tripped);
    assert_eq!(report.items_failed, 2);
    assert_eq!(report.quarantine_unavailable, 2);
    assert_eq!(report.items_deleted, 0);
    assert_eq!(report.bytes_freed, 0);
    for item in items {
        assert_eq!(fs::read(item.path).unwrap(), PAYLOAD);
    }
}

#[test]
fn one_unavailable_store_does_not_prevent_an_independent_quarantine() {
    let dir = scratch();
    let first_root = dir.path().join("blocked");
    let second_root = dir.path().join("healthy");
    fs::create_dir_all(&first_root).unwrap();
    fs::create_dir_all(&second_root).unwrap();
    block_store(&first_root);
    let first = artifact(&first_root, "target");
    let second = artifact(&second_root, "target");
    let mut cfg = config(dir.path(), DeletionMode::Quarantine);
    cfg.quarantine_roots = vec![first_root, second_root.clone()];
    let executor = DeletionExecutor::new(cfg, None);
    let report = executor.execute(
        &raw_plan(
            vec![first.clone(), second.clone()],
            DeletionMode::Quarantine,
        ),
        None,
    );
    assert_eq!(report.items_failed, 1);
    assert_eq!(report.quarantine_unavailable, 1);
    assert_eq!(report.items_quarantined, 1);
    assert_eq!(report.bytes_freed, 0);
    assert_eq!(report.deleted_paths, vec![second.path.clone()]);
    assert_eq!(fs::read(first.path).unwrap(), PAYLOAD);
    let store = QuarantineStore::under(&second_root);
    let id = stable_decision_id(&second.path, second.identity, second.size_bytes);
    store.restore(&id, false).unwrap();
    assert_eq!(fs::read(second.path).unwrap(), PAYLOAD);
}

#[test]
fn byte_estimates_saturate_instead_of_overflowing_a_valid_plan_or_report() {
    let dir = scratch();
    let mut first = artifact(dir.path(), "first");
    let mut second = artifact(dir.path(), "second");
    first.size_bytes = u64::MAX;
    second.size_bytes = u64::MAX;
    let mut cfg = config(dir.path(), DeletionMode::Unlink);
    cfg.dry_run = true;
    let executor = DeletionExecutor::new(cfg, None);
    let plan = executor.plan(vec![first, second]);
    assert_eq!(plan.total_reclaimable_bytes, u64::MAX);
    let report = executor.execute(&plan, None);
    assert_eq!(report.items_would_delete, 2);
    assert_eq!(report.bytes_would_free, u64::MAX);
    assert_eq!(report.bytes_freed, 0);
}
