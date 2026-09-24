//! Exercise the public mutation APIs, not just the planner's filters.
//! A forged/stale plan must not bypass a refusal, and a recoverable cleanup
//! must not become an irreversible unlink when its recovery store is busy.

#![cfg(unix)]

use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
