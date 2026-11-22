//! Exercise exclusion and maintenance scope through the public production APIs.
//! Fixtures use real directory walks and mutations, without a mock platform.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use storage_ballast_helper::monitor::voi_scheduler::{VoiConfig, VoiScheduler};
use storage_ballast_helper::scanner::deletion::{
    DeletionConfig, DeletionExecutor, DeletionMode, SkipReason,
};
use storage_ballast_helper::scanner::patterns::{ArtifactPatternRegistry, OpaqueTreeDisposition};
use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::scoring::{
    ArtifactCertainty, CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger,
    ScoreFactors,
};
use storage_ballast_helper::scanner::walker::{
    DirectoryWalker, WalkEntry, WalkerConfig, identity_for_path, structural_signals_for_path,
};

const PAYLOAD: &[u8] = b"generated artifact bytes";
const CACHE_TAG: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

fn cache(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::write(path.join("CACHEDIR.TAG"), CACHE_TAG).unwrap();
    fs::write(path.join("artifact.bin"), PAYLOAD).unwrap();
}

fn walk(roots: Vec<PathBuf>, excluded: Vec<PathBuf>, opaque: bool) -> Vec<WalkEntry> {
    DirectoryWalker::new(
        WalkerConfig {
            root_paths: roots,
            max_depth: 5,
            follow_symlinks: false,
            cross_devices: false,
            parallelism: 1,
            excluded_paths: excluded.into_iter().collect(),
            opaque_pruning: opaque,
        },
        ProtectionRegistry::marker_only(),
    )
    .walk()
    .unwrap()
}

// A scored fixture isolates execution admission from score tuning, as in the
// existing deletion-boundary tests. Classification and identity are observed.
fn candidate(path: &Path) -> CandidacyScore {
    CandidacyScore {
        path: path.to_path_buf(),
        identity: Some(identity_for_path(path, false).unwrap()),
        total_score: 0.99,
        factors: ScoreFactors {
            location: 0.9,
            name: 0.9,
            age: 0.9,
            size: 0.9,
            structure: 0.9,
            pressure_multiplier: 1.0,
        },
        vetoed: false,
        veto_reason: None,
        classification: ArtifactPatternRegistry::default()
            .classify(path, structural_signals_for_path(path)),
        size_bytes: fs::metadata(path.join("artifact.bin")).unwrap().len(),
        age: Duration::from_secs(48 * 3600),
        decision: DecisionOutcome {
            action: DecisionAction::Delete,
            posterior_abandoned: 0.99,
            expected_loss_keep: 1.5,
            expected_loss_delete: 0.1,
            calibration_score: 0.95,
            fallback_active: false,
            certainty: ArtifactCertainty::Definite,
            posterior_floor_applied: false,
            regret_calibration: 1.0,
            category_suspended: false,
        },
        ledger: EvidenceLedger {
            terms: Vec::new(),
            summary: "exclusion boundary fixture".to_string(),
        },
    }
}

fn executor(root: &Path, excluded: Vec<PathBuf>, mode: DeletionMode) -> DeletionExecutor {
    DeletionExecutor::new(
        DeletionConfig {
            min_score: 0.0,
            check_open_files: false,
            require_identity: true,
            excluded_paths: excluded,
            quarantine_roots: vec![root.to_path_buf()],
            mode,
            ..DeletionConfig::default()
        },
        None,
    )
}

#[test]
fn excluded_ancestors_cover_explicit_roots_and_their_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let real = base.join("real");
    let excluded = real.join("keep");
    fs::create_dir_all(excluded.join("nested/cache")).unwrap();
    fs::create_dir_all(real.join("keep-other/cache")).unwrap();
    let root_alias = base.join("root-alias");
    let excluded_alias = base.join("excluded-alias");
    let unavailable_root = base.join("unavailable-root");
    symlink(&real, &root_alias).unwrap();
    symlink(&excluded, &excluded_alias).unwrap();
    symlink(base.join("missing-volume"), &unavailable_root).unwrap();

    for root in [&real, &root_alias] {
        for exclusion in [&excluded, &excluded_alias] {
            let blocked = root.join("keep/nested");
            let healthy = root.join("keep-other");
            let entries = walk(
                vec![blocked.clone(), unavailable_root.clone(), healthy.clone()],
                vec![exclusion.clone(), PathBuf::from("/")],
                false,
            );
            assert!(
                entries
                    .iter()
                    .all(|entry| !entry.path.starts_with(&blocked))
            );
            assert!(
                entries
                    .iter()
                    .any(|entry| entry.path == healthy.join("cache"))
            );
        }
    }
}

#[test]
fn excluded_descendant_keeps_opaque_parent_while_safe_sibling_is_reclaimed() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let parent = root.join("cache");
    let kept = parent.join("keep");
    let safe = parent.join("safe-cache");
    cache(&parent);
    cache(&safe);
    fs::create_dir(&kept).unwrap();
    fs::write(kept.join("preserved.dat"), PAYLOAD).unwrap();

    let entries = walk(vec![root.clone()], vec![kept.clone()], true);
    let parent_entry = entries.iter().find(|entry| entry.path == parent).unwrap();
    assert_eq!(
        parent_entry.opaque_tree.as_ref().unwrap().disposition,
        OpaqueTreeDisposition::SignalOnly
    );
    assert!(
        parent_entry
            .walk_classification(&ArtifactPatternRegistry::default())
            .is_none()
    );
    assert!(entries.iter().any(|entry| entry.path == safe));
    assert!(entries.iter().all(|entry| !entry.path.starts_with(&kept)));

    let parent_candidate = candidate(&parent);
    let unrestricted = executor(&root, Vec::new(), DeletionMode::Unlink);
    assert!(
        unrestricted
            .explain_preflight(&parent_candidate, None)
            .is_ok()
    );
    let guarded = executor(
        &root,
        vec![kept.clone(), PathBuf::from("/")],
        DeletionMode::Unlink,
    );
    let plan = guarded.plan(vec![parent_candidate, candidate(&safe)]);
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].path, safe);
    assert_eq!(plan.refused.len(), 1);
    assert_eq!(plan.refused[0].1, SkipReason::SacredStowaway);
    let report = guarded.execute(&plan, None);
    assert_eq!(report.items_deleted, 1, "{report:?}");
    assert_eq!(report.items_failed, 0, "{report:?}");
    assert!(!safe.exists());
    assert_eq!(fs::read(kept.join("preserved.dat")).unwrap(), PAYLOAD);
    assert_eq!(fs::read(parent.join("artifact.bin")).unwrap(), PAYLOAD);
}

#[test]
fn retargeted_exclusion_revokes_a_plan_without_changing_candidate_identity() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let path = root.join("cache");
        cache(&path);
        fs::create_dir(path.join("keep")).unwrap();
        fs::write(path.join("keep/preserved.dat"), PAYLOAD).unwrap();
        let outside = root.join("outside");
        fs::create_dir_all(outside.join("keep")).unwrap();
        let alias = root.join("policy-parent");
        symlink(&outside, &alias).unwrap();
        let excluded = alias.join("keep");
        assert_eq!(
            storage_ballast_helper::core::paths::resolve_absolute_path(&excluded),
            outside.join("keep")
        );
        let item = candidate(&path);
        let guarded = executor(&root, vec![excluded], mode);
        let plan = guarded.plan(vec![item.clone()]);
        assert_eq!(plan.candidates.len(), 1);
        assert!(guarded.explain_preflight(&item, None).is_ok());

        fs::rename(&alias, root.join("previous-policy-parent")).unwrap();
        symlink(&path, &alias).unwrap();
        assert_eq!(
            item.identity,
            Some(identity_for_path(&path, false).unwrap())
        );
        let report = guarded.execute(&plan, None);
        assert_eq!(report.items_deleted, 0, "{report:?}");
        assert_eq!(report.items_failed, 0, "{report:?}");
        assert_eq!(report.skipped_by_reason.get("sacred_stowaway"), Some(&1));
        assert_eq!(fs::read(path.join("keep/preserved.dat")).unwrap(), PAYLOAD);
        assert_eq!(fs::read(path.join("artifact.bin")).unwrap(), PAYLOAD);
    }
}

#[test]
fn maintenance_reload_preserves_evidence_and_spends_budget_on_eligible_roots() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let removed = root.join("a-removed");
    let recovering = root.join("b-recovering");
    let healthy = root.join("c-healthy");
    fs::create_dir_all(healthy.join("artifact")).unwrap();
    for enabled in [false, true] {
        let now = Instant::now();
        let mut scheduler = VoiScheduler::new(VoiConfig {
            enabled,
            scan_budget_per_interval: 1,
            ..VoiConfig::default()
        });
        scheduler.reconcile_paths(&[removed.clone(), healthy.clone()]);
        scheduler.record_scan_result(&healthy, 4096, 1, 0, 1.0, now);
        scheduler.record_dirty(&healthy, true, now);
        scheduler.reconcile_paths(&[recovering.clone(), healthy.clone()]);
        assert!(scheduler.path_stats(&removed).is_none());
        let stats = scheduler.path_stats(&healthy).unwrap();
        assert_eq!(stats.scan_count, 1);
        assert_eq!(stats.last_scanned, Some(now));
        assert!(stats.dirty_pending);

        let plan = scheduler.schedule_within(
            &[
                healthy.clone(),
                removed.clone(),
                healthy.clone(),
                root.join("unknown"),
            ],
            now,
        );
        assert_eq!(plan.budget_used, 1);
        assert_eq!(plan.paths.len(), 1);
        assert_eq!(plan.paths[0].path, healthy);
        let entries = walk(
            plan.paths.into_iter().map(|entry| entry.path).collect(),
            Vec::new(),
            false,
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.path == healthy.join("artifact"))
        );
        scheduler.record_scan_result(&removed, 8192, 1, 0, 1.0, now);
        assert!(
            scheduler.path_stats(&removed).is_none(),
            "late feedback must not restore revoked scope"
        );
    }
}
