//! Source-root policy at the real unlink and quarantine boundaries (#33).

use super::*;
use crate::scanner::scoring::{ArtifactCertainty, DecisionOutcome, EvidenceLedger};
use std::borrow::Cow;

fn scratch() -> tempfile::TempDir {
    for base in [
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ] {
        if base.is_dir()
            && !is_hardcoded_source_tree(&base)
            && let Ok(dir) = tempfile::tempdir_in(base)
        {
            // A test runner may redirect TMPDIR into its checkout. An
            // ancestor repository would invalidate a clear-root fixture.
            if !dir
                .path()
                .ancestors()
                .skip(1)
                .any(|p| p.join(".git").exists())
            {
                return dir;
            }
        }
    }
    panic!("no neutral scratch directory for source-root safety regression");
}

fn git(root: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git is required by repository protection tests");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn repository(root: &Path) {
    fs::create_dir_all(root).unwrap();
    git(root, &["init", "--initial-branch=main"]);
}

fn artifact(path: &Path) -> CandidacyScore {
    fs::create_dir_all(path.join("debug/deps")).unwrap();
    fs::write(path.join("debug/deps/generated.o"), b"object bytes").unwrap();
    CandidacyScore {
        path: path.to_path_buf(),
        identity: Some(walker::identity_for_path(path, false).unwrap()),
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
        classification: ArtifactClassification {
            pattern_name: Cow::Borrowed("target"),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.95,
            structural_confidence: 0.95,
            combined_confidence: 0.95,
        },
        size_bytes: 12,
        age: Duration::from_secs(7200),
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
            summary: "source-root regression".to_string(),
        },
    }
}

fn executor(root: &Path, policy: SourceRootPolicy, mode: DeletionMode) -> DeletionExecutor {
    DeletionExecutor::new(
        DeletionConfig {
            source_roots: policy,
            require_identity: true,
            check_open_files: false,
            quarantine_roots: vec![root.to_path_buf()],
            mode,
            ..DeletionConfig::default()
        },
        None,
    )
}

fn retained(candidate: &CandidacyScore) {
    assert_eq!(
        fs::read(candidate.path.join("debug/deps/generated.o")).unwrap(),
        b"object bytes"
    );
}

#[test]
fn source_root_default_denies_untracked_build_output_for_both_mutation_modes() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let repo = dir.path().join("team/project");
        repository(&repo);
        let candidate = artifact(&repo.join("target"));
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        let executor = executor(dir.path(), policy, mode);
        let report = executor.execute(&executor.plan(vec![candidate.clone()]), None);
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(report.bytes_quarantined, 0);
        assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
        assert!(report.backoff_candidates.is_empty());
        retained(&candidate);
        assert!(!dir.path().join(".sbh/quarantine").exists());
    }
}

#[test]
fn nested_repository_blocks_untracked_evidence_in_a_sibling_directory() {
    let dir = scratch();
    repository(&dir.path().join("deep/nested/project"));
    let candidate = artifact(&dir.path().join("target"));
    fs::write(
        candidate.path.join("release-evidence.txt"),
        b"not regenerable",
    )
    .unwrap();
    let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
    let executor = executor(dir.path(), policy, DeletionMode::Unlink);
    let report = executor.execute(&executor.plan(vec![candidate.clone()]), None);
    assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
    assert_eq!(
        fs::read(candidate.path.join("release-evidence.txt")).unwrap(),
        b"not regenerable"
    );
    retained(&candidate);
}

#[test]
fn explicit_opt_in_keeps_untracked_build_artifact_reclamation_available() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        repository(dir.path());
        let candidate = artifact(&dir.path().join("target"));
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], true);
        let executor = executor(dir.path(), policy, mode);
        let report = executor.execute(&executor.plan(vec![candidate.clone()]), None);
        assert_eq!(report.items_deleted, 1, "{report:?}");
        assert_eq!(report.items_failed, 0);
        assert!(!candidate.path.exists());
        assert!(dir.path().join(".git").is_dir());
        match mode {
            DeletionMode::Unlink => {
                assert_eq!(report.bytes_freed, candidate.size_bytes);
                assert_eq!(report.items_quarantined, 0);
            }
            DeletionMode::Quarantine => {
                assert_eq!(report.bytes_freed, 0);
                assert_eq!(report.items_quarantined, 1);
                let id = crate::scanner::decision_record::stable_decision_id(
                    &candidate.path,
                    candidate.identity,
                    candidate.size_bytes,
                );
                let record = QuarantineStore::under(dir.path())
                    .record(&id)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    fs::read(record.quarantine_path.join("debug/deps/generated.o")).unwrap(),
                    b"object bytes"
                );
            }
        }
    }
}

#[test]
fn explicit_opt_in_does_not_override_tracked_content_or_sacred_paths() {
    for tracked in [false, true] {
        let dir = scratch();
        repository(dir.path());
        let candidate = artifact(&dir.path().join("target"));
        if tracked {
            git(dir.path(), &["add", "target"]);
        } else {
            fs::write(candidate.path.join(protection::MARKER_FILENAME), b"keep").unwrap();
        }
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], true);
        let executor = executor(dir.path(), policy, DeletionMode::Unlink);
        let report = executor.execute(&executor.plan(vec![candidate.clone()]), None);
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        let reason = if tracked {
            "contains_git"
        } else {
            "sacred_stowaway"
        };
        assert_eq!(report.skipped_by_reason.get(reason), Some(&1), "{report:?}");
        retained(&candidate);
    }
}

#[test]
fn revoke_opt_in_invalidates_existing_executor_and_queued_plan() {
    let dir = scratch();
    repository(dir.path());
    let candidate = artifact(&dir.path().join("target"));
    let roots = vec![dir.path().to_path_buf()];
    let policy = SourceRootPolicy::new(&roots, true);
    let executor = executor(dir.path(), policy.clone(), DeletionMode::Unlink);
    let plan = executor.plan(vec![candidate.clone()]);
    assert_eq!(executor.explain_preflight(&candidate, None), Ok(()));
    policy.replace(&roots, false);
    let report = executor.execute(&plan, None);
    assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
    assert_eq!(report.items_deleted, 0);
    retained(&candidate);
    policy.replace(&roots, true);
    assert_eq!(executor.execute(&plan, None).items_deleted, 1);
}

#[test]
fn repository_appearing_after_preflight_is_denied_before_mutation() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let candidate = artifact(&dir.path().join("target"));
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        let executor = executor(dir.path(), policy, mode);
        let plan = executor.plan(vec![candidate.clone()]);
        let create_repo = |_: &CandidacyScore| {
            fs::create_dir_all(dir.path().join("new-sibling/.git")).unwrap();
            Ok(())
        };
        let report = executor.execute_with_guard(&plan, None, Some(&create_repo));
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
        retained(&candidate);
    }
}

#[test]
fn reload_during_live_guard_revokes_preflight_authorization() {
    let dir = scratch();
    repository(dir.path());
    let candidate = artifact(&dir.path().join("target"));
    let roots = vec![dir.path().to_path_buf()];
    let policy = SourceRootPolicy::new(&roots, true);
    let executor = executor(dir.path(), policy.clone(), DeletionMode::Unlink);
    let revoke = |_: &CandidacyScore| {
        policy.replace(&roots, false);
        Ok(())
    };
    let report =
        executor.execute_with_guard(&executor.plan(vec![candidate.clone()]), None, Some(&revoke));
    assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
    assert_eq!(report.bytes_freed, 0);
    retained(&candidate);
}

#[test]
fn both_private_mutation_backends_recheck_after_preflight() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let candidate = artifact(&dir.path().join("target"));
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        let executor = executor(dir.path(), policy, mode);
        assert_eq!(executor.explain_preflight(&candidate, None), Ok(()));
        fs::create_dir_all(dir.path().join("nested/.git")).unwrap();
        let result = match mode {
            DeletionMode::Unlink => executor.delete_path(&candidate),
            DeletionMode::Quarantine => executor.quarantine_path(&candidate),
        };
        assert!(
            matches!(result, Err(SbhError::SafetyVeto { .. })),
            "{result:?}"
        );
        retained(&candidate);
    }
}

#[test]
fn interactive_confirmation_cannot_override_source_root_denial() {
    let dir = scratch();
    repository(dir.path());
    let candidate = artifact(&dir.path().join("target"));
    let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
    let executor = executor(dir.path(), policy, DeletionMode::Unlink);
    assert_eq!(
        executor.delete_candidate_checked(&candidate, None).unwrap(),
        CheckedDeletion::Skipped(SkipReason::SourceRootDenied),
    );
    retained(&candidate);
}

#[test]
fn removed_configured_root_does_not_authorize_a_stale_plan() {
    let dir = scratch();
    let candidate = artifact(&dir.path().join("target"));
    let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
    let executor = executor(dir.path(), policy.clone(), DeletionMode::Unlink);
    let plan = executor.plan(vec![candidate.clone()]);
    policy.replace(&[], false);
    let report = executor.execute(&plan, None);
    assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
    retained(&candidate);
}

#[test]
fn gitfile_source_root_is_denied_without_querying_its_missing_git_directory() {
    let dir = scratch();
    fs::write(
        dir.path().join(".git"),
        b"gitdir: /missing/worktree-metadata\n",
    )
    .unwrap();
    let candidate = artifact(&dir.path().join("target"));
    let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
    let executor = executor(dir.path(), policy, DeletionMode::Unlink);
    assert_eq!(
        executor.explain_preflight(&candidate, None),
        Err(SkipReason::SourceRootDenied)
    );
    retained(&candidate);
}

#[test]
fn source_root_narrowing_during_guard_blocks_parent_but_allows_retained_build_output() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let parent = artifact(&dir.path().join("target"));
        let narrowed_root = parent.path.join("retained");
        let child = artifact(&narrowed_root.join("target"));
        let evidence = parent.path.join("release-evidence.txt");
        fs::write(&evidence, b"irreplaceable evidence").unwrap();
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        let executor = executor(dir.path(), policy.clone(), mode);
        let plan = executor.plan(vec![parent.clone()]);
        let guard_calls = std::cell::Cell::new(0);
        let narrow = |_: &CandidacyScore| {
            guard_calls.set(guard_calls.get() + 1);
            policy.replace(std::slice::from_ref(&narrowed_root), false);
            Ok(())
        };

        // This guard runs after preflight. The assertion on its call count
        // prevents an unrelated earlier veto from making this a false pass.
        let report = executor.execute_with_guard(&plan, None, Some(&narrow));
        assert_eq!(guard_calls.get(), 1, "{report:?}");
        assert_eq!(report.items_deleted, 0, "{report:?}");
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(report.bytes_quarantined, 0);
        assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
        assert!(report.backoff_candidates.is_empty());
        assert!(!dir.path().join(".sbh/quarantine").exists());
        retained(&parent);
        retained(&child);
        assert_eq!(fs::read(&evidence).unwrap(), b"irreplaceable evidence");

        // The same executor sees the narrowed permission, rather than a stale
        // snapshot or a blanket ban on all cleanup after a reload.
        let report = executor.execute(&executor.plan(vec![child.clone()]), None);
        assert_eq!(report.items_deleted, 1, "{report:?}");
        assert_eq!(report.items_failed, 0);
        assert!(!child.path.exists());
        retained(&parent);
        assert_eq!(fs::read(&evidence).unwrap(), b"irreplaceable evidence");
        match mode {
            DeletionMode::Unlink => assert_eq!(report.bytes_freed, child.size_bytes),
            DeletionMode::Quarantine => {
                assert_eq!(report.bytes_freed, 0);
                assert_eq!(report.items_quarantined, 1);
            }
        }
    }
}

#[test]
fn source_root_reload_to_separate_cache_keeps_retired_repository_candidates_denied() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let dir = scratch();
        let repo = dir.path().join("team/project");
        repository(&repo);
        let source_candidate = artifact(&repo.join("target"));
        let evidence = repo.join("untracked-evidence.txt");
        fs::write(&evidence, b"not checked into Git").unwrap();
        let cache_root = dir.path().join("cache");
        let cache_candidate = artifact(&cache_root.join("target"));
        let policy = SourceRootPolicy::new(&[dir.path().to_path_buf()], false);
        let executor = executor(dir.path(), policy.clone(), mode);
        let plan = executor.plan(vec![cache_candidate.clone(), source_candidate.clone()]);
        let denied = executor.execute(&plan, None);
        assert_eq!(denied.items_deleted, 0);
        assert_eq!(denied.skipped_by_reason.get("source_root_denied"), Some(&2));
        retained(&source_candidate);
        retained(&cache_candidate);

        // Removing the broad source-containing root can enable a genuinely
        // separate cache. It must not admit a source candidate queued earlier.
        policy.replace(std::slice::from_ref(&cache_root), false);
        let report = executor.execute(&plan, None);
        assert_eq!(report.items_deleted, 1, "{report:?}");
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
        assert!(report.backoff_candidates.is_empty());
        assert!(!cache_candidate.path.exists());
        retained(&source_candidate);
        assert!(repo.join(".git").is_dir());
        assert_eq!(fs::read(&evidence).unwrap(), b"not checked into Git");
    }
}
