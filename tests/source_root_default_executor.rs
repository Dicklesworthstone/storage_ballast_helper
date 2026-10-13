//! Regression coverage for executors whose caller omitted the source-root policy.
//!
//! These tests deliberately leave DeletionConfig::source_roots at its default.
//! Configured-policy tests cannot detect the missing-wiring failure: they install
//! the very policy that the production caller forgot. All mutations are confined
//! to disposable fixtures outside the checkout; no daemon or ballast is started.

#![cfg(unix)]

use std::borrow::Cow;
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use storage_ballast_helper::scanner::deletion::{
    DeletionConfig, DeletionExecutor, DeletionMode, DeletionReport, SkipReason,
};
use storage_ballast_helper::scanner::patterns::{ArtifactCategory, ArtifactClassification};
use storage_ballast_helper::scanner::scoring::{
    ArtifactCertainty, CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger, ScoreFactors,
};
use storage_ballast_helper::scanner::source_roots::SourceRootPolicy;
use storage_ballast_helper::scanner::walker::identity_for_path;

fn scratch() -> tempfile::TempDir {
    for base in [PathBuf::from("/tmp"), PathBuf::from("/var/tmp")] {
        if let Ok(directory) = tempfile::tempdir_in(base)
            && !directory
                .path()
                .ancestors()
                .any(|ancestor| ancestor.join(".git").exists())
        {
            return directory;
        }
    }
    panic!("source-root tests need a temporary directory outside a Git work tree");
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("Git is required for repository safety regressions");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn artifact(path: &Path) -> CandidacyScore {
    fs::create_dir_all(path.join("debug/deps")).unwrap();
    fs::write(path.join("debug/deps/generated.o"), b"object bytes").unwrap();
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
            summary: "uninstalled-policy executor regression".to_string(),
        },
    }
}

fn config(root: &Path, mode: DeletionMode) -> DeletionConfig {
    DeletionConfig {
        require_identity: true,
        check_open_files: false,
        quarantine_roots: vec![root.to_path_buf()],
        mode,
        ..DeletionConfig::default()
    }
}

fn retained(candidate: &CandidacyScore) {
    assert_eq!(
        fs::read(candidate.path.join("debug/deps/generated.o")).unwrap(),
        b"object bytes"
    );
}

fn denied(report: &DeletionReport) {
    assert_eq!(report.items_deleted, 0, "{report:?}");
    assert_eq!(report.items_failed, 0, "{report:?}");
    assert_eq!(report.items_skipped, 1, "{report:?}");
    assert_eq!(report.items_would_delete, 0, "{report:?}");
    assert_eq!(report.bytes_would_free, 0, "{report:?}");
    assert_eq!(report.bytes_freed, 0, "{report:?}");
    assert_eq!(report.bytes_quarantined, 0, "{report:?}");
    assert_eq!(report.skipped_by_reason.get("source_root_denied"), Some(&1));
    assert!(report.errors.is_empty(), "a safety veto is not an I/O failure");
    assert!(report.backoff_candidates.is_empty());
    assert!(!report.circuit_breaker_tripped);
}

#[test]
fn source_root_default_executor_preserves_untracked_evidence_in_both_modes() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        for dry_run in [false, true] {
            let directory = scratch();
            git(directory.path(), &["init", "--initial-branch=main"]);
            let candidate = artifact(&directory.path().join("target"));
            let evidence = candidate.path.join("release-evidence.txt");
            fs::write(&evidence, b"irreplaceable evidence").unwrap();
            let executor = DeletionExecutor::new(
                DeletionConfig {
                    dry_run,
                    ..config(directory.path(), mode)
                },
                None,
            );
            let plan = executor.plan(vec![candidate.clone()]);
            assert_eq!(plan.candidates.len(), 1, "scoring admits this artifact");
            denied(&executor.execute(&plan, None));
            retained(&candidate);
            assert_eq!(fs::read(&evidence).unwrap(), b"irreplaceable evidence");
            assert!(!directory.path().join(".sbh/quarantine").exists());
        }
    }
}

#[test]
fn source_root_default_executor_still_reclaims_ordinary_non_repository_artifacts() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let directory = scratch();
        let candidate = artifact(&directory.path().join("target"));
        let executor = DeletionExecutor::new(config(directory.path(), mode), None);
        let plan = executor.plan(vec![candidate.clone()]);
        let report = executor.execute(&plan, None);
        assert_eq!(report.items_deleted, 1, "positive control: {report:?}");
        assert_eq!(report.items_skipped, 0, "{report:?}");
        assert_eq!(report.items_failed, 0, "{report:?}");
        assert!(!candidate.path.exists());
        match mode {
            DeletionMode::Unlink => {
                assert_eq!(report.bytes_freed, candidate.size_bytes);
                assert_eq!(report.items_quarantined, 0);
            }
            DeletionMode::Quarantine => {
                assert_eq!(report.bytes_freed, 0);
                assert_eq!(report.items_quarantined, 1);
                assert_eq!(report.bytes_quarantined, candidate.size_bytes);
            }
        }
    }
}

#[test]
fn source_root_default_executor_rechecks_after_the_live_guard() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let directory = scratch();
        let candidate = artifact(&directory.path().join("target"));
        let executor = DeletionExecutor::new(config(directory.path(), mode), None);
        let plan = executor.plan(vec![candidate.clone()]);
        assert_eq!(executor.explain_preflight(&candidate, None), Ok(()));
        let guard_calls = Cell::new(0);
        let create_repository = |_: &CandidacyScore| {
            guard_calls.set(guard_calls.get() + 1);
            fs::create_dir(directory.path().join(".git")).unwrap();
            Ok(())
        };
        let report = executor.execute_with_guard(&plan, None, Some(&create_repository));
        assert_eq!(guard_calls.get(), 1, "preflight must actually reach the guard");
        denied(&report);
        retained(&candidate);
        assert!(!directory.path().join(".sbh/quarantine").exists());
    }
}

#[test]
fn source_root_default_executor_recognizes_a_gitfile_without_resolving_git_metadata() {
    let directory = scratch();
    fs::write(
        directory.path().join(".git"),
        b"gitdir: /nonexistent/linked-worktree-metadata\n",
    )
    .unwrap();
    let candidate = artifact(&directory.path().join("target"));
    let executor = DeletionExecutor::new(config(directory.path(), DeletionMode::Unlink), None);
    denied(&executor.execute(&executor.plan(vec![candidate.clone()]), None));
    retained(&candidate);
}

#[test]
fn source_root_default_executor_cannot_be_bypassed_by_a_parent_symlink() {
    let directory = scratch();
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "--initial-branch=main"]);
    let original = artifact(&repository.join("target"));
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&repository, &alias).unwrap();
    let candidate = CandidacyScore {
        path: alias.join("target"),
        ..original.clone()
    };
    let executor = DeletionExecutor::new(config(directory.path(), DeletionMode::Unlink), None);
    denied(&executor.execute(&executor.plan(vec![candidate]), None));
    retained(&original);
}

#[test]
fn source_root_default_policy_checks_file_parents_and_fresh_repository_markers() {
    let directory = scratch();
    let file = directory.path().join("generated.o");
    fs::write(&file, b"ordinary file").unwrap();
    let policy = SourceRootPolicy::default();
    assert!(policy.authorize(&file).is_ok(), "do not probe file/.git");
    assert!(policy.refresh().roots.is_empty());
    fs::create_dir(directory.path().join(".git")).unwrap();
    assert!(policy.authorize(&file).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"ordinary file");
}

#[test]
fn source_root_explicit_installation_allows_untracked_output_but_not_tracked_content() {
    for tracked in [false, true] {
        let directory = scratch();
        git(directory.path(), &["init", "--initial-branch=main"]);
        let candidate = artifact(&directory.path().join("target"));
        if tracked {
            git(directory.path(), &["add", "target"]);
        }
        let policy = SourceRootPolicy::default();
        let executor = DeletionExecutor::new(
            DeletionConfig {
                source_roots: policy.clone(),
                ..config(directory.path(), DeletionMode::Unlink)
            },
            None,
        );
        let plan = executor.plan(vec![candidate.clone()]);
        denied(&executor.execute(&plan, None));
        retained(&candidate);

        // Installation changes existing executor clones, not just new ones.
        policy.replace(&[directory.path().to_path_buf()], true);
        let report = executor.execute(&plan, None);
        if tracked {
            assert_eq!(report.items_deleted, 0, "{report:?}");
            assert_eq!(report.skipped_by_reason.get("contains_git"), Some(&1));
            retained(&candidate);
        } else {
            assert_eq!(report.items_deleted, 1, "{report:?}");
            assert!(!candidate.path.exists());
        }
        assert!(directory.path().join(".git").is_dir());
    }
}

#[test]
fn source_root_default_executor_keeps_interactive_confirmation_behind_the_same_veto() {
    let directory = scratch();
    git(directory.path(), &["init", "--initial-branch=main"]);
    let candidate = artifact(&directory.path().join("target"));
    let executor = DeletionExecutor::new(config(directory.path(), DeletionMode::Unlink), None);
    assert_eq!(
        executor.explain_preflight(&candidate, None),
        Err(SkipReason::SourceRootDenied)
    );
    assert_eq!(
        executor.delete_candidate_checked(&candidate, None).unwrap(),
        storage_ballast_helper::scanner::deletion::CheckedDeletion::Skipped(
            SkipReason::SourceRootDenied
        )
    );
    retained(&candidate);
}
