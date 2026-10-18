//! Checked build evidence must survive every generic PAL safety consumer.
//!
//! These tests exercise real scoring/projection and executor entry points with
//! deterministic process evidence. They do not claim to exercise native libproc.

#![cfg(unix)]

use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use storage_ballast_helper::core::errors::Result;
use storage_ballast_helper::platform::pal::{
    FsStats, MemoryInfo, MountPoint, Platform, PlatformPaths, ServiceManager,
};
use storage_ballast_helper::platform::types::{
    ExecutablesResult, MappedRegion, OpenFilesResult, ProcessInfo,
};
use storage_ballast_helper::scanner::deletion::{
    DeletionConfig, DeletionExecutor, DeletionMode, DeletionPlan,
};
use storage_ballast_helper::scanner::patterns::{ArtifactCategory, ArtifactClassification};
use storage_ballast_helper::scanner::scoring::{
    ArtifactCertainty, CandidacyScore, DecisionAction, DecisionOutcome, EvidenceLedger,
    ScoreFactors,
};
use storage_ballast_helper::scanner::walker::{
    collect_active_reference_index, collect_open_path_ancestors_with_platform, identity_for_path,
};

const PAYLOAD: &[u8] = b"retain active build output";

struct SnapshotPlatform {
    root: PathBuf,
    directories: Vec<(i32, PathBuf)>,
    complete: AtomicBool,
    build_reads: AtomicUsize,
}

impl SnapshotPlatform {
    fn new(root: &Path, directories: Vec<(i32, PathBuf)>, complete: bool) -> Self {
        Self {
            root: root.to_path_buf(),
            directories,
            complete: AtomicBool::new(complete),
            build_reads: AtomicUsize::new(0),
        }
    }
}

impl Platform for SnapshotPlatform {
    fn name(&self) -> &'static str { "checked-build-fixture" }
    fn fs_stats(&self, _: &Path) -> Result<FsStats> {
        Ok(FsStats {
            total_bytes: 1024 * 1024,
            free_bytes: 512 * 1024,
            available_bytes: 512 * 1024,
            fs_type: "fixture".to_owned(),
            mount_point: self.root.clone(),
            is_readonly: false,
        })
    }
    fn mount_points(&self) -> Result<Vec<MountPoint>> { Ok(Vec::new()) }
    fn is_ram_backed(&self, _: &Path) -> Result<bool> { Ok(false) }
    fn default_paths(&self) -> PlatformPaths { PlatformPaths::default() }
    fn memory_info(&self) -> Result<MemoryInfo> {
        Ok(MemoryInfo {
            total_bytes: 1024,
            available_bytes: 512,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
        })
    }
    fn service_manager(&self) -> Box<dyn ServiceManager> {
        panic!("reference inspection must not control services")
    }
    fn process_list(&self) -> Result<Vec<ProcessInfo>> { Ok(Vec::new()) }
    fn open_files_under(&self, _: &Path) -> Result<OpenFilesResult> {
        Ok(OpenFilesResult::complete(Vec::new()))
    }
    fn executables_under(&self, _: &Path) -> Result<ExecutablesResult> {
        Ok(ExecutablesResult { processes: Vec::new(), complete: true })
    }
    fn mmap_regions_under(&self, _: &Path) -> Result<Vec<MappedRegion>> { Ok(Vec::new()) }
    fn build_directories_in_use(&self) -> Vec<(i32, PathBuf)> {
        panic!("safety consumers must not discard build observation coverage")
    }
    fn build_directories_in_use_checked(&self) -> (Vec<(i32, PathBuf)>, bool) {
        self.build_reads.fetch_add(1, Ordering::SeqCst);
        (self.directories.clone(), self.complete.load(Ordering::SeqCst))
    }
}

fn scratch() -> (tempfile::TempDir, PathBuf) {
    // Independent of a TMPDIR redirected beneath a protected source root.
    let temp = tempfile::tempdir_in("/tmp").unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    (temp, root)
}

fn artifact(root: &Path, relative: &str) -> CandidacyScore {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, PAYLOAD).unwrap();
    CandidacyScore {
        identity: Some(identity_for_path(&path, false).unwrap()),
        path,
        total_score: 0.9,
        factors: ScoreFactors {
            location: 0.8, name: 0.9, age: 0.7, size: 0.6, structure: 0.85,
            pressure_multiplier: 1.0,
        },
        vetoed: false,
        veto_reason: None,
        classification: ArtifactClassification {
            pattern_name: Cow::Borrowed("target"),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.95,
            structural_confidence: 0.9,
            combined_confidence: 0.92,
        },
        size_bytes: u64::try_from(PAYLOAD.len()).unwrap(),
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
        ledger: EvidenceLedger { terms: Vec::new(), summary: "checked build fixture".to_owned() },
    }
}

fn plan(candidates: Vec<CandidacyScore>, mode: DeletionMode) -> DeletionPlan {
    DeletionPlan {
        total_reclaimable_bytes: candidates.iter().map(|candidate| candidate.size_bytes).sum(),
        estimated_items: candidates.len(),
        candidates,
        mode,
        refused: Vec::new(),
    }
}

fn executor(root: &Path, platform: Arc<SnapshotPlatform>, mode: DeletionMode) -> DeletionExecutor {
    DeletionExecutor::new(DeletionConfig {
        mode,
        check_open_files: true,
        require_identity: true,
        quarantine_roots: vec![root.to_path_buf()],
        ..DeletionConfig::default()
    }, None).with_platform(platform)
}

#[test]
fn incomplete_empty_build_evidence_holds_unlink_and_quarantine_without_backoff() {
    for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
        let (_temp, root) = scratch();
        let first = artifact(&root, "target/debug/first.o");
        let second = artifact(&root, "unrelated/second.o");
        let platform = Arc::new(SnapshotPlatform::new(&root, Vec::new(), false));
        let executor = executor(&root, Arc::clone(&platform), mode);
        let plan = plan(vec![first, second], mode);
        let report = executor.execute(&plan, None);
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_failed, 0);
        assert_eq!(report.items_skipped, 2);
        assert_eq!(report.skipped_by_reason.get("open_scan_incomplete"), Some(&2));
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(report.bytes_quarantined, 0);
        assert!(report.backoff_candidates.is_empty());
        assert!(report.deleted_paths.is_empty());
        assert!(!root.join(".sbh").exists(), "refusal must not allocate a quarantine store");
        for candidate in &plan.candidates {
            assert_eq!(fs::read(&candidate.path).unwrap(), PAYLOAD);
        }
        assert_eq!(platform.build_reads.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn partial_positive_scopes_and_missing_coverage_survive_both_projections() {
    let (_temp, root) = scratch();
    let busy = artifact(&root, "active/deep/object.o");
    let idle = artifact(&root, "idle/object.o");
    let platform = SnapshotPlatform::new(&root, vec![(41, root.join("active"))], false);
    let index = collect_active_reference_index(&platform, std::slice::from_ref(&root));
    assert!(!index.is_complete());
    let busy_summary = index.summary_for(&busy.path);
    assert!(busy_summary.processes.iter().any(|process| process.pid == 41 && process.build_directory));
    assert!(busy_summary.incomplete_reason.is_some());
    let idle_summary = index.summary_for(&idle.path);
    assert!(idle_summary.processes.is_empty());
    assert!(idle_summary.incomplete_reason.is_some());
    for candidate in [&busy, &idle] {
        assert!(index.summary_for_identity(candidate.identity.unwrap()).incomplete_reason.is_some());
    }
    let (paths, complete) = collect_open_path_ancestors_with_platform(
        &platform, &[busy.path.clone(), idle.path.clone()],
    );
    assert!(!complete);
    assert!(paths.contains(&busy.path));
    assert!(!paths.contains(&idle.path), "unknown use is not an invented positive reference");
}

#[test]
fn complete_build_scope_protects_nested_output_without_holding_an_idle_sibling() {
    let (_temp, root) = scratch();
    let busy = artifact(&root, "active/deep/object.o");
    let idle = artifact(&root, "idle/object.o");
    let platform = Arc::new(SnapshotPlatform::new(&root, vec![(41, root.join("active"))], true));
    let executor = executor(&root, platform, DeletionMode::Unlink);
    let report = executor.execute(&plan(vec![busy.clone(), idle.clone()], DeletionMode::Unlink), None);
    assert_eq!(report.items_deleted, 1, "{report:?}");
    assert_eq!(report.items_failed, 0);
    assert_eq!(report.items_skipped, 1);
    assert_eq!(report.skipped_by_reason.get("file_open"), Some(&1));
    assert_eq!(fs::read(&busy.path).unwrap(), PAYLOAD);
    assert!(!idle.path.exists());
}

#[test]
fn recovered_coverage_is_observed_on_the_next_batch_not_latched_as_a_path_failure() {
    let (_temp, root) = scratch();
    let item = artifact(&root, "target/debug/object.o");
    let platform = Arc::new(SnapshotPlatform::new(&root, Vec::new(), false));
    let executor = executor(&root, Arc::clone(&platform), DeletionMode::Unlink);
    let plan = plan(vec![item.clone()], DeletionMode::Unlink);
    let held = executor.execute(&plan, None);
    assert_eq!(held.items_deleted, 0);
    assert_eq!(held.skipped_by_reason.get("open_scan_incomplete"), Some(&1));
    assert!(held.backoff_candidates.is_empty());
    platform.complete.store(true, Ordering::SeqCst);
    let released = executor.execute(&plan, None);
    assert_eq!(released.items_deleted, 1, "{released:?}");
    assert_eq!(released.items_failed, 0);
    assert_eq!(released.items_skipped, 0);
    assert!(!item.path.exists());
    assert_eq!(platform.build_reads.load(Ordering::SeqCst), 2);
}

#[test]
fn empty_candidate_scope_needs_no_process_observation() {
    let (_temp, root) = scratch();
    let platform = SnapshotPlatform::new(&root, Vec::new(), false);
    let (paths, complete) = collect_open_path_ancestors_with_platform(&platform, &[]);
    assert!(paths.is_empty());
    assert!(complete);
    assert_eq!(platform.build_reads.load(Ordering::SeqCst), 0);
}
