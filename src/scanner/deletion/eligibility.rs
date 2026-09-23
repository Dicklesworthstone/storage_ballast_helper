//! Shared admission checks for planning and the live mutation boundary.
//!
//! `DeletionPlan` and `CandidacyScore` are public data, not proof that the
//! receiving executor approved a mutation. Never trust a caller to have
//! filtered them, and never let emergency Review admission erase a veto.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use super::{CandidacyScore, DecisionAction, DeletionConfig, SkipReason};
use crate::scanner::protection;

pub(super) fn check(candidate: &CandidacyScore, config: &DeletionConfig) -> Result<(), SkipReason> {
    let decision = &candidate.decision;
    if candidate.vetoed || candidate.veto_reason.is_some() || decision.category_suspended {
        return Err(SkipReason::Vetoed);
    }
    if !config.min_score.is_finite()
        || config.min_score < 0.0
        || !candidate.total_score.is_finite()
        || candidate.total_score < config.min_score
    {
        return Err(SkipReason::BelowThreshold);
    }
    let actionable = match decision.action {
        DecisionAction::Delete => true,
        DecisionAction::Review => config.include_review,
        DecisionAction::Keep => false,
    };
    if !actionable
        || !probability(decision.posterior_abandoned)
        || !probability(decision.calibration_score)
        || !probability(decision.regret_calibration)
        || !nonnegative_finite(decision.expected_loss_keep)
        || !nonnegative_finite(decision.expected_loss_delete)
    {
        return Err(SkipReason::Vetoed);
    }
    check_path(candidate, config)
}

/// Check protection that does not require a recursive directory walk.
///
/// File candidates need the same direct catalog rules as directories. A
/// directory-only containment check silently skipped database files and
/// operator-protected file patterns. Ancestor markers also live OUTSIDE a
/// candidate's subtree and must be checked separately, including after a
/// plan has already been built. Do not cache an unprotected verdict here.
fn check_path(candidate: &CandidacyScore, config: &DeletionConfig) -> Result<(), SkipReason> {
    let path = &candidate.path;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // Planning may describe a disappeared candidate; the existing
        // preflight will attribute it to PathGone before any mutation.
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SkipReason::SacredStowaway),
    };
    // Leave the existing preflight's explicit Symlink attribution intact.
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    // Resolve existing parent aliases so a path through a symlink cannot
    // hide the protected ancestors of the actual object. Failure to resolve
    // is missing safety evidence, never proof that the object is unprotected.
    let normalized = fs::canonicalize(path).map_err(|_| SkipReason::SacredStowaway)?;
    // The immutable source-tree floor applies to the actual object, too.
    // A relative path or a parent symlink must not hide .git or a protected
    // project location. Re-resolve on every call: a parent alias can move
    // after preflight without changing the candidate's device/inode.
    if super::is_hardcoded_source_tree(&normalized) {
        return Err(SkipReason::HardcodedSourceTree);
    }
    let marker_root = if metadata.is_dir() {
        normalized.as_path()
    } else {
        // Do not probe file/.sbh-protect: that produces ENOTDIR even for a
        // healthy unprotected file and would disable all file reclamation.
        normalized.parent().ok_or(SkipReason::SacredStowaway)?
    };
    for ancestor in marker_root.ancestors() {
        match fs::symlink_metadata(ancestor.join(protection::MARKER_FILENAME)) {
            // Any marker entry protects, even a dangling symlink. Reading
            // marker metadata is unnecessary and could block on a FIFO.
            Ok(_) => return Err(SkipReason::SacredStowaway),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(SkipReason::SacredStowaway),
        }
    }
    if metadata.is_dir()
        && candidate.classification.category == crate::scanner::patterns::ArtifactCategory::GoCache
    {
        check_go_cache(&normalized)?;
    }
    // Recheck direct/ancestor catalog rules for directories as well as
    // files at the mutation boundary. The protection module resolves exact
    // paths and literal glob prefixes, including operator-configured aliases.
    // Depth zero deliberately leaves recursive containment to preflight:
    // this must not multiply large-tree walks during planning and mutation.
    let overlaps = protection::find_sacred_overlaps_with_config(
        &normalized,
        &config.sacred_paths,
        protection::StowawayScanConfig {
            max_depth: 0,
            ..config.stowaway_scan
        },
    )
    .map_err(|_| SkipReason::SacredStowaway)?;
    if !overlaps.is_empty() {
        return Err(SkipReason::SacredStowaway);
    }
    // Recursive directory containment remains in the existing preflight,
    // preserving its bounded walk, per-batch reuse, and accounting.
    Ok(())
}

/// A cache label grants unusually destructive privileges: the executor can
/// bypass its source check and make read-only trees writable. The label in a
/// public or queued candidate is not authority for either privilege. Recheck
/// the actual cache root at every admission, including the final mutation
/// boundary, without descending through its potentially huge module trees.
fn check_go_cache(path: &Path) -> Result<(), SkipReason> {
    use crate::scanner::patterns::{
        ArtifactCategory, OpaqueTreeContext, OpaqueTreeDisposition, classify_opaque_tree,
    };

    // A real module cache contains module source BELOW its root, not a
    // project manifest or source files AT its root. Never exempt the latter
    // just because stale evidence still calls the directory a Go cache.
    if super::looks_like_source_code(path) {
        return Err(SkipReason::LooksLikeSourceCode);
    }
    let Some(tree) = classify_opaque_tree(path, OpaqueTreeContext::default()) else {
        return Err(SkipReason::Vetoed);
    };
    if tree.disposition != OpaqueTreeDisposition::CandidateOpaque
        || tree.classification.category != ArtifactCategory::GoCache
    {
        return Err(SkipReason::Vetoed);
    }

    // The scanner's cheap structural probe may follow cache/download or
    // merely see an entry named trim.txt. Such aliases and special files
    // cannot authorize permission widening. Inspect marker types without
    // following symlinks; the build-cache shard proof above is also no-follow.
    let marker_verified = match tree.classification.pattern_name.as_ref() {
        "opaque-go-build-cache" => fs::symlink_metadata(path.join("trim.txt"))
            .is_ok_and(|metadata| metadata.file_type().is_file()),
        "opaque-go-mod-cache" => {
            fs::symlink_metadata(path.join("cache"))
                .is_ok_and(|metadata| metadata.file_type().is_dir())
                && fs::symlink_metadata(path.join("cache/download"))
                    .is_ok_and(|metadata| metadata.file_type().is_dir())
        }
        _ => false,
    };
    if !marker_verified {
        return Err(SkipReason::Vetoed);
    }
    Ok(())
}

fn probability(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn nonnegative_finite(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    use crate::scanner::deletion::{CheckedDeletion, DeletionExecutor, DeletionMode, DeletionPlan};
    use crate::scanner::patterns::{ArtifactCategory, ArtifactClassification};
    use crate::scanner::quarantine::QuarantineStore;
    use crate::scanner::scoring::{ArtifactCertainty, DecisionOutcome, EvidenceLedger, ScoreFactors};
    use crate::scanner::walker::identity_for_path;

    const PAYLOAD: &[u8] = b"preserve these bytes";

    fn scratch() -> tempfile::TempDir {
        // Independent of a TMPDIR redirected under a protected source root.
        tempfile::tempdir_in("/tmp").unwrap()
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
            size_bytes: 20,
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
                summary: "file and ancestor protection fixture".to_string(),
            },
        }
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

    fn raw_plan(item: &CandidacyScore, mode: DeletionMode) -> DeletionPlan {
        DeletionPlan {
            candidates: vec![item.clone()],
            total_reclaimable_bytes: item.size_bytes,
            estimated_items: 1,
            mode,
        }
    }

    fn assert_refused(executor: &DeletionExecutor, item: &CandidacyScore, mode: DeletionMode) {
        // A manually constructed plan deliberately bypasses plan()'s filter.
        let report = executor.execute(&raw_plan(item, mode), None);
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(report.skipped_by_reason.get("sacred_stowaway"), Some(&1));
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(report.bytes_quarantined, 0);
        assert_eq!(
            executor.delete_candidate_checked(item, None).unwrap(),
            CheckedDeletion::Skipped(SkipReason::SacredStowaway)
        );
        assert!(item.path.exists());
    }

    #[test]
    fn database_file_candidates_obey_the_builtin_catalog_in_both_modes() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            let dir = scratch();
            let executor = DeletionExecutor::new(config(dir.path(), mode), None);
            for name in ["state.db", "state.sqlite", "state.sqlite3"] {
                let path = dir.path().join(name);
                fs::write(&path, PAYLOAD).unwrap();
                let item = candidate(&path);
                assert!(executor.plan(vec![item.clone()]).candidates.is_empty());
                assert_refused(&executor, &item, mode);
                assert_eq!(fs::read(&path).unwrap(), PAYLOAD);
            }
            assert!(!QuarantineStore::under(dir.path()).root().exists());
        }
    }

    #[test]
    fn exact_and_glob_protections_apply_to_file_candidates() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for glob in [false, true] {
                let dir = scratch();
                let path = dir.path().join("keep-artifact.bin");
                fs::write(&path, PAYLOAD).unwrap();
                let pattern = if glob {
                    dir.path().join("keep-*")
                } else {
                    path.clone()
                };
                let mut cfg = config(dir.path(), mode);
                cfg.sacred_paths
                    .extend(protection::sacred_paths_from_protected_patterns(&[
                        pattern.to_string_lossy().into_owned(),
                    ]));
                let executor = DeletionExecutor::new(cfg, None);
                assert_refused(&executor, &candidate(&path), mode);
                assert_eq!(fs::read(path).unwrap(), PAYLOAD);
            }
        }
    }

    #[test]
    fn ancestor_marker_added_after_planning_blocks_files_and_directories() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for directory in [false, true] {
                let dir = scratch();
                let parent = dir.path().join("a/b/c");
                fs::create_dir_all(&parent).unwrap();
                let path = parent.join("target");
                let payload = if directory {
                    fs::create_dir(&path).unwrap();
                    path.join("artifact.o")
                } else {
                    path.clone()
                };
                fs::write(&payload, PAYLOAD).unwrap();
                let item = candidate(&path);
                let executor = DeletionExecutor::new(config(dir.path(), mode), None);
                let plan = executor.plan(vec![item.clone()]);
                assert_eq!(plan.estimated_items, 1);

                fs::write(dir.path().join(protection::MARKER_FILENAME), b"").unwrap();
                let report = executor.execute(&plan, None);
                assert_eq!(report.items_deleted, 0);
                assert_eq!(report.skipped_by_reason.get("sacred_stowaway"), Some(&1));
                assert_refused(&executor, &item, mode);
                assert_eq!(fs::read(payload).unwrap(), PAYLOAD);
                assert!(!QuarantineStore::under(dir.path()).root().exists());
            }
        }
    }

    #[test]
    fn alias_paths_cannot_hide_the_actual_marker_ancestors() {
        let dir = scratch();
        let real = dir.path().join("real");
        fs::create_dir_all(real.join("nested")).unwrap();
        fs::write(real.join(protection::MARKER_FILENAME), b"").unwrap();
        let payload = real.join("nested/artifact.bin");
        fs::write(&payload, PAYLOAD).unwrap();
        let alias = dir.path().join("alias");
        symlink(real.join("nested"), &alias).unwrap();
        let item = candidate(&alias.join("artifact.bin"));
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            let executor = DeletionExecutor::new(config(dir.path(), mode), None);
            assert_refused(&executor, &item, mode);
            assert_eq!(fs::read(&payload).unwrap(), PAYLOAD);
        }
    }

    #[test]
    fn dangling_ancestor_marker_is_still_a_protection_instruction() {
        let dir = scratch();
        fs::create_dir(dir.path().join("nested")).unwrap();
        let path = dir.path().join("nested/artifact.bin");
        fs::write(&path, PAYLOAD).unwrap();
        let marker = dir.path().join(protection::MARKER_FILENAME);
        symlink("nonexistent-marker-target", &marker).unwrap();
        let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);
        assert_refused(&executor, &candidate(&path), DeletionMode::Unlink);
        assert_eq!(fs::read(path).unwrap(), PAYLOAD);
        assert_eq!(
            fs::read_link(marker).unwrap(),
            Path::new("nonexistent-marker-target")
        );
    }

    #[test]
    fn final_mutation_recheck_observes_a_new_ancestor_marker() {
        let dir = scratch();
        let path = dir.path().join("artifact.bin");
        fs::write(&path, PAYLOAD).unwrap();
        let item = candidate(&path);
        let executor = DeletionExecutor::new(config(dir.path(), DeletionMode::Unlink), None);
        assert!(executor.explain_preflight(&item, None).is_ok());
        fs::write(dir.path().join(protection::MARKER_FILENAME), b"").unwrap();
        // Deliberately enter after preflight: both mutation helpers recheck.
        assert!(executor.delete_path(&item).is_err());
        assert!(executor.quarantine_path(&item).is_err());
        assert_eq!(fs::read(path).unwrap(), PAYLOAD);
        assert!(!QuarantineStore::under(dir.path()).root().exists());
    }

    #[test]
    fn files_under_an_exact_protected_directory_remain_protected() {
        let dir = scratch();
        let parent = dir.path().join("keep/nested");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("artifact.bin");
        fs::write(&path, PAYLOAD).unwrap();
        let mut cfg = config(dir.path(), DeletionMode::Unlink);
        cfg.sacred_paths
            .extend(protection::sacred_paths_from_protected_patterns(&[
                dir.path().join("keep").to_string_lossy().into_owned(),
            ]));
        let executor = DeletionExecutor::new(cfg, None);
        assert_refused(&executor, &candidate(&path), DeletionMode::Unlink);
        assert_eq!(fs::read(path).unwrap(), PAYLOAD);
    }

    #[test]
    fn unprotected_files_still_unlink_or_roundtrip_through_quarantine() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            let dir = scratch();
            let path = dir.path().join("artifact.bin");
            fs::write(&path, PAYLOAD).unwrap();
            let item = candidate(&path);
            let executor = DeletionExecutor::new(config(dir.path(), mode), None);
            let plan = executor.plan(vec![item.clone()]);
            assert_eq!(plan.estimated_items, 1);
            let report = executor.execute(&plan, None);
            assert_eq!(report.items_deleted, 1);
            assert_eq!(report.items_failed, 0);
            assert_eq!(report.items_skipped, 0);
            assert!(!path.exists());
            if mode == DeletionMode::Quarantine {
                assert_eq!(report.bytes_freed, 0);
                assert_eq!(report.items_quarantined, 1);
                let store = QuarantineStore::under(dir.path());
                let id = crate::scanner::decision_record::stable_decision_id(
                    &path,
                    item.identity,
                    item.size_bytes,
                );
                store.restore(&id, false).unwrap();
                assert_eq!(fs::read(path).unwrap(), PAYLOAD);
            } else {
                assert_eq!(report.bytes_freed, item.size_bytes);
            }
        }
    }

    fn go_candidate(path: &Path) -> CandidacyScore {
        let mut item = candidate(path);
        item.classification.category = ArtifactCategory::GoCache;
        item.classification.pattern_name = Cow::Borrowed("opaque-go-build-cache");
        item
    }

    fn go_cache(path: &Path, module_cache: bool) -> std::path::PathBuf {
        let payload = if module_cache {
            fs::create_dir_all(path.join("cache/download")).unwrap();
            let module = path.join("example.org/library@v1.0.0");
            fs::create_dir_all(&module).unwrap();
            fs::write(module.join("go.mod"), b"module example.org/library\n").unwrap();
            module.join("library.go")
        } else {
            fs::create_dir_all(path.join("00")).unwrap();
            fs::write(path.join("trim.txt"), b"0\n").unwrap();
            path.join("00/artifact-d")
        };
        fs::write(&payload, PAYLOAD).unwrap();
        payload
    }

    fn assert_checked_refusal(
        executor: &DeletionExecutor,
        item: &CandidacyScore,
        mode: DeletionMode,
        reason: SkipReason,
    ) {
        assert!(executor.plan(vec![item.clone()]).candidates.is_empty());
        let report = executor.execute(&raw_plan(item, mode), None);
        assert_eq!(report.items_deleted, 0);
        assert_eq!(report.items_skipped, 1);
        assert_eq!(report.bytes_freed, 0);
        assert_eq!(report.bytes_quarantined, 0);
        assert_eq!(
            executor.delete_candidate_checked(item, None).unwrap(),
            CheckedDeletion::Skipped(reason)
        );
        // Direct entry after a previously successful preflight must not
        // avoid the same live evidence requirements in either backend.
        assert!(executor.delete_path(item).is_err());
        assert!(executor.quarantine_path(item).is_err());
        assert!(item.path.exists());
    }

    #[test]
    fn forged_go_cache_labels_do_not_grant_source_or_force_removal_privileges() {
        use std::os::unix::fs::PermissionsExt;

        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for name in ["main.go", "artifact.bin"] {
                let dir = scratch();
                let path = dir.path().join("go-cache");
                fs::create_dir(&path).unwrap();
                let payload = path.join(name);
                fs::write(&payload, PAYLOAD).unwrap();
                fs::set_permissions(&payload, fs::Permissions::from_mode(0o444)).unwrap();
                let mut item = go_candidate(&path);
                // Emergency Review admission must not widen the safety rails.
                item.decision.action = DecisionAction::Review;
                let mut cfg = config(dir.path(), mode);
                cfg.include_review = true;
                let executor = DeletionExecutor::new(cfg, None);
                let reason = if name == "main.go" {
                    SkipReason::LooksLikeSourceCode
                } else {
                    SkipReason::Vetoed
                };
                assert_checked_refusal(&executor, &item, mode, reason);
                assert_eq!(fs::read(&payload).unwrap(), PAYLOAD);
                assert_eq!(
                    fs::metadata(payload).unwrap().permissions().mode() & 0o777,
                    0o444
                );
                assert!(!QuarantineStore::under(dir.path()).root().exists());
            }
        }
    }

    #[test]
    fn go_cache_layout_disappearing_after_preflight_blocks_both_mutations() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            let dir = scratch();
            let path = dir.path().join("go-build-cache");
            let payload = go_cache(&path, false);
            let item = go_candidate(&path);
            let executor = DeletionExecutor::new(config(dir.path(), mode), None);
            assert!(executor.explain_preflight(&item, None).is_ok());
            fs::rename(path.join("trim.txt"), path.join("trim.saved")).unwrap();
            assert_checked_refusal(&executor, &item, mode, SkipReason::Vetoed);
            assert_eq!(fs::read(payload).unwrap(), PAYLOAD);
            assert!(!QuarantineStore::under(dir.path()).root().exists());
        }
    }

    #[test]
    fn source_appearing_in_a_go_cache_after_preflight_is_not_removed() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for name in ["go.mod", "main.go", "package.json", "lib.rs"] {
                let dir = scratch();
                let path = dir.path().join("go-module-cache");
                let payload = go_cache(&path, true);
                let item = go_candidate(&path);
                let executor = DeletionExecutor::new(config(dir.path(), mode), None);
                assert!(executor.explain_preflight(&item, None).is_ok());
                let source = path.join(name);
                fs::write(&source, PAYLOAD).unwrap();
                assert_checked_refusal(&executor, &item, mode, SkipReason::LooksLikeSourceCode);
                assert_eq!(fs::read(source).unwrap(), PAYLOAD);
                assert_eq!(fs::read(payload).unwrap(), PAYLOAD);
                assert!(!QuarantineStore::under(dir.path()).root().exists());
            }
        }
    }

    #[test]
    fn symlinked_or_non_file_go_cache_markers_do_not_authorize_removal() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for variant in 0..5 {
                let dir = scratch();
                let path = dir.path().join("go-cache");
                let external = dir.path().join("external");
                fs::create_dir_all(external.join("download")).unwrap();
                fs::write(external.join("marker"), PAYLOAD).unwrap();
                fs::create_dir(&path).unwrap();
                if variant != 4 {
                    fs::create_dir(path.join("00")).unwrap();
                }
                let payload = path.join("artifact-d");
                fs::write(&payload, PAYLOAD).unwrap();
                match variant {
                    0 => symlink(&external, path.join("cache")).unwrap(),
                    1 => {
                        fs::create_dir(path.join("cache")).unwrap();
                        symlink(external.join("download"), path.join("cache/download")).unwrap();
                    }
                    2 => symlink(external.join("marker"), path.join("trim.txt")).unwrap(),
                    3 => fs::create_dir(path.join("trim.txt")).unwrap(),
                    _ => {
                        // A valid trim.txt without a shard must not vouch
                        // for a DIFFERENT, symlinked module-cache signature.
                        fs::write(path.join("trim.txt"), b"0\n").unwrap();
                        symlink(&external, path.join("cache")).unwrap();
                    }
                }
                let executor = DeletionExecutor::new(config(dir.path(), mode), None);
                assert_checked_refusal(&executor, &go_candidate(&path), mode, SkipReason::Vetoed);
                assert_eq!(fs::read(payload).unwrap(), PAYLOAD);
                assert_eq!(fs::read(external.join("marker")).unwrap(), PAYLOAD);
                assert!(!QuarantineStore::under(dir.path()).root().exists());
            }
        }
    }

    #[test]
    fn genuine_go_caches_still_reclaim_or_restore_with_nested_module_source() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for module_cache in [false, true] {
                let dir = scratch();
                let path = dir.path().join("go-cache");
                let payload = go_cache(&path, module_cache);
                let item = go_candidate(&path);
                let executor = DeletionExecutor::new(config(dir.path(), mode), None);
                let plan = executor.plan(vec![item.clone()]);
                assert_eq!(plan.estimated_items, 1);
                let report = executor.execute(&plan, None);
                assert_eq!(report.items_deleted, 1);
                assert_eq!(report.items_failed, 0);
                assert_eq!(report.items_skipped, 0);
                assert!(!path.exists());
                if mode == DeletionMode::Quarantine {
                    assert_eq!(report.bytes_freed, 0);
                    assert_eq!(report.items_quarantined, 1);
                    let id = crate::scanner::decision_record::stable_decision_id(
                        &path,
                        item.identity,
                        item.size_bytes,
                    );
                    QuarantineStore::under(dir.path())
                        .restore(&id, false)
                        .unwrap();
                    assert_eq!(fs::read(payload).unwrap(), PAYLOAD);
                } else {
                    assert_eq!(report.bytes_freed, item.size_bytes);
                }
            }
        }
    }

    #[test]
    fn aliases_cannot_hide_git_ancestry_even_with_an_empty_catalog() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for directory in [false, true] {
                let dir = scratch();
                let git = dir.path().join(".git/objects");
                fs::create_dir_all(&git).unwrap();
                // An artifact-like name does not grant a .git carve-out.
                let real = git.join("target");
                let payload = if directory {
                    fs::create_dir(&real).unwrap();
                    real.join("artifact.o")
                } else {
                    real.clone()
                };
                fs::write(&payload, PAYLOAD).unwrap();
                let alias = dir.path().join("alias");
                symlink(&git, &alias).unwrap();
                let item = candidate(&alias.join("target"));
                let mut cfg = config(dir.path(), mode);
                cfg.sacred_paths.clear();
                let executor = DeletionExecutor::new(cfg, None);
                assert_checked_refusal(&executor, &item, mode, SkipReason::HardcodedSourceTree);
                assert_eq!(fs::read(payload).unwrap(), PAYLOAD);
                assert!(!QuarantineStore::under(dir.path()).root().exists());
            }
        }
    }

    #[test]
    fn moving_the_same_inode_behind_a_git_alias_revokes_admission() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            let dir = scratch();
            let real = dir.path().join("real");
            fs::create_dir_all(real.join("target")).unwrap();
            fs::write(real.join("target/artifact.o"), PAYLOAD).unwrap();
            let alias = dir.path().join("alias");
            symlink(&real, &alias).unwrap();
            let item = candidate(&alias.join("target"));
            let mut cfg = config(dir.path(), mode);
            cfg.sacred_paths.clear();
            let executor = DeletionExecutor::new(cfg, None);
            assert!(executor.explain_preflight(&item, None).is_ok());

            let git = dir.path().join(".git");
            fs::rename(&real, &git).unwrap();
            fs::rename(&alias, dir.path().join("old-alias")).unwrap();
            symlink(&git, &alias).unwrap();
            assert_eq!(
                item.identity,
                Some(identity_for_path(&item.path, false).unwrap())
            );
            // Exercise the actual boundary, not only a fresh preflight.
            assert!(executor.delete_path(&item).is_err());
            assert!(executor.quarantine_path(&item).is_err());
            assert_checked_refusal(&executor, &item, mode, SkipReason::HardcodedSourceTree);
            assert_eq!(fs::read(git.join("target/artifact.o")).unwrap(), PAYLOAD);
        }
    }

    #[test]
    fn directory_protection_is_rechecked_after_parent_alias_relocation() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            for glob in [false, true] {
                let dir = scratch();
                let real = dir.path().join("real");
                fs::create_dir_all(real.join("target")).unwrap();
                fs::write(real.join("target/artifact.o"), PAYLOAD).unwrap();
                let alias = dir.path().join("alias");
                symlink(&real, &alias).unwrap();
                let protected = dir.path().join("protected");
                let pattern = if glob {
                    protected.join("*")
                } else {
                    protected.clone()
                };
                let mut cfg = config(dir.path(), mode);
                cfg.sacred_paths
                    .extend(protection::sacred_paths_from_protected_patterns(&[
                        pattern.to_string_lossy().into_owned(),
                    ]));
                let item = candidate(&alias.join("target"));
                let executor = DeletionExecutor::new(cfg, None);
                assert!(executor.explain_preflight(&item, None).is_ok());

                fs::rename(&real, &protected).unwrap();
                fs::rename(&alias, dir.path().join("old-alias")).unwrap();
                symlink(&protected, &alias).unwrap();
                assert_eq!(
                    item.identity,
                    Some(identity_for_path(&item.path, false).unwrap())
                );
                assert!(executor.delete_path(&item).is_err());
                assert!(executor.quarantine_path(&item).is_err());
                assert_checked_refusal(&executor, &item, mode, SkipReason::SacredStowaway);
                assert_eq!(
                    fs::read(protected.join("target/artifact.o")).unwrap(),
                    PAYLOAD
                );
                assert!(!QuarantineStore::under(dir.path()).root().exists());
            }
        }
    }

    #[test]
    fn direct_protection_rechecks_do_not_repeat_recursive_containment() {
        let dir = scratch();
        let path = dir.path().join("target");
        fs::create_dir_all(path.join("nested")).unwrap();
        fs::write(path.join("nested/.sbh-protect"), b"").unwrap();
        let mut cfg = config(dir.path(), DeletionMode::Unlink);
        cfg.stowaway_scan.max_entries = 1;
        cfg.stowaway_scan.max_dirs = 1;
        let item = candidate(&path);
        // Only direct rules and ancestors belong in admission. The existing
        // bounded preflight owns descendant discovery and its cost counters.
        assert!(check(&item, &cfg).is_ok());
        let executor = DeletionExecutor::new(cfg, None);
        assert_eq!(
            executor.explain_preflight(&item, None),
            Err(SkipReason::SacredStowaway)
        );
        assert!(path.join("nested/.sbh-protect").exists());
    }

    #[test]
    fn unprotected_parent_aliases_remain_eligible_in_both_modes() {
        for mode in [DeletionMode::Unlink, DeletionMode::Quarantine] {
            let dir = scratch();
            let real = dir.path().join("real");
            fs::create_dir_all(real.join("target")).unwrap();
            fs::write(real.join("target/artifact.o"), PAYLOAD).unwrap();
            let alias = dir.path().join("alias");
            symlink(&real, &alias).unwrap();
            let item = candidate(&alias.join("target"));
            let executor = DeletionExecutor::new(config(dir.path(), mode), None);
            assert!(executor.explain_preflight(&item, None).is_ok());
            let plan = executor.plan(vec![item]);
            assert_eq!(plan.estimated_items, 1);
            let report = executor.execute(&plan, None);
            assert_eq!(report.items_deleted, 1);
            assert_eq!(report.items_failed, 0);
            assert_eq!(report.items_skipped, 0);
            assert!(!real.join("target").exists());
            if mode == DeletionMode::Quarantine {
                assert_eq!(report.bytes_freed, 0);
                assert_eq!(report.items_quarantined, 1);
            }
        }
    }
}
