#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use storage_ballast_helper::core::config::ScoringConfig;
    use storage_ballast_helper::platform::cleanup_catalog::{
        self, CleanupConfidence, CleanupRule, ReclaimCommand,
    };
    use storage_ballast_helper::platform::macos;
    use storage_ballast_helper::platform::sacred_catalog::cross_platform_sacred_paths;
    use storage_ballast_helper::scanner::patterns::{
        ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, StructuralSignals,
        extract_pattern_label_with_cleanup_rules_and_home,
    };
    use storage_ballast_helper::scanner::protection::find_sacred_overlaps;
    use storage_ballast_helper::scanner::scoring::{
        ActiveReferenceSummary, CandidateInput, DecisionAction, ScoringEngine,
    };
    use tempfile::{Builder as TempDirBuilder, TempDir};

    fn default_engine() -> ScoringEngine {
        ScoringEngine::from_config(&ScoringConfig::default(), 4) // 4 hours min age
    }

    fn classify_macos(
        registry: &ArtifactPatternRegistry,
        path: &Path,
        signals: StructuralSignals,
    ) -> ArtifactClassification {
        registry.classify_with_cleanup_rules(path, signals, macos::cleanup_catalog::cleanup_rules())
    }

    fn classify_macos_with_home(
        registry: &ArtifactPatternRegistry,
        path: &Path,
        signals: StructuralSignals,
        home: &Path,
    ) -> ArtifactClassification {
        registry.classify_with_cleanup_rules_and_home(
            path,
            signals,
            macos::cleanup_catalog::cleanup_rules(),
            home,
        )
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn mac_cleanup_catalog_fixture_scans_every_pattern_with_expected_confidence() {
        let fake_root = TempDirBuilder::new()
            .prefix("sbh-mac-cleanup-catalog-")
            .tempdir()
            .expect("create synthetic mac cleanup root");
        let fake_home = fake_root.path().join("Users").join("operator");
        let registry = ArtifactPatternRegistry::default();
        let rules = macos::cleanup_catalog::cleanup_rules();
        let mut temp_dirs = Vec::new();
        let mut matched_rule_names = BTreeSet::new();
        let mut scanned_labels = BTreeSet::new();
        let mut expected_scanned_labels = BTreeSet::new();

        for rule in rules {
            let (path, temp_dir, materialized) = mac_cleanup_fixture_path(rule, &fake_home);
            if materialized {
                materialize_cleanup_fixture(rule, &path);
                assert!(
                    path.exists(),
                    "fixture path should exist for {}: {}",
                    rule.name,
                    path.display()
                );
            }
            if let Some(temp_dir) = temp_dir {
                temp_dirs.push(temp_dir);
            }

            let matched = cleanup_catalog::match_rule_with_home(&path, rules, &fake_home)
                .unwrap_or_else(|| panic!("{} did not match {}", path.display(), rule.path_glob));
            assert_eq!(
                matched.name,
                rule.name,
                "fixture path matched the wrong mac cleanup rule: {}",
                path.display()
            );
            assert_eq!(matched.confidence, rule.confidence);
            matched_rule_names.insert(matched.name);

            if rule.is_scan_visible_candidate() {
                let scanner_match =
                    cleanup_catalog::match_scan_visible_rule_with_home(&path, rules, &fake_home)
                        .expect("scan-visible matcher should find candidate");
                assert_eq!(scanner_match.name, rule.name);

                let signals = structural_signals_for_cleanup_rule(rule);
                let classification =
                    classify_macos_with_home(&registry, &path, signals, &fake_home);
                assert_eq!(classification.pattern_name.as_ref(), rule.scanner_label());
                assert_eq!(
                    classification.category,
                    expected_category_for_cleanup_rule(rule)
                );
                assert_confidence(rule, classification.name_confidence);

                let label = extract_pattern_label_with_cleanup_rules_and_home(
                    &path.to_string_lossy(),
                    rules,
                    &fake_home,
                );
                assert_eq!(label, rule.scanner_label());
                scanned_labels.insert(label);
                expected_scanned_labels.insert(rule.scanner_label().to_string());

                if !rule.is_path_scanner_candidate() {
                    assert!(
                        cleanup_catalog::match_path_scanner_rule_with_home(
                            &path, rules, &fake_home
                        )
                        .is_none(),
                        "{} should be scan-visible but not a path-scanner deletion candidate",
                        rule.name
                    );
                }
            } else {
                assert!(
                    cleanup_catalog::match_scan_visible_rule_with_home(&path, rules, &fake_home)
                        .is_none(),
                    "{} should not be emitted as a scan-visible candidate",
                    rule.name
                );
            }
        }

        assert_eq!(matched_rule_names.len(), rules.len());
        assert_eq!(scanned_labels, expected_scanned_labels);
        assert!(
            !temp_dirs.is_empty(),
            "temporary /tmp fixtures should stay alive for the whole test"
        );
    }

    fn mac_cleanup_fixture_path(
        rule: &CleanupRule,
        fake_home: &Path,
    ) -> (PathBuf, Option<TempDir>, bool) {
        match rule.name {
            "xcode-derived-data" => (
                fake_home.join("Library/Developer/Xcode/DerivedData/sbh-demo-abc123"),
                None,
                true,
            ),
            "core-simulator-caches" => (
                fake_home.join("Library/Developer/CoreSimulator/Caches/device-cache"),
                None,
                true,
            ),
            "electron-cache" => electron_fixture(fake_home, "Cache", "data_0"),
            "electron-cache-root" => electron_root_fixture(fake_home, "Cache"),
            "electron-service-worker-cache" => {
                electron_fixture(fake_home, "Service Worker/CacheStorage", "session-1")
            }
            "electron-service-worker-cache-root" => {
                electron_root_fixture(fake_home, "Service Worker/CacheStorage")
            }
            "electron-code-cache" => electron_fixture(fake_home, "Code Cache", "js-blob"),
            "electron-code-cache-root" => electron_root_fixture(fake_home, "Code Cache"),
            "electron-gpu-cache" => electron_fixture(fake_home, "GPUCache", "shader-blob"),
            "electron-gpu-cache-root" => electron_root_fixture(fake_home, "GPUCache"),
            "electron-indexed-db" => electron_fixture(fake_home, "IndexedDB", "origin.leveldb"),
            "electron-indexed-db-root" => electron_root_fixture(fake_home, "IndexedDB"),
            "electron-vm-bundles" => electron_fixture(fake_home, "vm_bundles", "bundle-1"),
            "electron-vm-bundles-root" => electron_root_fixture(fake_home, "vm_bundles"),
            "tmp-dash-target" => tmp_dir_fixture("sbh-mac-", "-target"),
            "tmp-underscore-target" => tmp_dir_fixture("sbh-mac-", "_target"),
            "tmp-target-underscore-prefix" => tmp_dir_fixture("target_sbh_mac_", ""),
            "user-named-trash-exact" => (PathBuf::from("/tmp/trash"), None, false),
            "user-named-trashed-exact" => (PathBuf::from("/tmp/trashed"), None, false),
            "user-named-trash" => tmp_dir_fixture("sbh-mac-trash-", ""),
            "release-work-buildroot" => (
                fake_home.join("release-work/mcp_agent_mail_rust_buildroot"),
                None,
                true,
            ),
            "user-logs" => (fake_home.join("Library/Logs/sbh.log"), None, true),
            "ipsw-software-updates" => (
                fake_home.join("Library/iTunes/iPhone Software Updates/iPhone_17.ipsw"),
                None,
                true,
            ),
            "home-trash-report" => (fake_home.join(".Trash/old-session"), None, true),
            "icloud-trash-report" => (
                fake_home.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash/old-session"),
                None,
                true,
            ),
            "time-machine-local-snapshots" => (PathBuf::from("/"), None, false),
            "spotlight-index-report" => (PathBuf::from("/.Spotlight-V100"), None, false),
            "photos-library-sacred" => (
                fake_home.join("Pictures/Photos Library.photoslibrary"),
                None,
                true,
            ),
            "mail-library-sacred" => (fake_home.join("Library/Mail/V10"), None, true),
            "messages-library-sacred" => (fake_home.join("Library/Messages/chat.db"), None, true),
            "final-cut-library-sacred" => (fake_home.join("Movies/Cut.fcpbundle"), None, true),
            // ajg1.10.3: the ~/Library/Caches/<app> rule (age >= 7 d, Review
            // unless Definite) — any single app-cache directory matches.
            "user-library-caches-app" => {
                (fake_home.join("Library/Caches/com.example.app"), None, true)
            }
            name => panic!("missing mac cleanup fixture for {name}"),
        }
    }

    fn electron_fixture(
        fake_home: &Path,
        cache_dir: &str,
        child: &str,
    ) -> (PathBuf, Option<TempDir>, bool) {
        (
            fake_home
                .join("Library/Application Support/Claude")
                .join(cache_dir)
                .join(child),
            None,
            true,
        )
    }

    fn electron_root_fixture(
        fake_home: &Path,
        cache_dir: &str,
    ) -> (PathBuf, Option<TempDir>, bool) {
        (
            fake_home
                .join("Library/Application Support/Claude")
                .join(cache_dir),
            None,
            true,
        )
    }

    fn tmp_dir_fixture(prefix: &str, suffix: &str) -> (PathBuf, Option<TempDir>, bool) {
        let temp_dir = TempDirBuilder::new()
            .prefix(prefix)
            .suffix(suffix)
            .tempdir_in("/tmp")
            .unwrap_or_else(|err| panic!("create /tmp mac cleanup fixture: {err}"));
        (temp_dir.path().to_path_buf(), Some(temp_dir), true)
    }

    fn materialize_cleanup_fixture(rule: &CleanupRule, path: &Path) {
        match rule.reclaim_command {
            ReclaimCommand::RemoveMatchingFiles => create_file_fixture(path),
            ReclaimCommand::ReportOnly
                if rule.name == "home-trash-report" || rule.name == "icloud-trash-report" =>
            {
                create_file_fixture(path);
            }
            _ => create_dir_fixture(path),
        }
    }

    fn create_dir_fixture(path: &Path) {
        fs::create_dir_all(path).expect("create cleanup fixture directory");
        fs::write(path.join(".sbh-fixture"), b"synthetic cleanup fixture")
            .expect("write cleanup fixture marker");
    }

    fn create_file_fixture(path: &Path) {
        let parent = path.parent().expect("fixture file should have parent");
        fs::create_dir_all(parent).expect("create cleanup fixture parent");
        fs::write(path, b"synthetic cleanup fixture").expect("write cleanup fixture file");
    }

    fn structural_signals_for_cleanup_rule(rule: &CleanupRule) -> StructuralSignals {
        if rule.name.contains("target") {
            StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_fingerprint: true,
                ..StructuralSignals::default()
            }
        } else if rule.name.contains("derived-data") || rule.name.contains("buildroot") {
            StructuralSignals {
                has_build: true,
                mostly_object_files: true,
                ..StructuralSignals::default()
            }
        } else {
            StructuralSignals::default()
        }
    }

    fn expected_category_for_cleanup_rule(rule: &CleanupRule) -> ArtifactCategory {
        if rule.name.contains("target") {
            ArtifactCategory::RustTarget
        } else if rule.name.starts_with("electron")
            || rule.name.contains("cache")
            || rule.name.contains("logs")
            || rule.name.contains("ipsw")
        {
            ArtifactCategory::CacheDir
        } else if rule.name.contains("derived-data") || rule.name.contains("buildroot") {
            ArtifactCategory::BuildOutput
        } else if rule.reclaim_command == ReclaimCommand::PromptBeforeRemove {
            ArtifactCategory::TempDir
        } else {
            ArtifactCategory::Unknown
        }
    }

    fn assert_confidence(rule: &CleanupRule, actual: f64) {
        let expected = match rule.confidence {
            CleanupConfidence::Definite => 0.96,
            CleanupConfidence::Likely => 0.92,
            CleanupConfidence::Unclear => 0.56,
            CleanupConfidence::ReportOnly | CleanupConfidence::Sacred => 0.0,
        };
        assert!(
            (actual - expected).abs() < f64::EPSILON,
            "{} confidence should be {expected}, got {actual}",
            rule.name
        );
    }

    #[test]
    fn fixed_cargo_prefix_safe_for_source_module() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        // Scenario: A source module named "cargo_utils" (e.g. src/cargo_utils/)
        // It has no artifacts, no Cargo.toml (it's a module, not a crate root).
        let path = PathBuf::from("/data/projects/mycrate/src/cargo_utils");
        let signals = StructuralSignals::default(); // No markers

        let classification = classify_macos(&registry, &path, signals);

        // Assert that it DOES NOT match the dangerous "cargo-prefix" pattern anymore.
        // It should fall back to unknown or some other low-confidence match.
        assert_ne!(classification.pattern_name, "cargo-prefix");
        assert!(
            classification.combined_confidence < 0.2,
            "Confidence should be low for source dir: {}",
            classification.combined_confidence
        );

        let input = CandidateInput {
            path,
            size_bytes: 4096,
            age: Duration::from_hours(24), // Old
            classification,
            signals,
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };

        let score = engine.score_candidate(&input, 0.5);

        // Should now be Keep (score too low).
        assert_eq!(
            score.decision.action,
            DecisionAction::Keep,
            "SAFE: Source module 'cargo_utils' kept."
        );
    }

    #[test]
    fn fixed_cache_name_safe_for_source_module() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        // Scenario: A source module named "cache" (e.g. src/cache/)
        let path = PathBuf::from("/data/projects/mycrate/src/cache");
        let signals = StructuralSignals::default();

        let classification = classify_macos(&registry, &path, signals);

        // Matches generic-cache-exact, but confidence should be lower (0.45).
        assert_eq!(classification.pattern_name, "generic-cache-exact");
        assert!(classification.name_confidence <= 0.45);

        let input = CandidateInput {
            path,
            size_bytes: 4096,
            age: Duration::from_hours(24),
            classification,
            signals,
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };

        // Score:
        // Location (0.40) * 0.25 = 0.10
        // Name (0.45) * 0.25 = 0.1125
        // Age (1.0) * 0.20 = 0.20
        // Size (0.05) * 0.15 = 0.0075
        // Structure (0.40) * 0.15 = 0.06
        // Total = 0.48 < 0.5 (min_score).

        let score = engine.score_candidate(&input, 0.5); // Moderate pressure
        assert_eq!(
            score.decision.action,
            DecisionAction::Keep,
            "SAFE: Source module 'cache' kept."
        );
    }

    #[test]
    fn fixed_underscore_target_source_crate_is_hard_kept() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        let path = PathBuf::from("/data/projects/asupersync_ansi_c/tools/rust_fuzz_target");
        let signals = StructuralSignals {
            has_cargo_toml: true,
            ..StructuralSignals::default()
        };
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "underscore-target-suffix");
        assert!(
            classification.combined_confidence < 0.1,
            "Cargo.toml source root should not retain high *_target confidence: {}",
            classification.combined_confidence
        );

        let input = CandidateInput {
            path,
            size_bytes: 5 * 1_073_741_824,
            age: Duration::from_hours(336),
            classification,
            signals,
            active_references: ActiveReferenceSummary::default(),
            is_open: false,
            excluded: false,
        };

        let score = engine.score_candidate(&input, 0.95);

        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("contains Cargo.toml without build-artifact markers")
        );
    }

    #[test]
    fn generic_target_suffix_source_dir_without_markers_is_hard_kept() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        let path = PathBuf::from("/data/projects/asupersync_ansi_c/tools/rust_fuzz_target");
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "underscore-target-suffix");

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 5 * 1_073_741_824,
                age: Duration::from_hours(336),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("target-like name lacks Cargo build markers outside temporary storage")
        );
    }

    #[test]
    fn private_tmp_target_underscore_prefix_is_actionable_when_old_and_unreferenced() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        let path = PathBuf::from("/private/tmp/target_rust_fuzz_42");
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "tmp-target-underscore-prefix");
        assert_eq!(classification.category, ArtifactCategory::RustTarget);

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 5 * 1_073_741_824,
                age: Duration::from_hours(48),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(!score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Delete);
    }

    #[test]
    fn xcode_derived_data_project_dir_is_actionable_build_output() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path =
            PathBuf::from("/Users/operator/Library/Developer/Xcode/DerivedData/sbh-demo-abc123");
        let signals = StructuralSignals {
            has_build: true,
            mostly_object_files: true,
            ..StructuralSignals::default()
        };
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "xcode-derived-data");
        assert_eq!(classification.category, ArtifactCategory::BuildOutput);

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 3 * 1_073_741_824,
                age: Duration::from_hours(24 * 8),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.8,
        );

        assert!(!score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Delete);
    }

    #[test]
    fn core_simulator_cache_entry_is_actionable_but_devices_are_kept() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let cache_path =
            PathBuf::from("/Users/operator/Library/Developer/CoreSimulator/Caches/device-cache");
        let cache_signals = StructuralSignals::default();
        let cache_classification = classify_macos(&registry, &cache_path, cache_signals);

        assert_eq!(cache_classification.pattern_name, "core-simulator-caches");
        assert_eq!(cache_classification.category, ArtifactCategory::CacheDir);

        let cache_score = engine.score_candidate(
            &CandidateInput {
                path: cache_path,
                size_bytes: 2 * 1_073_741_824,
                age: Duration::from_hours(48),
                classification: cache_classification,
                signals: cache_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(!cache_score.vetoed);
        assert_eq!(cache_score.decision.action, DecisionAction::Delete);

        let device_path = PathBuf::from(
            "/Users/operator/Library/Developer/CoreSimulator/Devices/ABCDEF/data/Library/Caches",
        );
        let device_signals = StructuralSignals::default();
        let device_classification = classify_macos(&registry, &device_path, device_signals);

        assert_ne!(device_classification.pattern_name, "core-simulator-caches");

        let device_score = engine.score_candidate(
            &CandidateInput {
                path: device_path,
                size_bytes: 2 * 1_073_741_824,
                age: Duration::from_hours(48),
                classification: device_classification,
                signals: device_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert_eq!(device_score.decision.action, DecisionAction::Keep);
    }

    #[test]
    fn electron_service_worker_cache_is_actionable_cache_dir() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path = PathBuf::from(
            "/Users/operator/Library/Application Support/Claude/Service Worker/CacheStorage/session-1",
        );
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "electron-service-worker-cache");
        assert_eq!(classification.category, ArtifactCategory::CacheDir);

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 2 * 1_073_741_824,
                age: Duration::from_hours(12),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.8,
        );

        assert!(!score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Delete);
    }

    #[test]
    fn stale_ipsw_is_actionable_but_recent_ipsw_is_kept() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path =
            PathBuf::from("/Users/operator/Library/iTunes/iPhone Software Updates/iPhone_17.ipsw");
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "ipsw-software-updates");
        assert_eq!(classification.category, ArtifactCategory::CacheDir);

        let stale_score = engine.score_candidate(
            &CandidateInput {
                path: path.clone(),
                size_bytes: 6 * 1_073_741_824,
                age: Duration::from_hours(24 * 45),
                classification: classification.clone(),
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(!stale_score.vetoed);
        assert_eq!(stale_score.decision.action, DecisionAction::Delete);

        let recent_score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 6 * 1_073_741_824,
                age: Duration::from_hours(24 * 7),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert_eq!(recent_score.decision.action, DecisionAction::Keep);
        assert!(
            recent_score
                .veto_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("ipsw-software-updates age"))
        );
    }

    #[test]
    fn private_tmp_user_named_trash_requires_review_not_delete() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path = PathBuf::from("/tmp/frankenterm-trash-20260503");
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "user-named-trash");
        assert_eq!(classification.category, ArtifactCategory::TempDir);

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 8 * 1_073_741_824,
                age: Duration::from_hours(336),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(!score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Review);
        assert!(score.ledger.summary.contains("action=Review"));
    }

    #[test]
    fn home_trash_report_is_reported_but_hard_kept() {
        let fake_home = PathBuf::from("/Users/operator");
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path = fake_home.join(".Trash/old-session");
        let signals = StructuralSignals::default();
        let classification = classify_macos_with_home(&registry, &path, signals, &fake_home);

        assert_eq!(classification.pattern_name, "home-trash-report");
        assert_eq!(classification.category, ArtifactCategory::Unknown);
        assert!(classification.combined_confidence.abs() < f64::EPSILON);

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 3 * 1_073_741_824,
                age: Duration::from_secs(0),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert_eq!(
            score.veto_reason.as_deref(),
            Some("home-trash-report cleanup rule is report-only")
        );
    }

    #[test]
    fn spotlight_index_report_warns_about_rebuild_and_is_hard_kept() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path = PathBuf::from("/.Spotlight-V100");
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "spotlight-index-report");
        assert_eq!(classification.category, ArtifactCategory::Unknown);
        assert!(classification.combined_confidence.abs() < f64::EPSILON);

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 12 * 1_073_741_824,
                age: Duration::from_secs(0),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            1.0,
        );

        let reason = score
            .veto_reason
            .as_deref()
            .expect("spotlight report should be vetoed");
        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert!(reason.contains("spotlight-index-report cleanup rule is report-only"));
        assert!(reason.contains("1-4 hour rebuild"));
        assert!(reason.contains("cripple the machine"));
    }

    #[test]
    fn stale_release_work_buildroot_is_actionable_even_with_cargo_manifest() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path = PathBuf::from("/Users/operator/release-work/mcp_agent_mail_rust_buildroot");
        let signals = StructuralSignals {
            has_cargo_toml: true,
            ..StructuralSignals::default()
        };
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "release-work-buildroot");
        assert_eq!(classification.category, ArtifactCategory::BuildOutput);

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 39 * 1_073_741_824,
                age: Duration::from_hours(24 * 11),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(!score.vetoed, "unexpected veto: {:?}", score.veto_reason);
        assert_eq!(score.decision.action, DecisionAction::Delete);
    }

    #[test]
    fn recent_release_work_buildroot_is_kept_until_seven_days_old() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let path = PathBuf::from("/Users/operator/release-work/mcp_agent_mail_rust_buildroot");
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &path, signals);

        assert_eq!(classification.pattern_name, "release-work-buildroot");

        let score = engine.score_candidate(
            &CandidateInput {
                path,
                size_bytes: 39 * 1_073_741_824,
                age: Duration::from_hours(24 * 6),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
        );

        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert!(
            score
                .veto_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("below 604800s"))
        );
    }

    #[test]
    fn private_tmp_user_named_trash_with_beads_stowaway_is_hard_kept() {
        let dir = TempDirBuilder::new()
            .prefix("sbh-agent-trash-")
            .tempdir_in("/tmp")
            .expect("create tmp trash candidate");
        let candidate_path = dir.path().to_path_buf();
        fs::create_dir_all(candidate_path.join("nested").join(".beads"))
            .expect("create beads stowaway");
        fs::write(
            candidate_path
                .join("nested")
                .join(".beads")
                .join("beads.db"),
            b"project state",
        )
        .expect("write beads stowaway");

        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();
        let signals = StructuralSignals::default();
        let classification = classify_macos(&registry, &candidate_path, signals);
        let overlaps = find_sacred_overlaps(&candidate_path, cross_platform_sacred_paths())
            .expect("scan stowaways");

        assert_eq!(classification.pattern_name, "user-named-trash");
        assert!(overlaps.iter().any(|overlap| overlap.pattern == ".beads/"));

        let score = engine.score_candidate_with_sacred_overlaps(
            &CandidateInput {
                path: candidate_path,
                size_bytes: 8 * 1_073_741_824,
                age: Duration::from_hours(336),
                classification,
                signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: false,
                excluded: false,
            },
            0.95,
            &overlaps,
        );

        assert!(score.vetoed);
        assert_eq!(score.decision.action, DecisionAction::Keep);
        assert!(score.veto_reason.as_deref().is_some_and(|reason| {
            reason.contains("sacred path overlap") && reason.contains(".beads/")
        }));
    }
}
