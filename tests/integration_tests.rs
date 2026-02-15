//! Integration tests: CLI smoke tests and full-pipeline scenarios.

mod common;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use storage_ballast_helper::ballast::manager::BallastManager;
use storage_ballast_helper::core::config::{BallastConfig, Config};
use storage_ballast_helper::daemon::notifications::{NotificationEvent, NotificationManager};
use storage_ballast_helper::monitor::ewma::DiskRateEstimator;
use storage_ballast_helper::monitor::pid::{PidPressureController, PressureLevel, PressureReading};
use storage_ballast_helper::monitor::predictive::{PredictiveActionPolicy, PredictiveConfig};
use storage_ballast_helper::scanner::deletion::{DeletionConfig, DeletionExecutor};
use storage_ballast_helper::scanner::patterns::{
    ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, StructuralSignals,
};
use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::scoring::{CandidateInput, DecisionAction, ScoringEngine};
use storage_ballast_helper::scanner::walker::{DirectoryWalker, WalkerConfig};

#[test]
fn help_command_prints_usage() {
    let result = common::run_cli_case("help_command_prints_usage", &["--help"]);
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("Usage: sbh [OPTIONS] <COMMAND>"),
        "missing help banner; log: {}",
        result.log_path.display()
    );
}

#[test]
fn version_command_prints_version() {
    let result = common::run_cli_case("version_command_prints_version", &["--version"]);
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("storage_ballast_helper")
            || result.stdout.contains("sbh")
            || result.stderr.contains("storage_ballast_helper"),
        "missing version output; log: {}",
        result.log_path.display()
    );
}

#[test]
fn subcommand_help_flags_work() {
    // Verify that each subcommand accepts --help without crashing.
    let subcommands = [
        "install",
        "uninstall",
        "status",
        "stats",
        "scan",
        "clean",
        "ballast",
        "config",
        "daemon",
        "emergency",
        "protect",
        "unprotect",
        "tune",
        "check",
        "blame",
        "dashboard",
    ];

    for subcmd in subcommands {
        let case_name = format!("subcommand_{subcmd}_help");
        let result = common::run_cli_case(&case_name, &[subcmd, "--help"]);
        assert!(
            result.status.success(),
            "subcommand '{subcmd} --help' failed; log: {}",
            result.log_path.display()
        );
        assert!(
            result.stdout.contains("Usage") || result.stdout.contains("usage"),
            "subcommand '{subcmd} --help' missing usage info; log: {}",
            result.log_path.display()
        );
    }
}

#[test]
fn json_flag_accepted_by_status() {
    let result = common::run_cli_case("json_flag_accepted_by_status", &["status", "--json"]);
    // Status may succeed or fail depending on system state, but
    // it should produce some output (not crash).
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        !combined.is_empty(),
        "status --json should produce output; log: {}",
        result.log_path.display()
    );
}

#[test]
fn completions_command_generates_shell_script() {
    let result = common::run_cli_case(
        "completions_command_generates_shell_script",
        &["completions", "bash"],
    );
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("sbh"),
        "expected completion script contents; log: {}",
        result.log_path.display()
    );
}

// ══════════════════════════════════════════════════════════════════
// Pipeline integration tests
// ══════════════════════════════════════════════════════════════════

// ── Scenario 1: Green pressure → no deletions ────────────────────

#[test]
fn green_pressure_no_deletions() {
    let env = common::TestEnvironment::new();
    // Create some files that look like normal project files.
    env.create_file(
        "project/src/main.rs",
        b"fn main() {}",
        Duration::from_secs(3600),
    );
    env.create_file(
        "project/Cargo.toml",
        b"[package]",
        Duration::from_secs(3600),
    );

    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);

    let input = CandidateInput {
        path: env.root().join("project/src/main.rs"),
        size_bytes: 12,
        age: Duration::from_secs(3600),
        classification: ArtifactClassification::unknown(),
        signals: StructuralSignals::default(),
        is_open: false,
        excluded: false,
    };

    let score = scoring.score_candidate(&input, 0.0); // Green: urgency=0
    // Unknown classification + low urgency → should NOT recommend deletion.
    assert_ne!(
        score.decision.action,
        DecisionAction::Delete,
        "green pressure should not delete unknown files"
    );
}

// ── Scenario 2: Pressure buildup with controller escalation ──────

#[test]
fn pressure_escalation_through_levels() {
    let mut pid = PidPressureController::new(
        0.25,
        0.08,
        0.02,
        100.0,
        18.0,
        1.0,
        20.0,
        14.0,
        10.0,
        6.0,
        Duration::from_secs(2),
    );
    let t0 = Instant::now();

    // Simulate declining free space over time.
    let readings = [
        (50, PressureLevel::Green),  // 50% free
        (12, PressureLevel::Yellow), // 12% free
        (8, PressureLevel::Orange),  // 8% free
        (4, PressureLevel::Red),     // 4% free
    ];

    for (i, (free_pct, expected_level)) in readings.iter().enumerate() {
        let r = pid.update(
            PressureReading {
                free_bytes: *free_pct,
                total_bytes: 100,
            },
            None,
            t0 + Duration::from_secs(i as u64),
        );
        assert_eq!(
            r.level, *expected_level,
            "at step {i}: expected {expected_level:?}, got {:?}",
            r.level
        );
    }
}

// ── Scenario 3: Ballast provision, release, verify, replenish ────

#[test]
fn ballast_lifecycle() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let ballast_dir = tmpdir.path().join("ballast");

    let config = BallastConfig {
        file_count: 3,
        file_size_bytes: 4096,
        replenish_cooldown_minutes: 0,
        auto_provision: true,
        ..BallastConfig::default()
    };

    let mut manager = BallastManager::new(ballast_dir.clone(), config).expect("create manager");

    // Provision.
    let prov = manager.provision(None).expect("provision");
    assert_eq!(prov.files_created, 3, "should create 3 ballast files");
    assert_eq!(manager.available_count(), 3);
    assert!(manager.releasable_bytes() > 0);

    // Verify integrity.
    let verify = manager.verify();
    assert_eq!(verify.files_ok, 3);
    assert_eq!(verify.files_corrupted, 0);

    // Release 2.
    let release = manager.release(2).expect("release");
    assert_eq!(release.files_released, 2);
    assert_eq!(manager.available_count(), 1);

    // Replenish.
    let replenish = manager.replenish(None).expect("replenish");
    assert_eq!(
        replenish.files_created, 2,
        "should recreate 2 released files"
    );
    assert_eq!(manager.available_count(), 3);
}

// ── Scenario 4: Walker discovers entries in temp directory ────────

#[test]
fn walker_discovers_entries_in_tree() {
    let env = common::TestEnvironment::new();
    env.create_file("a/file1.txt", b"hello", Duration::from_secs(3600));
    env.create_file("a/b/file2.txt", b"world", Duration::from_secs(7200));
    env.create_dir("empty_dir");

    let config = WalkerConfig {
        root_paths: vec![env.root().to_path_buf()],
        max_depth: 5,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
    };

    let protection = ProtectionRegistry::new(None).expect("create protection");
    let walker = DirectoryWalker::new(config, protection);
    let entries = walker.walk().expect("walk should succeed");

    // Walker discovers directories as deletion candidates.
    let paths: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().to_string())
        .collect();
    assert!(!entries.is_empty(), "should discover at least some entries");
    // Directory "a" should be discovered.
    assert!(
        paths.iter().any(|p| p.ends_with("/a")),
        "should discover directory 'a' in {:?}",
        paths
    );
}

// ── Scenario 5: Scoring pipeline ranks artifacts above source ─────

#[test]
fn scoring_pipeline_ranks_artifacts_above_source() {
    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);

    // High-confidence Rust target artifact with strong structural signals.
    let target_input = CandidateInput {
        path: PathBuf::from("/tmp/project/target"),
        size_bytes: 500_000_000,            // 500 MB
        age: Duration::from_secs(4 * 3600), // 4 hours
        classification: ArtifactClassification {
            pattern_name: "cargo-target".to_string(),
            category: ArtifactCategory::RustTarget,
            name_confidence: 0.9,
            structural_confidence: 0.95,
            combined_confidence: 0.9,
        },
        signals: StructuralSignals {
            has_incremental: true,
            has_deps: true,
            has_build: true,
            has_fingerprint: true,
            ..Default::default()
        },
        is_open: false,
        excluded: false,
    };

    // Unknown source file — should not be recommended for deletion.
    let source_input = CandidateInput {
        path: PathBuf::from("/tmp/project/src/main.rs"),
        size_bytes: 500,
        age: Duration::from_secs(3600), // 1 hour
        classification: ArtifactClassification::unknown(),
        signals: StructuralSignals::default(),
        is_open: false,
        excluded: false,
    };

    let urgency = 0.8;
    let target_score = scoring.score_candidate(&target_input, urgency);
    let source_score = scoring.score_candidate(&source_input, urgency);

    assert!(
        !target_score.vetoed,
        "target should not be vetoed: {:?}",
        target_score.veto_reason
    );
    assert!(
        target_score.total_score > source_score.total_score,
        "target ({:.3}) should score higher than source ({:.3})",
        target_score.total_score,
        source_score.total_score,
    );
    assert!(
        target_score.total_score > 0.5,
        "target should have substantial score: {:.3}",
        target_score.total_score,
    );
}

// ── Scenario 6: Dry-run deletion pipeline ────────────────────────

#[test]
fn dry_run_deletes_nothing() {
    let env = common::TestEnvironment::new();
    let artifact = env.create_file(
        "target/debug/deps/libfoo.rlib",
        &vec![0u8; 1024],
        Duration::from_secs(86400),
    );

    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);
    let registry = ArtifactPatternRegistry::default();

    let class = registry.classify(
        &artifact,
        StructuralSignals {
            has_deps: true,
            ..Default::default()
        },
    );

    let candidate = CandidateInput {
        path: artifact.clone(),
        size_bytes: 1024,
        age: Duration::from_secs(86400),
        classification: class,
        signals: StructuralSignals {
            has_deps: true,
            ..Default::default()
        },
        is_open: false,
        excluded: false,
    };

    let scored = scoring.score_candidate(&candidate, 0.9);
    let executor = DeletionExecutor::new(
        DeletionConfig {
            max_batch_size: 10,
            dry_run: true,
            min_score: 0.0,
            circuit_breaker_threshold: 3,
            circuit_breaker_cooldown: Duration::from_secs(1),
            check_open_files: false,
        },
        None,
    );

    let plan = executor.plan(vec![scored]);
    let report = executor.execute(&plan, None);

    assert!(report.dry_run, "should be dry run");
    // File should still exist.
    assert!(artifact.exists(), "dry-run should not delete the file");
}

// ── Scenario 7: EWMA + Predictive action pipeline ───────────────

#[test]
fn predictive_pipeline_detects_imminent_danger() {
    let mut estimator = DiskRateEstimator::new(0.4, 0.1, 0.8, 3);
    let policy = PredictiveActionPolicy::new(PredictiveConfig {
        enabled: true,
        action_horizon_minutes: 30.0,
        warning_horizon_minutes: 60.0,
        min_confidence: 0.3,
        min_samples: 3,
        imminent_danger_minutes: 5.0,
        critical_danger_minutes: 2.0,
    });

    let t0 = Instant::now();
    let total = 100_000_u64;

    // Seed.
    let _ = estimator.update(50_000, t0, total / 10);
    // Rapid consumption: 10k bytes/sec.
    let _ = estimator.update(40_000, t0 + Duration::from_secs(1), total / 10);
    let _ = estimator.update(30_000, t0 + Duration::from_secs(2), total / 10);
    let estimate = estimator.update(20_000, t0 + Duration::from_secs(3), total / 10);

    let current_free_pct = 20.0;
    let action = policy.evaluate(&estimate, current_free_pct, PathBuf::from("/data"));

    // With rapid consumption, should detect at least a warning or worse.
    assert!(
        action.severity() >= 1,
        "expected warning or higher, got severity {}",
        action.severity()
    );
}

// ── Scenario 8: Notification manager fires events ────────────────

#[test]
fn notification_manager_handles_events_without_panic() {
    // Create a disabled notification manager (no actual channels).
    let mut manager = NotificationManager::disabled();
    assert!(!manager.is_enabled());

    // Fire all event types — should not panic.
    manager.notify(&NotificationEvent::PressureChanged {
        from: "Green".to_string(),
        to: "Yellow".to_string(),
        mount: "/data".to_string(),
        free_pct: 12.0,
    });
    manager.notify(&NotificationEvent::CleanupCompleted {
        items_deleted: 5,
        bytes_freed: 1_000_000,
        mount: "/data".to_string(),
    });
    manager.notify(&NotificationEvent::BallastReleased {
        mount: "/data".to_string(),
        files_released: 2,
        bytes_freed: 2_000_000_000,
    });
    manager.notify(&NotificationEvent::Error {
        code: "SBH-3900".to_string(),
        message: "test error".to_string(),
    });
}

// ── Scenario 9: Config roundtrip (TOML → load → validate) ───────

#[test]
fn config_toml_roundtrip() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let config_path = tmpdir.path().join("sbh-test.toml");

    let toml_content = r#"
[pressure]
green_min_free_pct = 25.0
yellow_min_free_pct = 18.0
orange_min_free_pct = 12.0
red_min_free_pct = 7.0
poll_interval_ms = 2000

[scanner]
max_depth = 8
parallelism = 2
dry_run = true

[ballast]
file_count = 5
file_size_bytes = 536870912
"#;

    std::fs::write(&config_path, toml_content).expect("write toml");
    let cfg = Config::load(Some(&config_path)).expect("load config");

    assert_eq!(cfg.pressure.green_min_free_pct, 25.0);
    assert_eq!(cfg.pressure.yellow_min_free_pct, 18.0);
    assert_eq!(cfg.scanner.max_depth, 8);
    assert!(cfg.scanner.dry_run);
    assert_eq!(cfg.ballast.file_count, 5);
}

// ── Scenario 10: Pattern registry classifies known artifacts ─────

#[test]
fn pattern_registry_classifies_rust_target() {
    let registry = ArtifactPatternRegistry::default();

    let signals = StructuralSignals {
        has_incremental: true,
        has_deps: true,
        has_build: true,
        has_fingerprint: true,
        ..Default::default()
    };

    let class = registry.classify(std::path::Path::new("/data/projects/myapp/target"), signals);
    assert_eq!(class.category, ArtifactCategory::RustTarget);
    assert!(class.combined_confidence > 0.5);
}

#[test]
fn pattern_registry_classifies_node_modules() {
    let registry = ArtifactPatternRegistry::default();
    let class = registry.classify(
        std::path::Path::new("/data/projects/webapp/node_modules"),
        StructuralSignals::default(),
    );
    assert_eq!(class.category, ArtifactCategory::NodeModules);
}

// ── Scenario 11: Walker respects protection markers ──────────────

#[test]
fn walker_skips_protected_directories() {
    let env = common::TestEnvironment::new();
    env.create_file("unprotected/file.txt", b"data", Duration::from_secs(3600));
    env.create_file("protected/.sbh-protect", b"{}", Duration::from_secs(3600));
    env.create_file("protected/secret.txt", b"keep", Duration::from_secs(3600));

    let config = WalkerConfig {
        root_paths: vec![env.root().to_path_buf()],
        max_depth: 5,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 1,
        excluded_paths: HashSet::new(),
    };

    let protection = ProtectionRegistry::new(None).expect("create protection");
    let walker = DirectoryWalker::new(config, protection);
    let entries = walker.walk().expect("walk should succeed");

    let paths: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().to_string())
        .collect();

    // The file inside protected/ should not appear in results.
    assert!(
        !paths.iter().any(|p| p.contains("secret.txt")),
        "protected directory contents should be skipped: {:?}",
        paths
    );
}

// ── Scenario 12: Batch scoring ranks by score descending ─────────

#[test]
fn batch_scoring_ranks_correctly() {
    let cfg = Config::default();
    let scoring = ScoringEngine::from_config(&cfg.scoring, cfg.scanner.min_file_age_minutes);

    let candidates = vec![
        CandidateInput {
            path: PathBuf::from("/tmp/project/target"),
            size_bytes: 500_000_000,
            age: Duration::from_secs(4 * 3600), // 4 hours
            classification: ArtifactClassification {
                pattern_name: "cargo-target".to_string(),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.9,
                structural_confidence: 0.95,
                combined_confidence: 0.9,
            },
            signals: StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_build: true,
                has_fingerprint: true,
                ..Default::default()
            },
            is_open: false,
            excluded: false,
        },
        CandidateInput {
            path: PathBuf::from("/tmp/project/notes.txt"),
            size_bytes: 100,
            age: Duration::from_secs(2 * 3600), // 2 hours
            classification: ArtifactClassification::unknown(),
            signals: StructuralSignals::default(),
            is_open: false,
            excluded: false,
        },
    ];

    let ranked = scoring.score_batch(&candidates, 0.7);
    assert_eq!(ranked.len(), 2);
    assert!(
        ranked[0].total_score >= ranked[1].total_score,
        "batch should be sorted by score descending: {:.3} >= {:.3}",
        ranked[0].total_score,
        ranked[1].total_score,
    );
    // The high-confidence artifact should rank higher.
    assert!(
        ranked[0].total_score > ranked[1].total_score,
        "artifact ({:.3}) should score strictly above unknown ({:.3})",
        ranked[0].total_score,
        ranked[1].total_score,
    );
}
