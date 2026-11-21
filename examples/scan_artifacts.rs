//! Scan a directory for build artifacts, score them, and print results.
//!
//! Usage:
//!   cargo run --example scan_artifacts -- /path/to/scan
//!
//! Demonstrates library-only usage with no daemon, CLI, or SQLite.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::scanner::patterns::ArtifactPatternRegistry;
use storage_ballast_helper::scanner::protection::ProtectionRegistry;
use storage_ballast_helper::scanner::scoring::{
    ActiveReferenceSummary, CandidateInput, ScoringEngine,
};
use storage_ballast_helper::scanner::walker::{DirectoryWalker, WalkerConfig};

fn main() {
    let scan_root = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("."), PathBuf::from);

    println!("Scanning: {}", scan_root.display());

    let config = Config::default();
    let registry = ArtifactPatternRegistry::default();
    let protection = ProtectionRegistry::new(None).expect("protection registry");

    let walker_config = WalkerConfig {
        root_paths: vec![scan_root],
        max_depth: config.scanner.max_depth,
        follow_symlinks: false,
        cross_devices: false,
        parallelism: 4,
        excluded_paths: HashSet::new(),
        opaque_pruning: false,
    };

    let walker = DirectoryWalker::new(walker_config, protection);
    let entries = walker.walk().expect("walk failed");
    println!("Found {} entries", entries.len());

    let engine = ScoringEngine::from_config(&config.scoring, config.scanner.min_file_age_minutes);
    let now = SystemTime::now();

    let mut candidates: Vec<CandidateInput> = Vec::new();
    for entry in &entries {
        if entry.metadata.is_dir {
            let Some((classification, classified_tree_modified)) =
                entry.walk_classification(&registry)
            else {
                continue;
            };
            let age = now
                .duration_since(entry.effective_age_timestamp(
                    classification.category.is_regenerable_tree(),
                    classified_tree_modified,
                ))
                .unwrap_or_default();
            candidates.push(CandidateInput {
                path: entry.path.clone(),
                size_bytes: entry.metadata.content_size_bytes,
                age,
                classification,
                signals: entry.structural_signals,
                active_references: ActiveReferenceSummary::default(),
                is_open: entry.is_open,
                excluded: false,
            });
        }
    }

    let scores = engine.score_batch(&candidates, 0.5);
    let mut actionable: Vec<_> = scores
        .iter()
        .filter(|s| {
            s.decision.action != storage_ballast_helper::scanner::scoring::DecisionAction::Keep
        })
        .collect();
    actionable.sort_by(|a, b| b.total_score.partial_cmp(&a.total_score).unwrap());

    println!("\n{} actionable candidates:", actionable.len());
    for score in actionable.iter().take(20) {
        println!(
            "  {:.3}  {}  ({:?})",
            score.total_score,
            score.path.display(),
            score.classification.category,
        );
    }
}
