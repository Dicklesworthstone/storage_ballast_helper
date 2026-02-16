#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;
    use storage_ballast_helper::core::config::ScoringConfig;
    use storage_ballast_helper::scanner::patterns::{
        ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, StructuralSignals,
    };
    use storage_ballast_helper::scanner::scoring::{CandidateInput, DecisionAction, ScoringEngine};

    fn default_engine() -> ScoringEngine {
        ScoringEngine::from_config(&ScoringConfig::default(), 4) // 4 hours min age
    }

    #[test]
    fn risky_cargo_prefix_deletes_source_module() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        // Scenario: A source module named "cargo_utils" (e.g. src/cargo_utils/)
        // It has no artifacts, no Cargo.toml (it's a module, not a crate root).
        let path = PathBuf::from("/data/projects/mycrate/src/cargo_utils");
        let signals = StructuralSignals::default(); // No markers

        let classification = registry.classify(&path, signals);

        // Assert that it currently matches the "cargo_" pattern with high confidence
        assert_eq!(classification.pattern_name, "cargo-prefix");
        assert!(
            classification.combined_confidence > 0.5,
            "Confidence too high for source dir: {}",
            classification.combined_confidence
        );

        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 4096,
            age: Duration::from_secs(24 * 3600), // Old
            classification,
            signals,
            is_open: false,
            excluded: false,
        };

        // At moderate pressure (0.5), this should NOT be deleted.
        // But with current logic, it likely IS deleted.
        let score = engine.score_candidate(&input, 0.5);

        // If this assertion passes, the bug is real (it says Delete).
        // I want to verify the BUG exists, so I assert Delete.
        assert_eq!(
            score.decision.action,
            DecisionAction::Delete,
            "DANGEROUS: Source module 'cargo_utils' flagged for deletion!"
        );
    }

    #[test]
    fn risky_cache_name_deletes_source_module() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        // Scenario: A source module named "cache" (e.g. src/cache/)
        let path = PathBuf::from("/data/projects/mycrate/src/cache");
        let signals = StructuralSignals::default();

        let classification = registry.classify(&path, signals);

        assert_eq!(classification.pattern_name, "generic-cache-exact");

        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 4096,
            age: Duration::from_secs(24 * 3600),
            classification,
            signals,
            is_open: false,
            excluded: false,
        };

        let score = engine.score_candidate(&input, 0.5);
        assert_eq!(
            score.decision.action,
            DecisionAction::Delete,
            "DANGEROUS: Source module 'cache' flagged for deletion!"
        );
    }
}
