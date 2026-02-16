#[cfg(test)]
mod tests {
    use sbh::scanner::patterns::{ArtifactCategory, ArtifactClassification, ArtifactPatternRegistry, StructuralSignals};
    use sbh::scanner::scoring::{CandidateInput, ScoringEngine, DecisionAction};
    use sbh::core::config::ScoringConfig;
    use std::path::PathBuf;
    use std::time::Duration;
    use std::borrow::Cow;

    fn default_engine() -> ScoringEngine {
        ScoringEngine::from_config(&ScoringConfig::default(), 4) // 4 hours min age
    }

    #[test]
    fn fixed_cargo_prefix_safe_for_source_module() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        // Scenario: A source module named "cargo_utils" (e.g. src/cargo_utils/)
        // It has no artifacts, no Cargo.toml (it's a module, not a crate root).
        let path = PathBuf::from("/data/projects/mycrate/src/cargo_utils");
        let signals = StructuralSignals::default(); // No markers

        let classification = registry.classify(&path, signals);
        
        // Assert that it DOES NOT match the dangerous "cargo-prefix" pattern anymore.
        // It should fall back to unknown or some other low-confidence match.
        assert_ne!(classification.pattern_name, "cargo-prefix");
        assert!(classification.combined_confidence < 0.2, "Confidence should be low for source dir: {}", classification.combined_confidence);

        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 4096,
            age: Duration::from_secs(24 * 3600), // Old
            classification,
            signals,
            is_open: false,
            excluded: false,
        };

        let score = engine.score_candidate(&input, 0.5);
        
        // Should now be Keep (score too low).
        assert_eq!(score.decision.action, DecisionAction::Keep, "SAFE: Source module 'cargo_utils' kept.");
    }

    #[test]
    fn fixed_cache_name_safe_for_source_module() {
        let registry = ArtifactPatternRegistry::default();
        let engine = default_engine();

        // Scenario: A source module named "cache" (e.g. src/cache/)
        let path = PathBuf::from("/data/projects/mycrate/src/cache");
        let signals = StructuralSignals::default();

        let classification = registry.classify(&path, signals);
        
        // Matches generic-cache-exact, but confidence should be lower (0.45).
        assert_eq!(classification.pattern_name, "generic-cache-exact");
        assert!(classification.name_confidence <= 0.45);
        
        let input = CandidateInput {
            path: path.clone(),
            size_bytes: 4096,
            age: Duration::from_secs(24 * 3600),
            classification,
            signals,
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
        assert_eq!(score.decision.action, DecisionAction::Keep, "SAFE: Source module 'cache' kept.");
    }
}
