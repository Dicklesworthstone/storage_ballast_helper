#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::path::PathBuf;
    use std::time::Duration;
    use storage_ballast_helper::core::config::ScoringConfig;
    use storage_ballast_helper::scanner::patterns::{
        ArtifactCategory, ArtifactClassification, StructuralSignals,
    };
    use storage_ballast_helper::scanner::scoring::{CandidateInput, DecisionAction, ScoringEngine};

    fn default_engine() -> ScoringEngine {
        ScoringEngine::from_config(&ScoringConfig::default(), 30)
    }

    fn classification(confidence: f64, category: ArtifactCategory) -> ArtifactClassification {
        ArtifactClassification {
            pattern_name: Cow::Borrowed("test"),
            category,
            name_confidence: confidence,
            structural_confidence: confidence,
            combined_confidence: confidence,
        }
    }

    #[test]
    fn var_tmp_root_should_be_vetoed() {
        let engine = default_engine();
        // Construct a candidate that represents /var/tmp itself
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/var/tmp"),
                size_bytes: 4096,
                age: Duration::from_secs(24 * 3600 * 30), // Very old
                classification: classification(0.0, ArtifactCategory::Unknown),
                signals: StructuralSignals::default(),
                is_open: false,
                excluded: false,
            },
            0.5,
        );

        // We expect this to be vetoed because deleting the root of a system tmp dir is bad.
        // However, based on my analysis, it currently returns false (not vetoed).
        // This test asserts the *correct* behavior we want to enforce.
        assert!(score.vetoed, "Root /var/tmp should be vetoed from deletion");
    }

    #[test]
    fn dev_shm_root_should_be_vetoed() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/dev/shm"),
                size_bytes: 4096,
                age: Duration::from_secs(24 * 3600 * 30),
                classification: classification(0.0, ArtifactCategory::Unknown),
                signals: StructuralSignals::default(),
                is_open: false,
                excluded: false,
            },
            0.5,
        );
        assert!(score.vetoed, "Root /dev/shm should be vetoed from deletion");
    }

    #[test]
    fn var_tmp_subdir_should_allowed() {
        let engine = default_engine();
        let score = engine.score_candidate(
            &CandidateInput {
                path: PathBuf::from("/var/tmp/my-build-artifact"),
                size_bytes: 1024 * 1024 * 100,
                age: Duration::from_secs(3600 * 5),
                classification: classification(0.9, ArtifactCategory::BuildOutput),
                signals: StructuralSignals::default(),
                is_open: false,
                excluded: false,
            },
            0.5,
        );
        // Subdirectories should NOT be vetoed (allowed to be scored/deleted).
        assert!(!score.vetoed, "Subdir of /var/tmp should allowed");
    }
}
