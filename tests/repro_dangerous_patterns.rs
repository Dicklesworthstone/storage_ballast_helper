#[cfg(test)]
mod tests {
    use std::path::Path;
    use storage_ballast_helper::scanner::patterns::{
        ArtifactCategory, ArtifactPatternRegistry, StructuralSignals,
    };

    #[test]

    fn dangerous_prefixes_match_innocent_names() {
        let registry = ArtifactPatternRegistry::default();

        // "tmpl" (templates) starts with "tmp", but isn't a temp dir.

        // FIXED behavior: Should NOT match "generic-tmp-prefix" (now "tmp-", "tmp_", "tmp").

        let tmpl_class = registry.classify(Path::new("tmpl"), StructuralSignals::default());

        println!("tmpl classification: {:?}", tmpl_class);

        // Should be Unknown or have very low confidence.

        assert_ne!(
            tmpl_class.category,
            ArtifactCategory::TempDir,
            "tmpl should not be classified as TempDir"
        );

        assert!(
            tmpl_class.combined_confidence < 0.20,
            "Innocent 'tmpl' directory got high score: {}",
            tmpl_class.combined_confidence
        );

        // "cachet" starts with "cache".

        // FIXED behavior: Should NOT match "generic-cache-prefix".

        let cachet_class = registry.classify(Path::new("cachet"), StructuralSignals::default());

        assert_ne!(
            cachet_class.category,
            ArtifactCategory::CacheDir,
            "cachet should not be classified as CacheDir"
        );

        assert!(
            cachet_class.combined_confidence < 0.20,
            "Innocent 'cachet' directory got high score: {}",
            cachet_class.combined_confidence
        );
    }
}
