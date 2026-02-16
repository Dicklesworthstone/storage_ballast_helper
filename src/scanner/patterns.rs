//! Artifact pattern registry: regex-based name matching with structural marker verification.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::borrow::Cow;
use std::path::Path;

/// High-level artifact category used by the scorer and CLI reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactCategory {
    RustTarget,
    NodeModules,
    PythonCache,
    BuildOutput,
    CacheDir,
    TempDir,
    AgentWorkspace,
    Unknown,
}

/// Structural features collected from a directory tree.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StructuralSignals {
    pub has_incremental: bool,
    pub has_deps: bool,
    pub has_build: bool,
    pub has_fingerprint: bool,
    pub has_git: bool,
    pub has_cargo_toml: bool,
    pub mostly_object_files: bool,
}

impl StructuralSignals {
    /// Returns true if the signals strongly indicate a build artifact directory
    /// (e.g., Rust target with incremental/deps/fingerprint markers, or mostly
    /// object files).
    #[must_use]
    pub fn has_strong_signal(&self) -> bool {
        // Two or more Rust-specific markers = strong signal.
        let rust_markers = u8::from(self.has_incremental)
            + u8::from(self.has_deps)
            + u8::from(self.has_fingerprint);
        rust_markers >= 2 || self.mostly_object_files || (self.has_build && self.has_deps)
    }
}

/// Classification output for one path.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactClassification {
    pub pattern_name: Cow<'static, str>,
    pub category: ArtifactCategory,
    pub name_confidence: f64,
    pub structural_confidence: f64,
    pub combined_confidence: f64,
}

impl ArtifactClassification {
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            pattern_name: Cow::Borrowed("unknown"),
            category: ArtifactCategory::Unknown,
            name_confidence: 0.0,
            structural_confidence: 0.0,
            combined_confidence: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKind {
    Exact(&'static str),
    Prefix(&'static str),
    #[allow(dead_code)] // variant exists for future pattern use
    Suffix(&'static str),
    #[allow(dead_code)] // match arm exists but no patterns use this variant yet
    Contains(&'static str),
}

#[derive(Debug, Clone)]
struct ArtifactPattern {
    name: &'static str,
    kind: MatchKind,
    confidence: f64,
    category: ArtifactCategory,
}

/// User-provided pattern extension.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomPattern {
    pub name: String,
    pub needle: String,
    pub confidence: f64,
    pub category: ArtifactCategory,
}

#[derive(Debug, Clone)]
struct NormalizedCustomPattern {
    pattern: CustomPattern,
    lowercase_needle: String,
}

/// Registry of built-in and custom patterns.
#[derive(Debug, Clone)]
pub struct ArtifactPatternRegistry {
    builtins: Vec<ArtifactPattern>,
    custom: Vec<NormalizedCustomPattern>,
}

impl Default for ArtifactPatternRegistry {
    fn default() -> Self {
        Self {
            builtins: builtin_patterns(),
            custom: Vec::new(),
        }
    }
}

impl ArtifactPatternRegistry {
    #[must_use]
    pub fn with_custom(mut self, custom: Vec<CustomPattern>) -> Self {
        self.custom = custom
            .into_iter()
            .map(|pattern| NormalizedCustomPattern {
                lowercase_needle: pattern.needle.to_lowercase(),
                pattern,
            })
            .collect();
        self
    }

    /// Classify one path name with optional structural evidence.
    #[must_use]
    pub fn classify(&self, path: &Path, signals: StructuralSignals) -> ArtifactClassification {
        let Some(name_os) = path.file_name() else {
            return ArtifactClassification::unknown();
        };
        let normalized = name_os.to_string_lossy().to_lowercase();

        let mut best = ArtifactClassification::unknown();
        for pattern in &self.builtins {
            if matches_builtin(pattern.kind, &normalized)
                && pattern.confidence > best.name_confidence
            {
                best = ArtifactClassification {
                    pattern_name: Cow::Borrowed(pattern.name),
                    category: pattern.category,
                    name_confidence: pattern.confidence,
                    structural_confidence: 0.0,
                    combined_confidence: pattern.confidence,
                };
            }
        }

        for custom in &self.custom {
            if normalized.contains(&custom.lowercase_needle)
                && custom.pattern.confidence > best.name_confidence
            {
                best = ArtifactClassification {
                    pattern_name: Cow::Owned(custom.pattern.name.clone()),
                    category: custom.pattern.category,
                    name_confidence: custom.pattern.confidence,
                    structural_confidence: 0.0,
                    combined_confidence: custom.pattern.confidence,
                };
            }
        }

        // Structural rescue path: name is ambiguous but layout screams "Rust target".
        if best.category == ArtifactCategory::Unknown
            && (signals.has_fingerprint || (signals.has_incremental && signals.has_deps))
        {
            best = ArtifactClassification {
                pattern_name: Cow::Borrowed("structural-rust-target"),
                category: ArtifactCategory::RustTarget,
                name_confidence: 0.55,
                structural_confidence: 0.0,
                combined_confidence: 0.55,
            };
        }

        let structural = structural_score(best.category, signals);
        let mut combined = 0.70f64
            .mul_add(best.name_confidence, 0.30 * structural)
            .clamp(0.0, 1.0);

        // Structural safety override: if the structural score is very low (indicating
        // a project root signal like Cargo.toml or .git), we must severely penalize
        // the combined score to prevent deletion, even if the name matches a pattern.
        if structural < 0.1 {
            combined *= 0.1;
        }

        ArtifactClassification {
            structural_confidence: structural,
            combined_confidence: combined,
            ..best
        }
    }
}

fn matches_builtin(kind: MatchKind, normalized: &str) -> bool {
    match kind {
        MatchKind::Exact(token) => normalized == token,
        MatchKind::Prefix(token) => normalized.starts_with(token),
        MatchKind::Suffix(token) => normalized.ends_with(token),
        MatchKind::Contains(token) => normalized.contains(token),
    }
}

fn structural_score(category: ArtifactCategory, signals: StructuralSignals) -> f64 {
    if signals.has_git {
        return 0.0;
    }
    match category {
        ArtifactCategory::RustTarget => {
            if signals.has_fingerprint {
                0.98
            } else if signals.has_incremental && signals.has_deps {
                0.92
            } else if signals.has_build && signals.has_deps {
                0.85
            } else if signals.has_cargo_toml {
                0.05
            } else if signals.mostly_object_files {
                0.90
            } else {
                0.40
            }
        }
        ArtifactCategory::NodeModules => 0.80,
        ArtifactCategory::PythonCache => 0.75,
        ArtifactCategory::BuildOutput | ArtifactCategory::CacheDir | ArtifactCategory::TempDir => {
            if signals.mostly_object_files {
                0.80
            } else {
                0.40
            }
        }
        ArtifactCategory::AgentWorkspace => 0.78,
        ArtifactCategory::Unknown => {
            if signals.has_fingerprint || (signals.has_incremental && signals.has_deps) {
                0.75
            } else {
                0.0
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn builtin_patterns() -> Vec<ArtifactPattern> {
    vec![
        ArtifactPattern {
            name: "cargo-target",
            kind: MatchKind::Exact("target"),
            confidence: 0.70,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "dot-target-prefix",
            kind: MatchKind::Prefix(".target"),
            confidence: 0.92,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "underscore-target-prefix",
            kind: MatchKind::Prefix("_target_"),
            confidence: 0.88,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "cargo-target-prefix",
            kind: MatchKind::Prefix("cargo-target-"),
            confidence: 0.94,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "target-prefix",
            kind: MatchKind::Prefix("target-"),
            confidence: 0.82,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "target-suffix",
            kind: MatchKind::Suffix("-target"),
            confidence: 0.88,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "tmp-target-prefix",
            kind: MatchKind::Prefix(".tmp_target"),
            confidence: 0.90,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "tmp-cargo-home",
            kind: MatchKind::Prefix(".tmp_cargo_home_"),
            confidence: 0.90,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "tmp-codex",
            kind: MatchKind::Prefix(".tmp-codex-"),
            confidence: 0.86,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "tmp-pijs",
            kind: MatchKind::Prefix(".tmp-pijs-"),
            confidence: 0.86,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "tmp-ext",
            kind: MatchKind::Prefix(".tmp-ext-"),
            confidence: 0.82,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "pi-agent",
            kind: MatchKind::Prefix("pi_agent_"),
            confidence: 0.85,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "pi-target",
            kind: MatchKind::Prefix("pi_target_"),
            confidence: 0.85,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "pi-opus",
            kind: MatchKind::Prefix("pi_opus_"),
            confidence: 0.84,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "br-build",
            kind: MatchKind::Prefix("br-build"),
            confidence: 0.82,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "frankenterm-prefix",
            kind: MatchKind::Prefix("frankenterm-"),
            confidence: 0.90,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "cargo-home-prefix",
            kind: MatchKind::Prefix("cargo-home-"),
            confidence: 0.88,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "dot-cargo-prefix",
            kind: MatchKind::Prefix(".cargo_"),
            confidence: 0.86,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "agent-ft-suffix",
            kind: MatchKind::Suffix("-ft"),
            confidence: 0.90,
            category: ArtifactCategory::AgentWorkspace,
        },
        ArtifactPattern {
            name: "cass-target",
            kind: MatchKind::Prefix("cass-target"),
            confidence: 0.82,
            category: ArtifactCategory::RustTarget,
        },
        ArtifactPattern {
            name: "node-modules",
            kind: MatchKind::Exact("node_modules"),
            confidence: 0.97,
            category: ArtifactCategory::NodeModules,
        },
        ArtifactPattern {
            name: "next-build",
            kind: MatchKind::Exact(".next"),
            confidence: 0.90,
            category: ArtifactCategory::BuildOutput,
        },
        ArtifactPattern {
            name: "python-pycache",
            kind: MatchKind::Exact("__pycache__"),
            confidence: 0.96,
            category: ArtifactCategory::PythonCache,
        },
        ArtifactPattern {
            name: "python-venv",
            kind: MatchKind::Exact(".venv"),
            confidence: 0.85,
            category: ArtifactCategory::PythonCache,
        },
        ArtifactPattern {
            name: "pytest-cache",
            kind: MatchKind::Exact(".pytest_cache"),
            confidence: 0.84,
            category: ArtifactCategory::PythonCache,
        },
        ArtifactPattern {
            name: "generic-cache-prefix-hyphen",
            kind: MatchKind::Prefix("cache-"),
            confidence: 0.45,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "generic-cache-prefix-underscore",
            kind: MatchKind::Prefix("cache_"),
            confidence: 0.45,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "generic-cache-exact",
            kind: MatchKind::Exact("cache"),
            confidence: 0.45,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "dot-cache",
            kind: MatchKind::Prefix(".cache"),
            confidence: 0.62,
            category: ArtifactCategory::CacheDir,
        },
        ArtifactPattern {
            name: "generic-tmp-prefix-hyphen",
            kind: MatchKind::Prefix("tmp-"),
            confidence: 0.45,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "generic-tmp-prefix-underscore",
            kind: MatchKind::Prefix("tmp_"),
            confidence: 0.45,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "generic-tmp-exact",
            kind: MatchKind::Exact("tmp"),
            confidence: 0.45,
            category: ArtifactCategory::TempDir,
        },
        ArtifactPattern {
            name: "dot-tmp",
            kind: MatchKind::Prefix(".tmp"),
            confidence: 0.60,
            category: ArtifactCategory::TempDir,
        },
    ]
}

/// Extract a recognizable pattern label from a path string.
///
/// Used by stats aggregation to group deleted items by pattern.
/// Returns a simplified pattern string like "target/" or ".target*".
pub fn extract_pattern_label(path: &str) -> String {
    let p = Path::new(path);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");

    // Match known artifact patterns.
    let lower = name.to_ascii_lowercase();
    if lower == "target" || lower.starts_with("target-") {
        return "target/".to_string();
    }
    if lower.ends_with("-target") {
        return "*-target".to_string();
    }
    if lower.starts_with(".target") || lower.starts_with("_target_") {
        return ".target*".to_string();
    }
    if lower.starts_with("cargo-target") || lower.starts_with("cargo_target") {
        return "cargo-target-*".to_string();
    }
    if lower.starts_with("pi_agent")
        || lower.starts_with("pi_target")
        || lower.starts_with("pi_opus")
    {
        return "pi_*".to_string();
    }
    if lower.starts_with("cass-target") {
        return "cass-target*".to_string();
    }
    if lower.starts_with("br-build") {
        return "br-build*".to_string();
    }
    if lower.starts_with("frankenterm-") {
        return "frankenterm-*".to_string();
    }
    if lower.starts_with("cargo-home-") {
        return "cargo-home-*".to_string();
    }
    if lower.starts_with(".cargo_") {
        return ".cargo_*".to_string();
    }
    if lower.ends_with("-ft") {
        return "*-ft".to_string();
    }
    if lower.starts_with(".tmp_target") {
        return ".tmp_target*".to_string();
    }
    if lower == "node_modules" {
        return "node_modules/".to_string();
    }

    // Fallback: use the directory name.
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::{ArtifactCategory, ArtifactPatternRegistry, CustomPattern, StructuralSignals};
    use std::path::Path;

    #[test]
    fn rust_target_with_markers_gets_high_confidence() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(
            Path::new(".target_opus_main"),
            StructuralSignals {
                has_incremental: true,
                has_deps: true,
                has_fingerprint: true,
                ..StructuralSignals::default()
            },
        );
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert!(classification.combined_confidence > 0.90);
    }

    #[test]
    fn ambiguous_target_without_markers_stays_lower_confidence() {
        let registry = ArtifactPatternRegistry::default();
        let classification = registry.classify(Path::new("target"), StructuralSignals::default());
        assert_eq!(classification.category, ArtifactCategory::RustTarget);
        assert!(classification.combined_confidence < 0.80);
    }

    #[test]
    fn node_modules_is_classified_correctly() {
        let registry = ArtifactPatternRegistry::default();
        let classification =
            registry.classify(Path::new("node_modules"), StructuralSignals::default());
        assert_eq!(classification.category, ArtifactCategory::NodeModules);
        assert!(classification.combined_confidence > 0.60);
    }

    #[test]
    fn custom_patterns_are_honored() {
        let registry = ArtifactPatternRegistry::default().with_custom(vec![CustomPattern {
            name: "my-cache".to_string(),
            needle: "mytool-cache".to_string(),
            confidence: 0.88,
            category: ArtifactCategory::CacheDir,
        }]);
        let classification =
            registry.classify(Path::new("mytool-cache-prod"), StructuralSignals::default());
        assert_eq!(classification.pattern_name, "my-cache");
        assert_eq!(classification.category, ArtifactCategory::CacheDir);
        assert!(classification.combined_confidence > 0.60);
    }

    #[test]
    fn cargo_toml_presence_penalizes_score() {
        let registry = ArtifactPatternRegistry::default();
        // A name that would normally get 0.94 confidence ("cargo-target-...")
        let classification = registry.classify(
            Path::new("cargo-target-project"),
            StructuralSignals {
                has_cargo_toml: true,
                ..StructuralSignals::default()
            },
        );
        // Should be crushed to < 0.1 despite the name match.
        assert!(
            classification.combined_confidence < 0.1,
            "score {} was not penalized enough",
            classification.combined_confidence
        );
    }

    #[test]
    fn tmp_agent_and_cache_patterns_from_real_world_dirs() {
        let registry = ArtifactPatternRegistry::default();
        let cases = [
            ("green-ft", ArtifactCategory::AgentWorkspace),
            ("frankenterm-build-1234", ArtifactCategory::AgentWorkspace),
            ("cargo-home-pearlstone", ArtifactCategory::TempDir),
            (".cargo_cache_runner", ArtifactCategory::CacheDir),
            ("work-target", ArtifactCategory::RustTarget),
        ];

        for (name, expected) in cases {
            let classification = registry.classify(Path::new(name), StructuralSignals::default());
            assert_eq!(
                classification.category, expected,
                "unexpected classification for {name}"
            );
            assert!(
                classification.combined_confidence > 0.55,
                "low confidence {:.2} for {name}",
                classification.combined_confidence
            );
        }
    }
}
