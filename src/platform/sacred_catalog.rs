//! Embedded cross-platform sacred-path catalog.

#![allow(missing_docs)]

use std::sync::OnceLock;

use serde::Deserialize;

use crate::platform::types::{SacredPath, SacredPathSource};

pub const CROSS_PLATFORM_SACRED_CATALOG_TOML: &str = include_str!("sacred.toml");

#[derive(Debug, Deserialize)]
struct SacredCatalog {
    paths: Vec<SacredPath>,
}

static CROSS_PLATFORM_SACRED_PATHS: OnceLock<Vec<SacredPath>> = OnceLock::new();

#[must_use]
pub fn cross_platform_sacred_paths() -> &'static [SacredPath] {
    CROSS_PLATFORM_SACRED_PATHS
        .get_or_init(|| {
            parse_cross_platform_sacred_catalog(CROSS_PLATFORM_SACRED_CATALOG_TOML)
                .expect("embedded cross-platform sacred catalog should parse")
        })
        .as_slice()
}

pub fn parse_cross_platform_sacred_catalog(raw: &str) -> Result<Vec<SacredPath>, toml::de::Error> {
    let catalog: SacredCatalog = toml::from_str(raw)?;
    Ok(catalog.paths)
}

#[must_use]
pub fn find_cross_platform_sacred_path(pattern: &str) -> Option<&'static SacredPath> {
    cross_platform_sacred_paths()
        .iter()
        .find(|entry| entry.pattern == pattern)
}

pub fn cross_platform_sacred_patterns() -> impl Iterator<Item = &'static str> {
    cross_platform_sacred_paths()
        .iter()
        .map(|entry| entry.pattern.as_str())
}

#[must_use]
pub fn all_cross_platform_sacred_paths_are_builtin() -> bool {
    cross_platform_sacred_paths()
        .iter()
        .all(|entry| entry.source == SacredPathSource::Builtin)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::platform::types::{SacredPathKind, SacredPathSource};

    use super::{
        CROSS_PLATFORM_SACRED_CATALOG_TOML, all_cross_platform_sacred_paths_are_builtin,
        cross_platform_sacred_paths, cross_platform_sacred_patterns,
        find_cross_platform_sacred_path, parse_cross_platform_sacred_catalog,
    };

    #[test]
    fn embedded_catalog_parses() {
        let parsed = parse_cross_platform_sacred_catalog(CROSS_PLATFORM_SACRED_CATALOG_TOML)
            .expect("embedded cross-platform sacred TOML should parse");
        assert_eq!(parsed, cross_platform_sacred_paths());
        assert!(
            parsed.len() >= 20,
            "catalog should cover cross-platform repository, database, and credential families"
        );
    }

    #[test]
    fn catalog_patterns_are_unique_and_builtin() {
        assert!(all_cross_platform_sacred_paths_are_builtin());

        let mut patterns = HashSet::new();
        for entry in cross_platform_sacred_paths() {
            assert!(
                patterns.insert(entry.pattern.as_str()),
                "duplicate sacred pattern: {}",
                entry.pattern
            );
            assert_eq!(entry.source, SacredPathSource::Builtin);
            assert!(
                !entry.reason.trim().is_empty(),
                "sacred pattern {} must have a non-blank reason",
                entry.pattern
            );
        }
    }

    #[test]
    fn catalog_covers_required_cross_platform_families() {
        for expected in [
            ".git/",
            ".beads/",
            "beads.db",
            "*.db",
            "*.sqlite",
            "*.sqlite3",
            "~/.ssh",
            "~/.ssh/*",
            "~/.gnupg",
            "~/.gnupg/*",
            "~/.config/age",
            "~/.config/age/*",
        ] {
            assert!(
                find_cross_platform_sacred_path(expected).is_some(),
                "missing cross-platform sacred pattern {expected}"
            );
        }
    }

    #[test]
    fn catalog_uses_content_markers_for_repo_and_database_state() {
        for pattern in [".git/", ".beads/", ".ssh/", ".gnupg/", ".config/age/"] {
            let entry =
                find_cross_platform_sacred_path(pattern).expect("pattern should be present");
            assert_eq!(entry.kind, SacredPathKind::ContainsAny);
        }

        for pattern in ["beads.db", "*.db", "*.sqlite", "*.sqlite3"] {
            let entry =
                find_cross_platform_sacred_path(pattern).expect("pattern should be present");
            assert_eq!(entry.kind, SacredPathKind::StowawayMarker);
        }
    }

    #[test]
    fn catalog_uses_globs_and_exact_matches_for_credential_roots() {
        for pattern in ["~/.ssh", "~/.gnupg", "~/.config/age"] {
            let entry =
                find_cross_platform_sacred_path(pattern).expect("pattern should be present");
            assert_eq!(entry.kind, SacredPathKind::ExactMatch);
        }

        for pattern in ["~/.ssh/*", "~/.gnupg/*", "~/.config/age/*"] {
            let entry =
                find_cross_platform_sacred_path(pattern).expect("pattern should be present");
            assert_eq!(entry.kind, SacredPathKind::GlobMatch);
        }
    }

    #[test]
    fn pattern_iterator_exposes_static_patterns() {
        let patterns: Vec<&str> = cross_platform_sacred_patterns().collect();
        assert_eq!(patterns.len(), cross_platform_sacred_paths().len());
        assert!(patterns.contains(&".git/"));
        assert!(patterns.contains(&"*.sqlite3"));
    }
}
