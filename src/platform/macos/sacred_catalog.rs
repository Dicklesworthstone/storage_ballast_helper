//! Embedded macOS sacred-path catalog.

#![allow(missing_docs)]

use std::sync::OnceLock;

use serde::Deserialize;

use crate::platform::sacred_catalog::cross_platform_sacred_paths;
use crate::platform::types::{SacredPath, SacredPathSource};

pub const MACOS_SACRED_CATALOG_TOML: &str = include_str!("sacred.toml");

#[derive(Debug, Deserialize)]
struct SacredCatalog {
    paths: Vec<SacredPath>,
}

static MACOS_SACRED_PATHS: OnceLock<Vec<SacredPath>> = OnceLock::new();

#[must_use]
pub fn macos_sacred_paths() -> &'static [SacredPath] {
    MACOS_SACRED_PATHS
        .get_or_init(|| {
            parse_macos_sacred_catalog(MACOS_SACRED_CATALOG_TOML)
                .expect("embedded macOS sacred catalog should parse")
        })
        .as_slice()
}

pub fn parse_macos_sacred_catalog(raw: &str) -> Result<Vec<SacredPath>, toml::de::Error> {
    let catalog: SacredCatalog = toml::from_str(raw)?;
    Ok(catalog.paths)
}

#[must_use]
pub fn find_macos_sacred_path(pattern: &str) -> Option<&'static SacredPath> {
    macos_sacred_paths()
        .iter()
        .find(|entry| entry.pattern == pattern)
}

pub fn macos_sacred_patterns() -> impl Iterator<Item = &'static str> {
    macos_sacred_paths()
        .iter()
        .map(|entry| entry.pattern.as_str())
}

#[must_use]
pub fn platform_macos_sacred_paths() -> Vec<SacredPath> {
    let mut paths =
        Vec::with_capacity(cross_platform_sacred_paths().len() + macos_sacred_paths().len());
    paths.extend_from_slice(cross_platform_sacred_paths());
    paths.extend_from_slice(macos_sacred_paths());
    paths
}

#[must_use]
pub fn all_macos_sacred_paths_are_builtin() -> bool {
    platform_macos_sacred_paths()
        .iter()
        .all(|entry| entry.source == SacredPathSource::Builtin)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::platform::types::{SacredPathKind, SacredPathSource};

    use super::{
        MACOS_SACRED_CATALOG_TOML, all_macos_sacred_paths_are_builtin, find_macos_sacred_path,
        macos_sacred_paths, macos_sacred_patterns, parse_macos_sacred_catalog,
        platform_macos_sacred_paths,
    };

    #[test]
    fn embedded_catalog_parses() {
        let parsed = parse_macos_sacred_catalog(MACOS_SACRED_CATALOG_TOML)
            .expect("embedded macOS sacred TOML should parse");
        assert_eq!(parsed, macos_sacred_paths());
        assert!(
            parsed.len() >= 20,
            "catalog should cover macOS user-data families"
        );
    }

    #[test]
    fn catalog_patterns_are_unique_and_builtin() {
        assert!(all_macos_sacred_paths_are_builtin());

        let mut patterns = HashSet::new();
        for entry in macos_sacred_paths() {
            assert!(
                patterns.insert(entry.pattern.as_str()),
                "duplicate sacred pattern: {}",
                entry.pattern
            );
            assert_eq!(entry.source, SacredPathSource::Builtin);
            assert!(
                !entry.reason.trim().is_empty(),
                "macOS sacred pattern {} must have a non-blank reason",
                entry.pattern
            );
        }
    }

    #[test]
    fn catalog_covers_required_macos_user_data_families() {
        for expected in [
            "~/Pictures/*.photoslibrary",
            "~/Library/Mail/*",
            "~/Library/Messages/*",
            "~/Library/Group Containers/group.com.apple.notes/*",
            "~/Library/Calendars/*",
            "~/Library/Group Containers/group.com.apple.reminders/*",
            "~/Library/Mobile Documents/com~apple~CloudDocs/*",
            "~/Movies/*.fcpbundle",
            "~/Movies/*.imovielibrary",
            "~/Music/Logic/*",
            "~/Music/GarageBand/*",
            "~/Pictures/Lightroom*",
            "~/Pictures/Capture One*",
            "~/Documents/**/*.qbo",
        ] {
            assert!(
                find_macos_sacred_path(expected).is_some(),
                "missing macOS sacred pattern {expected}"
            );
        }
    }

    #[test]
    fn catalog_uses_globs_for_bundle_families() {
        for pattern in [
            "~/Pictures/*.photoslibrary",
            "~/Movies/*.fcpbundle",
            "~/Movies/*.imovielibrary",
        ] {
            let entry = find_macos_sacred_path(pattern).expect("pattern should be present");
            assert_eq!(entry.kind, SacredPathKind::GlobMatch);
        }
    }

    #[test]
    fn pattern_iterator_exposes_static_patterns() {
        let patterns: Vec<&str> = macos_sacred_patterns().collect();
        assert_eq!(patterns.len(), macos_sacred_paths().len());
        assert!(patterns.contains(&"~/Library/Mobile Documents/com~apple~CloudDocs/*"));
    }

    #[test]
    fn platform_catalog_layers_cross_platform_and_macos_rules() {
        let platform_paths = platform_macos_sacred_paths();
        assert!(platform_paths.len() > macos_sacred_paths().len());
        assert!(
            platform_paths
                .iter()
                .any(|entry| entry.pattern == ".git/" && entry.kind == SacredPathKind::ContainsAny)
        );
        assert!(
            platform_paths
                .iter()
                .any(|entry| entry.pattern == "~/Pictures/*.photoslibrary"
                    && entry.kind == SacredPathKind::GlobMatch)
        );
    }
}
