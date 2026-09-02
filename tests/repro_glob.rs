//! Regression (817028c): `**/` in a protection glob must match on component
//! boundaries. `src/**/main.rs` used to compile to `.*` followed by an
//! optional `/`, so it protected `src/badmain.rs` as well.

#![allow(missing_docs)]

use std::path::Path;

use storage_ballast_helper::scanner::protection::{ProtectionRegistry, validate_glob_pattern};

#[test]
fn double_star_matches_only_on_component_boundaries() {
    let patterns = vec!["/proj/src/**/main.rs".to_string()];
    validate_glob_pattern(&patterns[0]).expect("pattern is valid");
    let registry = ProtectionRegistry::new(Some(&patterns)).expect("registry");

    // Zero or more whole components between `src` and `main.rs`.
    assert!(registry.is_protected(Path::new("/proj/src/main.rs")));
    assert!(registry.is_protected(Path::new("/proj/src/a/main.rs")));
    assert!(registry.is_protected(Path::new("/proj/src/a/b/c/main.rs")));

    // A partial component is not a component.
    assert!(!registry.is_protected(Path::new("/proj/src/badmain.rs")));
    assert!(!registry.is_protected(Path::new("/proj/src/a/badmain.rs")));
    assert!(!registry.is_protected(Path::new("/proj/srcx/main.rs")));
    assert!(!registry.is_protected(Path::new("/other/src/main.rs")));
}

#[test]
fn single_star_stays_within_one_component() {
    let patterns = vec!["/data/projects/production-*".to_string()];
    let registry = ProtectionRegistry::new(Some(&patterns)).expect("registry");
    assert!(registry.is_protected(Path::new("/data/projects/production-api")));
    assert!(
        registry.is_protected(Path::new("/data/projects/production-api/target")),
        "a protected directory protects its subtree"
    );
    assert!(!registry.is_protected(Path::new("/data/projects/staging-api")));
    assert!(!registry.is_protected(Path::new("/data/projectsproduction-api")));
}
