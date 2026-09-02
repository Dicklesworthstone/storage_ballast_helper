//! Regression: truncating a path for display used to slice at a byte
//! offset, which panics when the cut lands inside a multi-byte scalar
//! ("byte index 2 is not a char boundary" for `"aé"` cut to 1). The shared
//! helper the TUI and the CLI use must clamp to a char boundary.

#![allow(missing_docs)]

use storage_ballast_helper::core::paths::truncate_display_tail;

#[test]
fn truncating_inside_a_multibyte_scalar_does_not_panic() {
    // 'é' occupies two bytes; a byte cut at len - 1 lands inside it. One
    // byte cannot hold it (so nothing is shown), two bytes can.
    assert_eq!(truncate_display_tail("aé", 1), "");
    assert_eq!(truncate_display_tail("aé", 2), "é");
    assert_eq!(truncate_display_tail("é", 0), "");
    // Every possible width on a mixed string yields valid UTF-8 (a panic
    // would fail the test; the assertion checks the tail is a real suffix).
    let mixed = "/données/façade/naïve/target/débug";
    for width in 0..=mixed.len() + 2 {
        let tail = truncate_display_tail(mixed, width);
        assert!(mixed.ends_with(tail), "width {width}: {tail:?}");
    }
}

#[test]
fn truncation_keeps_whole_path_components_when_it_can() {
    let long = "/very/long/deeply/nested/project/target/debug/build/artifact";
    let tail = truncate_display_tail(long, 30);
    assert!(tail.starts_with('/'), "cut aligns to a component: {tail}");
    assert!(long.ends_with(tail));
    assert!(tail.len() <= 30 + "/project".len());
    assert_eq!(truncate_display_tail("/short/path", 40), "/short/path");
}
