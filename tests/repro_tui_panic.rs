#![allow(missing_docs)]

#[test]
#[should_panic]
fn test_truncate_path_panic() {
    // Minimal deterministic repro: 'é' occupies two bytes in UTF-8.
    // Index 2 is inside that scalar value for "aé", so slicing at 2 panics.
    let path = "aé";
    let max_len = 1;
    let start = path.len() - max_len;
    let _ = &path[start..];
}
