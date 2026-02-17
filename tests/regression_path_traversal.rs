#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use std::path::Path;
    use storage_ballast_helper::core::paths::resolve_absolute_path;

    #[test]
    #[ignore = "documents current behavior; enable once path-resolution contract is hardened"]
    fn resolve_absolute_path_currently_allows_traversal() {
        // This test demonstrates that normalize_syntactic (the fallback when
        // canonicalize fails) allows ".." to escape intended roots if the
        // intermediate paths don't exist.

        // Assume /nonexistent_root does not exist.
        // We want to see if we can resolve to /etc/passwd from it.
        // Input: /nonexistent_root/../etc/passwd
        // Expected SAFE behavior: Should probably fail or stay within some logical root if bounded.
        // Actual behavior: Resolves to /etc/passwd

        let bad_path = Path::new("/nonexistent_root/../etc/passwd");
        let resolved = resolve_absolute_path(bad_path);

        // This currently resolves to /etc/passwd via syntactic normalization
        // when canonicalization fails. Keep this as documentation-only until
        // resolve_absolute_path gains a hardened contract.
        assert_eq!(resolved, Path::new("/etc/passwd"));
    }
}
