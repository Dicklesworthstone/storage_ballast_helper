//! Platform Abstraction Layer (PAL) — trait-based cross-platform support.

pub mod cleanup_catalog;
pub mod linux;
pub mod macos;
pub mod pal;
pub mod sacred_catalog;
pub mod test_overlay;
pub mod types;

use pal::Platform;

#[cfg(target_os = "linux")]
/// Return the compile-time-selected platform implementation.
#[must_use]
pub fn current() -> impl Platform {
    linux::LinuxPal::new()
}

#[cfg(target_os = "macos")]
/// Return the compile-time-selected platform implementation.
#[must_use]
pub fn current() -> impl Platform {
    macos::MacOsPal::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("sbh requires Linux or macOS");

/// Whether the effective user is root.
///
/// Root bypasses discretionary permission bits, so anything that provokes
/// `EACCES` with `chmod` (a handful of tests, the writability preflight's
/// negative path) has no meaning under uid 0. Callers that skip on root
/// print `SKIP: running as root` so a CI run can count them.
#[must_use]
pub fn running_as_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(test)]
mod tests {
    use super::{Platform, current};

    #[test]
    fn current_platform_matches_compile_target() {
        let platform = current();

        #[cfg(target_os = "linux")]
        assert_eq!(platform.name(), "linux");
        #[cfg(target_os = "macos")]
        assert_eq!(platform.name(), "macos");
    }

    #[test]
    fn current_platform_includes_cross_platform_sacred_catalog() {
        let platform = current();
        let patterns = platform
            .sacred_paths()
            .into_iter()
            .map(|entry| entry.pattern)
            .collect::<Vec<_>>();

        assert!(patterns.iter().any(|pattern| pattern == ".git/"));
        assert!(patterns.iter().any(|pattern| pattern == ".beads/"));
        assert!(patterns.iter().any(|pattern| pattern == "*.sqlite3"));
        assert!(patterns.iter().any(|pattern| pattern == "~/.ssh/*"));
    }
}
