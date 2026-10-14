//! `/etc/sbh/relocation.toml`: where dormant protected trees may go.
//!
//! Kept apart from the daemon's `config.toml` so a host can enable, retarget
//! or disable relocation without touching the daemon's configuration, and so
//! a typo here cannot stop the daemon from starting.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default location of the relocation config.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/sbh/relocation.toml";

/// Shared caches and sbh's own state, never relocated.
///
/// A dormant fortnight does not prove a shared cache is dead: the next build
/// that needs it may be a month away. Matched against every path component from the scratch root down to the
/// candidate, so nothing inside a match is a candidate either.
pub const BUILTIN_EXCLUDES: &[&str] = &[
    ".cargo",
    ".rustup",
    ".sbh",
    "rch*",
    "*cargo-cache*",
    "*cargo_cache*",
    "cass*",
    "*agent_search*",
    "*agent_mail*",
    "*agent-mail*",
];

/// Relocation settings. Every field has a default, so an absent file gives a
/// report-only configuration with no target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelocationConfig {
    /// `--apply` refuses unless this is true. Reports work either way.
    pub enabled: bool,
    /// rsync destination prefix: a local directory (`/bulk/sbh-relocated`),
    /// `host:/path`, or `user@host:` for a key restricted with `rrsync`.
    pub target: Option<String>,
    /// Insert this host's name below `target`. Turn it off when the target
    /// is already per-host (an `rrsync` key confined to `<base>/<host>`).
    pub include_hostname: bool,
    /// SSH identity used for a remote target.
    pub ssh_identity: Option<PathBuf>,
    /// SSH port for a remote target.
    pub ssh_port: Option<u16>,
    /// Extra `ssh -o` options, e.g. `ProxyCommand=tailscale nc %h %p` on a
    /// host whose tailscaled runs without a tun device.
    pub ssh_options: Vec<String>,
    /// Store ownership and modes in xattrs on the receiver
    /// (`--fake-super`), for a receiver that is not root.
    pub fake_super: bool,
    /// Days every entry must have been unchanged and unread.
    pub min_idle_days: u64,
    /// Smallest tree worth moving.
    pub min_bytes: u64,
    /// Scratch roots searched for markers.
    pub roots: Vec<PathBuf>,
    /// How far below a marker a candidate may be: 0 moves only whole marked
    /// trees; 2 also moves a dormant child or grandchild of a marked tree
    /// that is still in use elsewhere.
    pub unit_depth: usize,
    /// How deep below a root to look for markers.
    pub marker_depth: usize,
    /// Stop relocating once a run has moved this much.
    pub max_bytes_per_run: u64,
    /// Ledger continuity: a longer gap between sweeps restarts the
    /// observation window, because nothing watched in between.
    pub max_gap_hours: u64,
    /// Extra component patterns never to relocate (`*` wildcards).
    pub exclude: Vec<String>,
    /// Ledger and lock directory.
    pub state_dir: PathBuf,
    /// Walk budget per run, in directory entries.
    pub max_entries: u64,
    /// rsync `--bwlimit` in KiB/s.
    pub bwlimit_kib: Option<u64>,
    /// Where the target is, in words, for the stub's readme. An `rrsync` key
    /// hides the real directory behind a relative path
    /// (`backup-host:/bulk/sbh-relocated/<host>`).
    pub target_note: Option<String>,
}

impl Default for RelocationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target: None,
            include_hostname: true,
            ssh_identity: None,
            ssh_port: None,
            ssh_options: Vec::new(),
            fake_super: true,
            min_idle_days: 14,
            min_bytes: 256 << 20,
            roots: ["/tmp", "/var/tmp", "/dev/shm", "/data/tmp"]
                .iter()
                .map(PathBuf::from)
                .collect(),
            unit_depth: 2,
            marker_depth: 4,
            max_bytes_per_run: 500 << 30,
            max_gap_hours: 36,
            exclude: Vec::new(),
            state_dir: PathBuf::from("/var/lib/sbh"),
            max_entries: 50_000_000,
            bwlimit_kib: None,
            target_note: None,
        }
    }
}

impl RelocationConfig {
    /// Load `path`, or the default path when `None`. A missing default file
    /// yields the defaults; a missing explicit file is an error.
    pub fn load(path: Option<&Path>) -> io::Result<(Self, Option<PathBuf>)> {
        let (path, explicit) = path.map_or_else(
            || (PathBuf::from(DEFAULT_CONFIG_PATH), false),
            |path| (path.to_path_buf(), true),
        );
        match fs::read_to_string(&path) {
            Ok(text) => {
                let config: Self = toml::from_str(&text).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{}: {error}", path.display()),
                    )
                })?;
                config.validate()?;
                Ok((config, Some(path)))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && !explicit => {
                Ok((Self::default(), None))
            }
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("{}: {error}", path.display()),
            )),
        }
    }

    /// Reject settings that would make "dormant" meaningless.
    pub fn validate(&self) -> io::Result<()> {
        let invalid = |message: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, message));
        if self.min_idle_days < 1 {
            return invalid("min_idle_days must be at least 1");
        }
        if self.max_gap_hours < 1 || self.max_gap_hours >= self.min_idle_days * 24 {
            return invalid("max_gap_hours must be at least 1 and below the idle window");
        }
        if self.unit_depth > 4 || self.marker_depth > 8 {
            return invalid("unit_depth must be <= 4 and marker_depth <= 8");
        }
        if self.roots.iter().any(|root| !root.is_absolute()) {
            return invalid("roots must be absolute paths");
        }
        if self
            .ssh_options
            .iter()
            .any(|option| option.contains(['\'', '"']))
        {
            return invalid("ssh_options must not contain quotes");
        }
        if self.target.as_deref().is_some_and(str::is_empty) {
            return invalid("target must not be empty");
        }
        Ok(())
    }

    /// The idle window in seconds.
    #[must_use]
    pub fn min_idle_secs(&self) -> i64 {
        i64::try_from(self.min_idle_days.saturating_mul(86_400)).unwrap_or(i64::MAX)
    }

    /// The ledger continuity gap in seconds.
    #[must_use]
    pub fn max_gap_secs(&self) -> i64 {
        i64::try_from(self.max_gap_hours.saturating_mul(3_600)).unwrap_or(i64::MAX)
    }

    /// The pattern that excludes `name`, if any.
    #[must_use]
    pub fn excluded_by(&self, name: &str) -> Option<String> {
        BUILTIN_EXCLUDES
            .iter()
            .map(|pattern| (*pattern).to_string())
            .chain(self.exclude.iter().cloned())
            .find(|pattern| wildcard_match(pattern, name))
    }
}

/// Match `name` against `pattern`, where `*` matches any run of characters.
#[must_use]
pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    // Check both ends before slicing, so the slice bounds are char boundaries.
    if !name.starts_with(first) || !name.ends_with(last) || name.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard_match("rch*", "rch-cargo-cache-w1"));
        assert!(wildcard_match("*cargo-cache*", "x-cargo-cache-y"));
        assert!(wildcard_match(".cargo", ".cargo"));
        assert!(!wildcard_match(".cargo", ".cargo2"));
        assert!(!wildcard_match("rch*", "scratch"));
        assert!(wildcard_match("a*b*c", "a-x-b-y-c"));
        assert!(!wildcard_match("a*b*c", "a-x-c-y-b"));
        assert!(!wildcard_match("ab*ba", "aba"));
    }

    #[test]
    fn builtin_excludes_cover_the_live_caches() {
        let config = RelocationConfig::default();
        for name in [
            "rch-cargo-cache-worker7",
            ".cargo",
            ".sbh",
            "cass-index",
            "rch_bolddesert",
        ] {
            assert!(config.excluded_by(name).is_some(), "{name}");
        }
        for name in ["agent-scratch-20261013", "cargo-home", "asx-bv24"] {
            assert!(config.excluded_by(name).is_none(), "{name}");
        }
    }

    #[test]
    fn parses_and_validates() {
        let config: RelocationConfig = toml::from_str(
            "enabled = true\ntarget = \"ubuntu@backup-host:\"\ninclude_hostname = false\nexclude = [\"keep-*\"]\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.min_idle_days, 14);
        assert!(config.excluded_by("keep-me").is_some());
        assert!(toml::from_str::<RelocationConfig>("enabeld = true\n").is_err());
        let bad = RelocationConfig {
            max_gap_hours: 14 * 24,
            ..RelocationConfig::default()
        };
        assert!(bad.validate().is_err());
    }
}
