//! Observation ledger: access evidence where the filesystem keeps none.
//!
//! On a `noatime` mount a read leaves no trace, so "unread for 14 days"
//! cannot be read off the tree. Instead every sweep records the trees it
//! found unchanged and unheld. A tree qualifies once that record spans the
//! idle window without a gap longer than `max_gap`: a missed day of sweeps
//! restarts the window, because nothing was watching then.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name of the ledger inside the state directory.
pub const LEDGER_FILENAME: &str = "relocation-ledger.json";

/// One tree's quiet streak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// When the current streak began (Unix seconds).
    pub quiet_since: i64,
    /// The most recent sweep that found it quiet.
    pub last_seen: i64,
    /// Its newest change at that sweep; any other value restarts the streak.
    pub newest_change: i64,
}

/// A completed relocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationEntry {
    /// Where the tree lived.
    pub path: PathBuf,
    /// The rsync destination holding it now.
    pub destination: String,
    /// Allocated bytes moved.
    pub bytes: u64,
    /// Regular files moved.
    pub files: u64,
    /// When it moved (Unix seconds).
    pub relocated_at: i64,
}

/// The ledger file's contents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// Quiet streaks by path.
    #[serde(default)]
    pub observations: BTreeMap<PathBuf, Observation>,
    /// Destinations chosen for transfers that have not finished, by path, so
    /// an interrupted transfer resumes into the same place.
    #[serde(default)]
    pub in_progress: BTreeMap<PathBuf, String>,
    /// Completed relocations, oldest first.
    #[serde(default)]
    pub relocations: Vec<RelocationEntry>,
}

impl Ledger {
    /// Read the ledger in `state_dir`; a missing file is an empty ledger.
    pub fn load(state_dir: &Path) -> io::Result<Self> {
        match fs::read(state_dir.join(LEDGER_FILENAME)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }

    /// Write the ledger atomically (temporary file, fsync, rename).
    pub fn save(&self, state_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join(LEDGER_FILENAME);
        let temporary = state_dir.join(format!(".{LEDGER_FILENAME}.tmp"));
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(self).map_err(io::Error::other)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)
    }

    /// Record one sweep's finding for `path`. `quiet` means unchanged for
    /// the idle window and held by nobody right now.
    pub fn observe(
        &mut self,
        path: &Path,
        newest_change: i64,
        quiet: bool,
        now: i64,
        max_gap: i64,
    ) {
        if !quiet {
            self.observations.remove(path);
            return;
        }
        let entry = self
            .observations
            .entry(path.to_path_buf())
            .or_insert(Observation {
                quiet_since: now,
                last_seen: now,
                newest_change,
            });
        let continuous =
            entry.newest_change == newest_change && now.saturating_sub(entry.last_seen) <= max_gap;
        if !continuous {
            entry.quiet_since = now;
            entry.newest_change = newest_change;
        }
        entry.last_seen = now;
    }

    /// Seconds of continuous quiet observed for `path`.
    #[must_use]
    pub fn observed_quiet(&self, path: &Path, now: i64, max_gap: i64) -> Option<i64> {
        let entry = self.observations.get(path)?;
        (now.saturating_sub(entry.last_seen) <= max_gap)
            .then(|| entry.last_seen.saturating_sub(entry.quiet_since))
    }

    /// Drop streaks nobody has confirmed within two gaps: their trees are
    /// gone, or no longer candidates.
    pub fn prune(&mut self, now: i64, max_gap: i64) {
        self.observations
            .retain(|_, entry| now.saturating_sub(entry.last_seen) <= max_gap.saturating_mul(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    const GAP: i64 = 36 * 3_600;

    #[test]
    fn streak_grows_only_while_continuous_and_unchanged() {
        let mut ledger = Ledger::default();
        let path = Path::new("/data/tmp/x");
        let start = 1_000_000;
        for day in 0..=14 {
            ledger.observe(path, 5, true, start + day * DAY, GAP);
        }
        assert_eq!(
            ledger.observed_quiet(path, start + 14 * DAY, GAP),
            Some(14 * DAY)
        );
        // A change restarts the streak.
        ledger.observe(path, 6, true, start + 15 * DAY, GAP);
        assert_eq!(ledger.observed_quiet(path, start + 15 * DAY, GAP), Some(0));
        // A two-day gap restarts it too.
        ledger.observe(path, 6, true, start + 17 * DAY, GAP);
        assert_eq!(ledger.observed_quiet(path, start + 17 * DAY, GAP), Some(0));
        // Activity clears it.
        ledger.observe(path, 6, false, start + 18 * DAY, GAP);
        assert_eq!(ledger.observed_quiet(path, start + 18 * DAY, GAP), None);
    }

    #[test]
    fn stale_streaks_neither_count_nor_survive() {
        let mut ledger = Ledger::default();
        let path = Path::new("/tmp/y");
        ledger.observe(path, 1, true, 0, GAP);
        ledger.observe(path, 1, true, 20 * DAY, GAP);
        assert_eq!(ledger.observed_quiet(path, 20 * DAY, GAP), Some(0));
        assert_eq!(ledger.observed_quiet(path, 30 * DAY, GAP), None);
        ledger.prune(30 * DAY, GAP);
        assert!(ledger.observations.is_empty());
    }

    #[test]
    fn round_trips_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::default();
        ledger.observe(Path::new("/tmp/z"), 3, true, 10, GAP);
        ledger
            .in_progress
            .insert(PathBuf::from("/tmp/z"), "dest/".into());
        ledger.save(tmp.path()).unwrap();
        assert_eq!(Ledger::load(tmp.path()).unwrap(), ledger);
        assert_eq!(
            Ledger::load(&tmp.path().join("missing")).unwrap(),
            Ledger::default()
        );
    }
}
