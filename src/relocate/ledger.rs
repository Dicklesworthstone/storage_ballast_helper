//! Observation ledger: access evidence where the filesystem keeps none.
//!
//! On a `noatime` mount a read leaves no trace, so "unread for 14 days"
//! cannot be read off the tree. Instead every sweep records the trees it
//! found unchanged and unheld. A tree qualifies once that record spans the
//! idle window without a gap longer than `max_gap`: a missed day of sweeps
//! restarts the window, because nothing was watching then.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name of the ledger inside the state directory.
pub const LEDGER_FILENAME: &str = "relocation-ledger.json";

/// Exclusive ownership of a ledger's load, observation and save cycle.
///
/// Keep this guard alive through the last save, including transfers. Reports
/// that cannot acquire it may read a snapshot, but must not save observations.
pub struct WriterLock {
    #[cfg(unix)]
    _file: nix::fcntl::Flock<fs::File>,
}

impl WriterLock {
    /// Acquire the shared report/apply writer lock without waiting.
    pub fn acquire(state_dir: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            fs::create_dir_all(state_dir)?;
            let file = fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(state_dir.join("relocate.lock"))?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "relocation lock is not a regular file",
                ));
            }
            let file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .map_err(|(_, errno)| io::Error::from(errno))?;
            Ok(Self { _file: file })
        }
        #[cfg(not(unix))]
        {
            let _ = state_dir;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "relocation ledger locking requires Unix",
            ))
        }
    }
}

fn create_staging(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

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
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A dangling symlink is existing, unreadable state, not a missing
            // ledger. Nonblocking open also keeps a FIFO from stalling reports.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = match options.open(state_dir.join(LEDGER_FILENAME)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relocation ledger is not a regular file",
            ));
        }
        serde_json::from_reader(io::BufReader::new(file))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Write the ledger atomically and durably, using a private staging file.
    ///
    /// The caller must hold [`WriterLock`] from before loading this ledger
    /// through this save, so concurrent reports cannot replace newer state.
    pub fn save(&self, state_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join(LEDGER_FILENAME);
        let temporary = state_dir.join(format!(
            ".{LEDGER_FILENAME}.{}.{:032x}.tmp",
            std::process::id(),
            rand::random::<u128>()
        ));
        // Exclusive creation never truncates or follows an existing path. Only
        // a file successfully created by this call may be cleaned up below.
        let mut file = create_staging(&temporary)?;
        let staged = serde_json::to_writer_pretty(&mut file, self)
            .map_err(io::Error::other)
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = staged {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        #[cfg(unix)]
        fs::File::open(state_dir)?.sync_all()?;
        Ok(())
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

    #[test]
    #[cfg(unix)]
    fn writer_lock_serializes_reports_and_transfers() {
        let tmp = tempfile::tempdir().unwrap();
        let first = WriterLock::acquire(tmp.path()).unwrap();
        let error = WriterLock::acquire(tmp.path()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(first);
        assert!(WriterLock::acquire(tmp.path()).is_ok());
    }

    #[test]
    fn corrupt_existing_state_is_an_error_not_an_empty_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LEDGER_FILENAME);
        fs::write(&path, b"{interrupted or corrupt").unwrap();
        assert_eq!(
            Ledger::load(tmp.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fs::read(path).unwrap(), b"{interrupted or corrupt");
    }

    #[test]
    #[cfg(unix)]
    fn dangling_ledger_symlink_is_not_treated_as_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LEDGER_FILENAME);
        let absent = tmp.path().join("absent");
        std::os::unix::fs::symlink(&absent, &path).unwrap();
        assert!(Ledger::load(tmp.path()).is_err());
        assert_eq!(fs::read_link(path).unwrap(), absent);
    }

    #[test]
    #[cfg(unix)]
    fn nonregular_ledger_is_rejected_without_waiting_for_a_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LEDGER_FILENAME);
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert_eq!(
            Ledger::load(tmp.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    #[cfg(unix)]
    fn staging_is_private_and_never_truncates_existing_files_or_symlinks() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let staged = tmp.path().join("staged");
        let file = create_staging(&staged).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        drop(file);
        fs::write(&staged, b"previous interrupted save").unwrap();
        assert_eq!(
            create_staging(&staged).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&staged).unwrap(), b"previous interrupted save");
        let link = tmp.path().join("staging-link");
        std::os::unix::fs::symlink(&staged, &link).unwrap();
        assert!(create_staging(&link).is_err());
        assert_eq!(fs::read(staged).unwrap(), b"previous interrupted save");
        assert!(fs::symlink_metadata(link).unwrap().is_symlink());
    }

    #[test]
    #[cfg(unix)]
    fn save_preserves_legacy_staging_symlinks_and_publishes_private_state() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let _lock = WriterLock::acquire(tmp.path()).unwrap();
        let victim = tmp.path().join("unrelated-data");
        fs::write(&victim, b"keep these bytes").unwrap();
        let legacy = tmp.path().join(format!(".{LEDGER_FILENAME}.tmp"));
        std::os::unix::fs::symlink(&victim, &legacy).unwrap();
        let mut ledger = Ledger::default();
        ledger
            .in_progress
            .insert(PathBuf::from("/tmp/unit"), "backup:resume-here/".into());
        ledger.save(tmp.path()).unwrap();
        assert_eq!(Ledger::load(tmp.path()).unwrap(), ledger);
        assert_eq!(fs::read(victim).unwrap(), b"keep these bytes");
        assert!(fs::symlink_metadata(legacy).unwrap().is_symlink());
        assert_eq!(
            fs::metadata(tmp.path().join(LEDGER_FILENAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Only the caller's permanent files remain; the successful staging
        // file was atomically replaced, and unrelated staging was preserved.
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 4);
    }

    #[test]
    #[cfg(unix)]
    fn writer_lock_refuses_a_symlink_without_touching_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("other-lock");
        fs::write(&target, b"unrelated lock").unwrap();
        std::os::unix::fs::symlink(&target, tmp.path().join("relocate.lock")).unwrap();
        assert!(WriterLock::acquire(tmp.path()).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unrelated lock");
    }
}
