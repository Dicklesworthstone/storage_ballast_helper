//! Per-file reservations and a short post-truncation recovery window.
//!
//! Reservations do not hold the table lock across filesystem I/O. Failed or
//! declined operations restore the previous record without sliding its timer.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;

pub(super) const WINDOW: Duration = Duration::from_secs(60);
const MAX_IDENTITIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Identity {
    device: u64,
    inode: u64,
    created: Option<SystemTime>,
    // Without birth time, qualify the inode by path to avoid withholding a
    // different log whose filesystem recycled a recently freed inode number.
    fallback_path: Option<PathBuf>,
}

impl Identity {
    fn for_file(path: &Path, meta: &fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let created = meta.created().ok();
            Some(Self {
                device: meta.dev(),
                inode: meta.ino(),
                created,
                fallback_path: created.is_none().then(|| path.to_path_buf()),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (path, meta);
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Completed {
    at: Instant,
    logical_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
enum Entry {
    InFlight,
    Completed(Completed),
}

#[derive(Debug, Default)]
pub(super) struct RecentTruncations {
    entries: HashMap<Identity, Entry>,
}

impl RecentTruncations {
    pub(super) fn acquire<'a>(
        history: &'a Mutex<Self>,
        path: &Path,
        meta: &fs::Metadata,
        now: Instant,
    ) -> Option<Reservation<'a>> {
        let key = Identity::for_file(path, meta)?;
        Self::reserve(history, key, now)
    }

    fn reserve(history: &Mutex<Self>, key: Identity, now: Instant) -> Option<Reservation<'_>> {
        let mut table = history.lock();
        let previous = match table.entries.get(&key) {
            Some(Entry::InFlight) => return None,
            Some(Entry::Completed(previous)) => {
                (now.saturating_duration_since(previous.at) < WINDOW).then_some(*previous)
            }
            None => None,
        };
        if !table.entries.contains_key(&key) && table.entries.len() >= MAX_IDENTITIES {
            table.entries.retain(|_, entry| match entry {
                Entry::InFlight => true,
                Entry::Completed(done) => now.saturating_duration_since(done.at) < WINDOW,
            });
            if table.entries.len() >= MAX_IDENTITIES {
                // Do not evict an in-flight operation or a live recovery
                // window merely to truncate another file without tracking it.
                return None;
            }
        }
        table.entries.insert(key.clone(), Entry::InFlight);
        drop(table);
        Some(Reservation {
            history,
            key,
            previous,
            committed: false,
        })
    }
}

pub(super) struct Reservation<'a> {
    history: &'a Mutex<RecentTruncations>,
    key: Identity,
    previous: Option<Completed>,
    committed: bool,
}

impl Reservation<'_> {
    pub(super) fn previous_size(&self) -> Option<u64> {
        self.previous.map(|previous| previous.logical_bytes)
    }

    pub(super) fn commit(mut self, logical_bytes: u64, finished_at: Instant) {
        self.history.lock().entries.insert(
            self.key.clone(),
            Entry::Completed(Completed {
                at: finished_at,
                logical_bytes,
            }),
        );
        self.committed = true;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut table = self.history.lock();
        if let Some(previous) = self.previous {
            table.entries.insert(self.key.clone(), Entry::Completed(previous));
        } else {
            table.entries.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(inode: u64) -> Identity {
        Identity {
            device: 1,
            inode,
            created: Some(SystemTime::UNIX_EPOCH),
            fallback_path: None,
        }
    }

    #[test]
    fn only_one_operation_on_an_identity_is_in_flight() {
        let history = Mutex::new(RecentTruncations::default());
        let now = Instant::now();
        let first = RecentTruncations::reserve(&history, identity(1), now).unwrap();
        assert!(RecentTruncations::reserve(&history, identity(1), now).is_none());
        assert!(RecentTruncations::reserve(&history, identity(2), now).is_some());
        // The lock is not held by a reservation while its file operation runs.
        assert!(history.try_lock().is_some());
        drop(first);
        assert!(RecentTruncations::reserve(&history, identity(1), now).is_some());
    }

    #[test]
    fn successful_windows_start_after_the_operation_and_expire_at_the_boundary() {
        let history = Mutex::new(RecentTruncations::default());
        let now = Instant::now();
        let permit = RecentTruncations::reserve(&history, identity(1), now).unwrap();
        let finished = now + Duration::from_secs(300);
        permit.commit(4096, finished);
        let cooling = RecentTruncations::reserve(
            &history,
            identity(1),
            finished + WINDOW - Duration::from_nanos(1),
        )
        .unwrap();
        assert_eq!(cooling.previous_size(), Some(4096));
        drop(cooling);
        let ready = RecentTruncations::reserve(&history, identity(1), finished + WINDOW).unwrap();
        assert_eq!(ready.previous_size(), None);
    }

    #[test]
    fn rejected_retries_do_not_slide_the_recovery_window() {
        let history = Mutex::new(RecentTruncations::default());
        let now = Instant::now();
        RecentTruncations::reserve(&history, identity(1), now).unwrap().commit(4096, now);
        for second in 1..60 {
            let retry = RecentTruncations::reserve(
                &history,
                identity(1),
                now + Duration::from_secs(second),
            )
            .unwrap();
            assert_eq!(retry.previous_size(), Some(4096));
            drop(retry);
        }
        let ready = RecentTruncations::reserve(&history, identity(1), now + WINDOW).unwrap();
        assert_eq!(ready.previous_size(), None);
    }

    #[test]
    fn an_earlier_observation_cannot_expire_a_window() {
        let history = Mutex::new(RecentTruncations::default());
        let now = Instant::now();
        RecentTruncations::reserve(&history, identity(1), now)
            .unwrap()
            .commit(4096, now + WINDOW);
        let retry = RecentTruncations::reserve(&history, identity(1), now).unwrap();
        assert_eq!(retry.previous_size(), Some(4096));
    }

    #[test]
    fn saturation_is_bounded_and_releases_expired_records_without_evicting_live_ones() {
        let history = Mutex::new(RecentTruncations::default());
        let now = Instant::now();
        for inode in 0..MAX_IDENTITIES {
            RecentTruncations::reserve(&history, identity(inode as u64), now)
                .unwrap()
                .commit(4096, now);
        }
        assert_eq!(history.lock().entries.len(), MAX_IDENTITIES);
        assert!(RecentTruncations::reserve(&history, identity(u64::MAX), now).is_none());
        let in_flight = RecentTruncations::reserve(&history, identity(0), now).unwrap();
        let next = RecentTruncations::reserve(&history, identity(u64::MAX), now + WINDOW).unwrap();
        assert_eq!(history.lock().entries.len(), 2);
        assert!(RecentTruncations::reserve(&history, identity(0), now + WINDOW).is_none());
        drop(next);
        drop(in_flight);
    }

    #[test]
    fn a_recycled_inode_with_a_different_birth_time_is_not_the_previous_file() {
        let history = Mutex::new(RecentTruncations::default());
        let now = Instant::now();
        let old = identity(7);
        RecentTruncations::reserve(&history, old.clone(), now).unwrap().commit(4096, now);
        let mut new = old;
        new.created = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
        let replacement = RecentTruncations::reserve(&history, new, now).unwrap();
        assert_eq!(replacement.previous_size(), None);
    }
}
