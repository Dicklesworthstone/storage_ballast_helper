//! Device-scoped admission for directory work (bd-gh0x).
//!
//! Cold btrfs inode lookups contend on the filesystem root's inode lock.
//! One active directory task per btrfs device avoids adding contenders to
//! that lock. Other filesystems retain the caller's worker parallelism.
//! Waiting tasks stay off the ready queue, so they never occupy workers
//! that could be walking an unrelated device.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crossbeam_channel as channel;
use parking_lot::Mutex;

use super::WorkItem;

/// Directory tasks admitted concurrently on one detected btrfs device.
pub const MAX_ACTIVE_BTRFS_DIRECTORIES: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemKind {
    Btrfs,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WalkFilesystem {
    pub(super) device_id: u64,
    kind: FilesystemKind,
}

#[derive(Debug, Default)]
struct DeviceAdmission {
    active: usize,
    pending: VecDeque<WorkItem>,
}

/// The existing unbounded directory work queue, with btrfs admission ahead
/// of its ready channel. The bounded result channel still supplies output
/// backpressure. `in_flight` includes ready, deferred, and running work.
#[derive(Debug)]
pub(super) struct WorkQueue {
    tx: channel::Sender<WorkItem>,
    rx: channel::Receiver<WorkItem>,
    filesystems: Mutex<HashMap<u64, FilesystemKind>>,
    devices: Mutex<HashMap<u64, DeviceAdmission>>,
    in_flight: AtomicUsize,
}

impl WorkQueue {
    pub(super) fn new() -> Self {
        let (tx, rx) = channel::unbounded();
        Self {
            tx,
            rx,
            filesystems: Mutex::default(),
            devices: Mutex::default(),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Cache the filesystem family by the device from the walk's existing
    /// metadata read. A descendant inherits this answer until its metadata
    /// identifies a crossed mount. No additional per-child stat is needed.
    pub(super) fn filesystem(&self, path: &Path, device_id: u64) -> WalkFilesystem {
        let known = self.filesystems.lock().get(&device_id).copied();
        let kind = known.unwrap_or_else(|| {
            // Do not hold the shared admission lock across a filesystem call.
            let observed = filesystem_kind(path);
            *self.filesystems.lock().entry(device_id).or_insert(observed)
        });
        WalkFilesystem { device_id, kind }
    }

    #[cfg(test)]
    pub(super) fn mark_btrfs(&self, device_id: u64) {
        self.filesystems
            .lock()
            .insert(device_id, FilesystemKind::Btrfs);
    }

    pub(super) fn enqueue(&self, item: WorkItem) {
        self.in_flight.fetch_add(1, Ordering::Release);
        if item.filesystem.kind == FilesystemKind::Btrfs {
            let mut devices = self.devices.lock();
            let device = devices.entry(item.filesystem.device_id).or_default();
            if device.active >= MAX_ACTIVE_BTRFS_DIRECTORIES {
                device.pending.push_back(item);
                drop(devices);
                return;
            }
            device.active += 1;
            drop(devices);
        }
        self.send_ready(item);
    }

    fn send_ready(&self, item: WorkItem) {
        // The unbounded channel cannot be full, and this queue owns its
        // receiver until every worker and the stream have released it.
        self.tx
            .send(item)
            .expect("the work queue owns its ready receiver");
    }

    pub(super) fn recv_timeout(
        &self,
        wait: Duration,
    ) -> Result<WorkItem, channel::RecvTimeoutError> {
        self.rx.recv_timeout(wait)
    }

    pub(super) fn ready_is_empty(&self) -> bool {
        self.rx.is_empty()
    }

    pub(super) fn is_finished(&self) -> bool {
        self.in_flight.load(Ordering::Acquire) == 0
    }

    /// Release the completed task's admission. Its next sibling goes to
    /// the back of the ready queue exactly once; waiting workers never
    /// poll a device lock or repeatedly requeue blocked tasks.
    pub(super) fn complete(&self, filesystem: WalkFilesystem) {
        if filesystem.kind == FilesystemKind::Btrfs {
            let next = {
                let mut devices = self.devices.lock();
                let device = devices
                    .get_mut(&filesystem.device_id)
                    .expect("an admitted btrfs task has device state");
                let next = device.pending.pop_front();
                if next.is_none() {
                    device.active -= 1;
                }
                drop(devices);
                next
            };
            if let Some(next) = next {
                self.send_ready(next);
            }
        }
        let previous = self.in_flight.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "only admitted work can complete");
    }

    /// Called only after every worker has stopped. As with the original
    /// work channel, a queued directory makes its parent incomplete.
    pub(super) fn unfinished_paths(&self) -> Vec<PathBuf> {
        let mut unfinished = Vec::new();
        let mut record = |item: WorkItem| {
            if let Some(parent) = item.path.parent() {
                unfinished.push(parent.to_path_buf());
            }
        };
        for item in self.rx.try_iter() {
            record(item);
        }
        for device in self.devices.lock().values_mut() {
            for item in device.pending.drain(..) {
                record(item);
            }
        }
        unfinished
    }
}

#[cfg(target_os = "linux")]
fn filesystem_kind(path: &Path) -> FilesystemKind {
    const BTRFS_SUPER_MAGIC: u32 = 0x9123_683E;
    let Ok(stats) = rustix::fs::statfs(path) else {
        // Missing family evidence must not suppress traversal or silently
        // reduce the configured concurrency of an unrelated filesystem.
        return FilesystemKind::Other;
    };
    // Linux's filesystem magic is 32 bits in a signed, word-sized field.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let magic = stats.f_type as u32;
    if magic == BTRFS_SUPER_MAGIC {
        FilesystemKind::Btrfs
    } else {
        FilesystemKind::Other
    }
}

#[cfg(not(target_os = "linux"))]
const fn filesystem_kind(_path: &Path) -> FilesystemKind {
    FilesystemKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(path: &str, device_id: u64, kind: FilesystemKind) -> WorkItem {
        WorkItem {
            path: PathBuf::from(path),
            depth: 1,
            root_device_id: device_id,
            opaque_tree: None,
            filesystem: WalkFilesystem { device_id, kind },
            expected_metadata: None,
        }
    }

    #[test]
    fn btrfs_admits_one_directory_per_device_in_fifo_order() {
        let work = WorkQueue::new();
        for index in 0..64 {
            work.enqueue(item(
                &format!("/build/dir-{index}"),
                41,
                FilesystemKind::Btrfs,
            ));
        }
        for index in 0..64 {
            assert!(!work.is_finished());
            let next = work.rx.try_recv().expect("the next directory is admitted");
            assert_eq!(next.path, PathBuf::from(format!("/build/dir-{index}")));
            assert!(work.ready_is_empty(), "siblings must remain deferred");
            work.complete(next.filesystem);
        }
        assert!(work.is_finished());
        assert!(work.ready_is_empty());
        assert!(work.unfinished_paths().is_empty());
    }

    #[test]
    fn blocked_btrfs_work_leaves_other_devices_and_workers_available() {
        let work = WorkQueue::new();
        for index in 0..8 {
            work.enqueue(item(
                &format!("/btrfs-a/dir-{index}"),
                41,
                FilesystemKind::Btrfs,
            ));
        }
        work.enqueue(item("/btrfs-b/first", 42, FilesystemKind::Btrfs));
        for index in 0..64 {
            work.enqueue(item(
                &format!("/ext4/dir-{index}"),
                43,
                FilesystemKind::Other,
            ));
        }
        let ready: Vec<_> = work.rx.try_iter().collect();
        assert_eq!(ready.len(), 66);
        assert_eq!(ready[0].path, Path::new("/btrfs-a/dir-0"));
        assert_eq!(ready[1].path, Path::new("/btrfs-b/first"));
        assert!(ready[2..].iter().all(|item| item.path.starts_with("/ext4")));
        for item in ready.iter().skip(1) {
            work.complete(item.filesystem);
        }
        assert!(work.ready_is_empty(), "device A still owns its admission");
        assert!(!work.is_finished());
        work.complete(ready[0].filesystem);
        let next = work.rx.try_recv().unwrap();
        assert_eq!(next.path, Path::new("/btrfs-a/dir-1"));
    }

    #[test]
    fn cancellation_retains_both_ready_and_deferred_unfinished_paths() {
        let work = WorkQueue::new();
        work.enqueue(item("/btrfs/running", 41, FilesystemKind::Btrfs));
        let running = work.rx.try_recv().unwrap();
        work.enqueue(item("/btrfs/pending/one", 41, FilesystemKind::Btrfs));
        work.enqueue(item("/btrfs/pending/two", 41, FilesystemKind::Btrfs));
        work.enqueue(item("/ext4/queued/three", 42, FilesystemKind::Other));
        work.complete(running.filesystem);
        let mut unfinished = work.unfinished_paths();
        unfinished.sort();
        assert_eq!(
            unfinished,
            [
                PathBuf::from("/btrfs/pending"),
                PathBuf::from("/btrfs/pending"),
                PathBuf::from("/ext4/queued"),
            ]
        );
    }

    #[test]
    fn missing_filesystem_evidence_keeps_normal_admission() {
        let work = WorkQueue::new();
        let absent = Path::new("/sbh-test-no-such-filesystem/path");
        let filesystem = work.filesystem(absent, 41);
        assert_eq!(filesystem.kind, FilesystemKind::Other);
        assert_eq!(work.filesystem(absent, 41), filesystem);
        for index in 0..8 {
            let mut entry = item(&format!("/other/{index}"), 41, FilesystemKind::Other);
            entry.filesystem = filesystem;
            work.enqueue(entry);
        }
        assert_eq!(work.rx.len(), 8);
    }
}
