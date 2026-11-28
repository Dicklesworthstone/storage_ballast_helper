//! Depth-first discovery within one priority pre-scan entry.
//!
//! A name is acknowledged only after its classification/scoring is handled.
//! An interrupted child listing therefore cannot discard earlier nominees or
//! falsely finish its depth-1 parent. Saved paths are scheduling hints only:
//! callers recheck every resumed ancestor before any descendant is examined.

use std::io;
use std::path::{Component, Path, PathBuf};

use super::{PrescanCursor, PressureOrder};

pub(super) const MAX_SHALLOW_ROOTS: usize = 128;
pub(super) const MAX_SHALLOW_BYTES: usize = 512 * 1024;

/// How fresh classification permits a shallow pre-scan to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShallowDisposition {
    /// Refused, irrelevant, or not a directory.
    Skip,
    /// Examine children, without nominating this directory itself.
    Descend,
    /// Score this directory without traversing its contents.
    Candidate,
    /// Score this depth-1 directory, then examine its children.
    CandidateAndDescend,
}

impl ShallowDisposition {
    const fn candidate(self) -> bool {
        matches!(self, Self::Candidate | Self::CandidateAndDescend)
    }

    const fn descend(self) -> bool {
        matches!(self, Self::Descend | Self::CandidateAndDescend)
    }
}

/// One nominee awaiting the caller's fresh safety checks and scoring.
#[derive(Debug, Clone)]
pub struct ShallowCandidate {
    /// The path selected from a current or resumed directory listing.
    pub path: PathBuf,
    descend: bool,
}

/// A budget yield is distinct from successfully finishing the depth-1 entry.
#[derive(Debug)]
pub enum ShallowPoll {
    /// Score this nominee, then acknowledge it before requesting another.
    Candidate(ShallowCandidate),
    /// The entire allowed depth-1/2/3 traversal was handled.
    Complete,
    /// Enumeration or inspection used the current pass's allowance.
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShallowFrame {
    pub(super) directory: PathBuf,
    pub(super) after: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShallowPosition {
    pub(super) entry: PathBuf,
    pub(super) pending: Option<PathBuf>,
    pub(super) frames: Vec<ShallowFrame>,
}

impl ShallowPosition {
    pub(super) fn paths(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.entry.as_path())
            .chain(self.pending.as_deref())
            .chain(self.frames.iter().flat_map(|frame| {
                std::iter::once(frame.directory.as_path()).chain(frame.after.as_deref())
            }))
    }

    pub(super) fn validate(&self, root: &Path) -> io::Result<()> {
        if !direct_child(root, &self.entry) || self.frames.len() > 2 {
            return Err(invalid("invalid shallow pre-scan entry or depth"));
        }
        let mut expected = self.entry.as_path();
        for (index, frame) in self.frames.iter().enumerate() {
            if (index == 0 && frame.directory != self.entry)
                || (index > 0 && !direct_child(expected, &frame.directory))
                || frame
                    .after
                    .as_deref()
                    .is_some_and(|after| !direct_child(&frame.directory, after))
            {
                return Err(invalid("shallow pre-scan frame escapes its parent"));
            }
            expected = &frame.directory;
        }
        if self.pending.as_deref().is_some_and(|pending| {
            if self.frames.is_empty() {
                pending != self.entry
            } else {
                !direct_child(expected, pending)
            }
        }) || self.paths().any(|path| !valid_path(path))
        {
            return Err(invalid("invalid shallow pre-scan pending path"));
        }
        Ok(())
    }

    fn handled(&mut self, descend: bool) {
        let Some(path) = self.pending.take() else {
            return;
        };
        if descend && self.frames.len() < 2 {
            self.frames.push(ShallowFrame {
                directory: path,
                after: None,
            });
        } else if let Some(parent) = self.frames.last_mut() {
            parent.after = Some(path);
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn valid_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    !bytes.is_empty()
        && bytes.len() <= 16 * 1024
        && !bytes.contains(&0)
        && !path.components().any(|component| {
            matches!(component, Component::ParentDir | Component::CurDir)
        })
        // Path::components normalizes interior dots; checkpoints must not.
        && !bytes.split(|byte| *byte == b'/').any(|part| part == b".")
}

fn direct_child(parent: &Path, child: &Path) -> bool {
    valid_path(parent)
        && valid_path(child)
        && child.parent() == Some(parent)
        && child.file_name().is_some()
}

impl PrescanCursor {
    /// Whether polling this entry would resume below a previously inspected
    /// part of the branch. A suffix alone cannot certify a whole opaque unit.
    pub(crate) fn resumes_shallow_entry(&self, root: &Path, entry: &Path) -> bool {
        self.shallow.get(root).is_some_and(|position| {
            position.entry == entry
                && (!position.frames.is_empty() || position.pending.as_deref() != Some(entry))
        })
    }

    /// Continue a depth-1 entry through depth 3, checking the live budget
    /// between every inspection and between bounded enumeration chunks.
    /// `inspect` must revalidate scope, directory type, symlinks, and protection.
    /// It is called again for every retained ancestor on every poll.
    pub fn poll_shallow(
        &mut self,
        root: &Path,
        entry: &Path,
        follow_symlinks: bool,
        mut keep_reading: impl FnMut() -> bool,
        mut inspect: impl FnMut(&Path, usize) -> ShallowDisposition,
    ) -> io::Result<ShallowPoll> {
        if !direct_child(root, entry) {
            return Err(invalid("shallow entry is not a direct child of its root"));
        }
        if self
            .shallow
            .get(root)
            .is_some_and(|position| position.entry != entry)
        {
            self.forget_shallow(root);
        }
        self.shallow
            .entry(root.to_path_buf())
            .or_insert_with(|| ShallowPosition {
                entry: entry.to_path_buf(),
                pending: Some(entry.to_path_buf()),
                frames: Vec::new(),
            });
        self.bound_shallow(root);

        // A persisted child may no longer have the same traversable ancestors.
        // Reinspect from the top and discard only the refused branch's hints.
        let ancestors: Vec<_> = self.shallow[root]
            .frames
            .iter()
            .map(|frame| frame.directory.clone())
            .collect();
        for (index, ancestor) in ancestors.iter().enumerate() {
            if !keep_reading() {
                return Ok(ShallowPoll::Pending);
            }
            if !inspect(ancestor, index + 1).descend() {
                for abandoned in &ancestors[index..] {
                    self.discard_shallow_enumeration(root, entry, Some(abandoned));
                }
                let position = self.shallow.get_mut(root).expect("active shallow root");
                position.frames.truncate(index);
                position.pending = Some(ancestor.clone());
                break;
            }
        }

        loop {
            if !keep_reading() {
                return Ok(ShallowPoll::Pending);
            }
            let position = &self.shallow[root];
            if let Some(path) = &position.pending {
                let path = path.clone();
                let disposition = inspect(&path, position.frames.len() + 1);
                // Inspection may itself consume the last allowance. Keep the
                // nominee pending until the caller actually handles its score.
                if !keep_reading() {
                    return Ok(ShallowPoll::Pending);
                }
                if disposition.candidate() {
                    return Ok(ShallowPoll::Candidate(ShallowCandidate {
                        path,
                        descend: disposition.descend(),
                    }));
                }
                self.shallow
                    .get_mut(root)
                    .expect("active shallow root")
                    .handled(disposition.descend());
                self.bound_shallow(root);
                continue;
            }
            let Some(frame) = position.frames.last() else {
                self.forget_shallow(root);
                return Ok(ShallowPoll::Complete);
            };
            let directory = frame.directory.clone();
            let after = frame.after.clone();
            let page = match self.poll_shallow_entries(
                root,
                entry,
                &directory,
                after.as_deref(),
                follow_symlinks,
                &mut keep_reading,
            ) {
                Ok(Some(page)) => Some(page),
                Ok(None) => return Ok(ShallowPoll::Pending),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Err(error);
                }
                // An unreadable branch is refused for this discovery sweep,
                // not evidence of recursive coverage. Do not let one such
                // branch permanently hide every later candidate in its repo.
                // The next full sweep retries it under current permissions.
                Err(_) => None,
            };
            let position = self.shallow.get_mut(root).expect("active shallow root");
            if let Some(path) = page.and_then(|page| page.into_iter().next()) {
                position.pending = Some(path);
            } else {
                position.frames.pop();
                if let Some(parent) = position.frames.last_mut() {
                    parent.after = Some(directory.clone());
                }
                self.discard_shallow_enumeration(root, entry, Some(&directory));
            }
            self.bound_shallow(root);
        }
    }

    /// Acknowledge a scored or explicitly refused nominee. Merely yielding
    /// it from `poll_shallow` never advances discovery.
    pub fn acknowledge_shallow(&mut self, root: &Path, candidate: &ShallowCandidate) {
        if let Some(position) = self.shallow.get_mut(root)
            && position.pending.as_deref() == Some(candidate.path.as_path())
        {
            position.handled(candidate.descend);
        }
        self.bound_shallow(root);
    }

    pub(super) fn forget_shallow(&mut self, root: &Path) {
        if let Some(position) = self.shallow.remove(root) {
            self.discard_shallow_enumeration(root, &position.entry, None);
        }
    }

    fn bound_shallow(&mut self, active: &Path) {
        loop {
            let bytes: usize = self
                .shallow
                .iter()
                .map(|(root, position)| {
                    root.as_os_str().len()
                        + position
                            .paths()
                            .map(|path| path.as_os_str().len())
                            .sum::<usize>()
                })
                .sum();
            if self.shallow.len() <= MAX_SHALLOW_ROOTS && bytes <= MAX_SHALLOW_BYTES {
                break;
            }
            let Some(old) = self
                .shallow
                .keys()
                .find(|root| root.as_path() != active)
                .cloned()
            else {
                break;
            };
            // Dropping a hint only repeats discovery. The outer cursor has
            // not acknowledged this unfinished depth-1 entry.
            self.forget_shallow(&old);
        }
    }

    /// Resume automatic event scopes independently of configured-root sweeps.
    /// Explicit operator scans should use `scoped_read_ahead` instead.
    #[must_use]
    pub fn scoped_resume(&self) -> Self {
        self.scoped
            .as_deref()
            .map_or_else(|| self.scoped_read_ahead(), Clone::clone)
    }

    /// Retain bounded event-scope completion and shallow progress, pruning
    /// withdrawn roots. This never moves the configured sweep's root/entry.
    pub fn remember_scoped(&mut self, mut scoped: Self, roots: &[PathBuf]) {
        scoped.scoped = None;
        scoped.walk_order = PressureOrder::default();
        scoped.walk_dispatch = std::sync::Arc::default();
        let in_scope = |path: &Path| roots.iter().any(|root| path.starts_with(root));
        scoped.continuations.retain(|root, _| in_scope(root));
        let withdrawn: Vec<_> = scoped
            .shallow
            .keys()
            .filter(|root| !in_scope(root))
            .cloned()
            .collect();
        for root in withdrawn {
            scoped.forget_shallow(&root);
        }
        if scoped.root.as_deref().is_some_and(|root| !in_scope(root)) {
            scoped.root = None;
            scoped.after = None;
        }
        loop {
            let bytes: usize = scoped
                .root
                .iter()
                .chain(&scoped.after)
                .chain(scoped.continuations.iter().flat_map(<[_; 2]>::from))
                .map(|path| path.as_os_str().len())
                .sum();
            if scoped.continuations.len() <= MAX_SHALLOW_ROOTS && bytes <= MAX_SHALLOW_BYTES {
                break;
            }
            let old = scoped
                .continuations
                .keys()
                .find(|root| Some(root.as_path()) != scoped.root.as_deref())
                .cloned();
            let Some(old) = old else { break };
            scoped.continuations.remove(&old);
            scoped.forget_shallow(&old);
            scoped.discard_enumeration(&old);
        }
        self.scoped = Some(Box::new(scoped));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use super::*;

    fn inspect(path: &Path, depth: usize) -> ShallowDisposition {
        if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
            ShallowDisposition::Skip
        } else if path.file_name().is_some_and(|name| name == "target") {
            ShallowDisposition::Candidate
        } else if depth < 3 {
            ShallowDisposition::Descend
        } else {
            ShallowDisposition::Skip
        }
    }

    #[test]
    fn deep_nominees_survive_many_finite_slices_and_checkpoint_restarts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let entry = root.join("repo");
        let expected: BTreeSet<_> = (0..40)
            .map(|index| {
                let target = entry.join(format!("branch-{index:03}")).join("target");
                fs::create_dir_all(&target).unwrap();
                target
            })
            .collect();
        let checkpoint = temp.path().join("cursor.json");
        let mut cursor = PrescanCursor::new();
        let mut observed = BTreeSet::new();
        let mut stops = 0;
        for _ in 0..100 {
            let mut allowance = 50usize;
            loop {
                let result = cursor
                    .poll_shallow(
                        &root,
                        &entry,
                        false,
                        || {
                            let permitted = allowance > 0;
                            allowance = allowance.saturating_sub(1);
                            permitted
                        },
                        inspect,
                    )
                    .unwrap();
                match result {
                    ShallowPoll::Candidate(candidate) => {
                        assert!(
                            observed.insert(candidate.path.clone()),
                            "completed nominees must not replay"
                        );
                        cursor.acknowledge_shallow(&root, &candidate);
                    }
                    ShallowPoll::Pending => {
                        stops += 1;
                        assert_eq!(
                            cursor.position().1,
                            None,
                            "partial entry is not fully covered"
                        );
                        cursor.save(&checkpoint).unwrap();
                        // End the scanner lifetime, including every live reader.
                        drop(cursor);
                        cursor = PrescanCursor::load(&checkpoint);
                        break;
                    }
                    ShallowPoll::Complete => {
                        assert!(stops > 1);
                        assert_eq!(observed, expected);
                        assert!(cursor.shallow.is_empty());
                        return;
                    }
                }
            }
        }
        panic!("finite slices did not finish the shallow tree");
    }

    #[test]
    fn merely_nominating_a_candidate_never_acknowledges_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let entry = root.join("repo");
        fs::create_dir_all(entry.join("target")).unwrap();
        let checkpoint = temp.path().join("cursor.json");
        let mut cursor = PrescanCursor::new();
        let ShallowPoll::Candidate(candidate) = cursor
            .poll_shallow(&root, &entry, false, || true, inspect)
            .unwrap()
        else {
            panic!("expected target")
        };
        cursor.save(&checkpoint).unwrap();
        drop(cursor);
        let mut cursor = PrescanCursor::load(&checkpoint);
        let ShallowPoll::Candidate(retried) = cursor
            .poll_shallow(&root, &entry, false, || true, inspect)
            .unwrap()
        else {
            panic!("unacknowledged target must be retried")
        };
        assert_eq!(retried.path, candidate.path);
        cursor.acknowledge_shallow(&root, &retried);
        assert!(matches!(
            cursor
                .poll_shallow(&root, &entry, false, || true, inspect)
                .unwrap(),
            ShallowPoll::Complete
        ));
    }

    #[test]
    fn event_scopes_keep_their_own_positions_through_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let scoped_root = root.join("changed-project");
        let entry = scoped_root.join("workspace");
        fs::create_dir_all(entry.join("a/target")).unwrap();
        fs::create_dir_all(entry.join("b/target")).unwrap();
        let checkpoint = temp.path().join("cursor.json");
        let mut configured = PrescanCursor::new();
        configured.advance(&root, &root.join("already-covered"));
        let original = configured.position().1.map(Path::to_path_buf);
        let mut scoped = configured.scoped_resume();
        let ShallowPoll::Candidate(first) = scoped
            .poll_shallow(&scoped_root, &entry, false, || true, inspect)
            .unwrap()
        else {
            panic!("first scoped nominee")
        };
        scoped.acknowledge_shallow(&scoped_root, &first);
        configured.remember_scoped(scoped, std::slice::from_ref(&root));
        configured.save(&checkpoint).unwrap();
        drop(configured);
        let configured = PrescanCursor::load(&checkpoint);
        assert_eq!(configured.position().1, original.as_deref());
        let mut scoped = configured.scoped_resume();
        let ShallowPoll::Candidate(second) = scoped
            .poll_shallow(&scoped_root, &entry, false, || true, inspect)
            .unwrap()
        else {
            panic!("second scoped nominee")
        };
        assert_eq!(first.path, entry.join("a/target"));
        assert_eq!(second.path, entry.join("b/target"));
        assert_eq!(
            configured.scoped_read_ahead().position(),
            (None, None),
            "operator starts fresh"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_resumed_ancestor_with_a_symlink_never_visits_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let entry = root.join("repo");
        let branch = entry.join("branch");
        fs::create_dir_all(branch.join("target")).unwrap();
        let mut cursor = PrescanCursor::new();
        let ShallowPoll::Candidate(_) = cursor
            .poll_shallow(&root, &entry, false, || true, inspect)
            .unwrap()
        else {
            panic!("first candidate")
        };
        let outside = temp.path().join("outside");
        fs::rename(&branch, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &branch).unwrap();
        assert!(matches!(
            cursor
                .poll_shallow(&root, &entry, false, || true, inspect)
                .unwrap(),
            ShallowPoll::Complete
        ));
        assert!(outside.join("target").is_dir());
    }

    #[test]
    fn shallow_history_is_bounded_and_traversal_components_are_rejected() {
        let mut cursor = PrescanCursor::new();
        for index in 0..MAX_SHALLOW_ROOTS + 10 {
            let root = PathBuf::from(format!("/root-{index:03}"));
            assert!(matches!(
                cursor
                    .poll_shallow(&root, &root.join("repo"), false, || false, inspect)
                    .unwrap(),
                ShallowPoll::Pending
            ));
        }
        assert_eq!(cursor.shallow.len(), MAX_SHALLOW_ROOTS);
        for path in ["/root/../repo", "/root/./repo", "/root/repo/."] {
            assert!(
                cursor
                    .poll_shallow(Path::new("/root"), Path::new(path), false, || true, inspect)
                    .is_err()
            );
        }
    }

    #[test]
    fn an_unreadable_branch_does_not_hide_later_nominees() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let entry = root.join("repo");
        let refused = entry.join("a-branch");
        fs::create_dir_all(&refused).unwrap();
        let expected = entry.join("z-branch/target");
        fs::create_dir_all(&expected).unwrap();
        let mut cursor = PrescanCursor::new();
        let mut replaced = false;
        let result = cursor
            .poll_shallow(
                &root,
                &entry,
                false,
                || true,
                |path, depth| {
                    let disposition = inspect(path, depth);
                    if path == refused && !replaced {
                        // Model an admitted directory becoming unreadable before the
                        // read starts, independently of the runner's UID/permissions.
                        fs::rename(&refused, temp.path().join("old-branch")).unwrap();
                        fs::write(&refused, b"now a file").unwrap();
                        replaced = true;
                    }
                    disposition
                },
            )
            .unwrap();
        let ShallowPoll::Candidate(candidate) = result else {
            panic!("later nominee")
        };
        assert_eq!(candidate.path, expected);
    }
}
