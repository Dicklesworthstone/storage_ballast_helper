//! Scanner v2 filesystem event invalidation.
//!
//! The event layer is advisory: it marks roots/subtrees dirty and the scanner
//! reconciles those paths against current filesystem state before deletion.
//! Overflow, backend loss, and watch-budget gaps force conservative bounded
//! reconciliation rather than approving stale index state.

#![allow(missing_docs)]

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", test))]
use std::collections::VecDeque;
use std::fmt;
#[cfg(any(target_os = "linux", test))]
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::config::{ScannerConfig, ScannerEventSourceMode};
use crate::scanner::index::ScannerCandidateIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventBackendKind {
    Fanotify,
    RecursiveInotify,
    ReconciliationOnly,
}

impl fmt::Display for EventBackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fanotify => f.write_str("fanotify"),
            Self::RecursiveInotify => f.write_str("recursive-inotify"),
            Self::ReconciliationOnly => f.write_str("reconciliation-only"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProbe {
    pub backend: EventBackendKind,
    pub available: bool,
    pub reason: String,
}

impl BackendProbe {
    #[cfg(target_os = "linux")]
    fn available(backend: EventBackendKind, reason: impl Into<String>) -> Self {
        Self {
            backend,
            available: true,
            reason: reason.into(),
        }
    }

    fn unavailable(backend: EventBackendKind, reason: impl Into<String>) -> Self {
        Self {
            backend,
            available: false,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSourceConfig {
    root_paths: Vec<PathBuf>,
    mode: ScannerEventSourceMode,
    watch_budget: usize,
}

impl EventSourceConfig {
    #[must_use]
    pub fn from_scanner_config(root_paths: &[PathBuf], scanner_config: &ScannerConfig) -> Self {
        let mut roots = root_paths.to_vec();
        roots.sort();
        roots.dedup();
        Self {
            root_paths: roots,
            mode: scanner_config.event_source,
            watch_budget: scanner_config.event_watch_budget,
        }
    }

    #[must_use]
    pub fn root_paths(&self) -> &[PathBuf] {
        &self.root_paths
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSourceCapability {
    pub selected_backend: EventBackendKind,
    pub complete: bool,
    pub watched_dirs: usize,
    pub dirty_roots: Vec<PathBuf>,
    pub reason: String,
    pub fanotify: BackendProbe,
    pub recursive_inotify: BackendProbe,
}

impl EventSourceCapability {
    fn from_plan(plan: &EventSourcePlan) -> Self {
        Self {
            selected_backend: plan.backend,
            complete: plan.complete,
            watched_dirs: plan.watched_dirs.len(),
            dirty_roots: plan.dirty_roots.iter().cloned().collect(),
            reason: plan.reason.clone(),
            fanotify: fanotify_probe(),
            recursive_inotify: recursive_inotify_probe(plan.backend),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSourcePlan {
    pub backend: EventBackendKind,
    pub complete: bool,
    pub watched_dirs: Vec<PathBuf>,
    pub dirty_roots: BTreeSet<PathBuf>,
    pub reason: String,
}

impl EventSourcePlan {
    #[must_use]
    pub fn for_config(config: &EventSourceConfig) -> Self {
        if config.mode == ScannerEventSourceMode::ReconciliationOnly {
            return Self::reconciliation_only(
                &config.root_paths,
                "scanner.event_source forces reconciliation-only",
            );
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::reconciliation_only(
                &config.root_paths,
                "safe kernel scanner event backend is unavailable on this platform",
            )
        }

        #[cfg(target_os = "linux")]
        {
            if config.watch_budget == 0 {
                return Self::reconciliation_only(
                    &config.root_paths,
                    "scanner.event_watch_budget is 0",
                );
            }
            Self::recursive_inotify(&config.root_paths, config.watch_budget)
        }
    }

    fn reconciliation_only(root_paths: &[PathBuf], reason: impl Into<String>) -> Self {
        Self {
            backend: EventBackendKind::ReconciliationOnly,
            complete: false,
            watched_dirs: Vec::new(),
            dirty_roots: root_paths.iter().cloned().collect(),
            reason: reason.into(),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn recursive_inotify(root_paths: &[PathBuf], watch_budget: usize) -> Self {
        let mut watched_dirs = Vec::new();
        let mut dirty_roots = BTreeSet::new();
        let mut complete = true;
        let mut reason = "recursive inotify plan covers all current directories".to_string();

        'roots: for root in root_paths {
            if watched_dirs.len() >= watch_budget {
                complete = false;
                dirty_roots.insert(root.clone());
                reason = "recursive inotify watch budget exhausted".to_string();
                continue;
            }

            let metadata = match fs::symlink_metadata(root) {
                Ok(metadata) => metadata,
                Err(err) => {
                    complete = false;
                    dirty_roots.insert(root.clone());
                    reason = format!("root metadata unavailable for {}: {err}", root.display());
                    continue;
                }
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                complete = false;
                dirty_roots.insert(root.clone());
                reason = format!("root is not a plain directory: {}", root.display());
                continue;
            }

            watched_dirs.push(root.clone());
            let mut queue = VecDeque::from([root.clone()]);
            while let Some(dir) = queue.pop_front() {
                let entries = match sorted_child_paths(&dir) {
                    Ok(entries) => entries,
                    Err(err) => {
                        complete = false;
                        dirty_roots.insert(root.clone());
                        reason = format!("directory unreadable for watch planning: {err}");
                        continue;
                    }
                };

                for child in entries {
                    let Ok(metadata) = fs::symlink_metadata(&child) else {
                        complete = false;
                        dirty_roots.insert(root.clone());
                        reason = format!("child metadata unavailable under {}", root.display());
                        continue;
                    };
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        continue;
                    }
                    if watched_dirs.len() >= watch_budget {
                        complete = false;
                        dirty_roots.insert(root.clone());
                        reason = "recursive inotify watch budget exhausted".to_string();
                        continue 'roots;
                    }
                    watched_dirs.push(child.clone());
                    queue.push_back(child);
                }
            }
        }

        Self {
            backend: if watched_dirs.is_empty() {
                EventBackendKind::ReconciliationOnly
            } else {
                EventBackendKind::RecursiveInotify
            },
            complete,
            watched_dirs,
            dirty_roots,
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsEventKind {
    Create,
    Modify,
    Remove,
    Rename,
    Overflow,
    BackendRestart,
    PermissionLost,
    WatchBudgetExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEvent {
    pub kind: FsEventKind,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventInvalidation {
    dirty_roots: BTreeSet<PathBuf>,
    dirty_paths: BTreeSet<PathBuf>,
    generation_bump: bool,
    reasons: BTreeSet<String>,
}

impl EventInvalidation {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            dirty_roots: BTreeSet::new(),
            dirty_paths: BTreeSet::new(),
            generation_bump: false,
            reasons: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn dirty_roots(&self) -> &BTreeSet<PathBuf> {
        &self.dirty_roots
    }

    #[must_use]
    pub fn dirty_paths(&self) -> &BTreeSet<PathBuf> {
        &self.dirty_paths
    }

    #[must_use]
    pub fn requires_reconciliation(&self) -> bool {
        !self.dirty_roots.is_empty()
    }

    #[must_use]
    pub fn requires_index_generation_bump(&self) -> bool {
        self.generation_bump
    }

    #[must_use]
    pub fn reason_summary(&self) -> String {
        self.reasons.iter().cloned().collect::<Vec<_>>().join("; ")
    }

    pub fn apply_to_index(&self, index: &mut ScannerCandidateIndex) {
        if self.requires_index_generation_bump() {
            index.mark_event_overflow();
        }
    }

    fn mark_dirty_root(&mut self, root: PathBuf, reason: impl Into<String>) {
        self.dirty_roots.insert(root);
        self.reasons.insert(reason.into());
    }

    fn mark_dirty_path(&mut self, roots: &[PathBuf], path: &Path, reason: impl Into<String>) {
        let reason = reason.into();
        self.dirty_paths.insert(path.to_path_buf());
        if let Some(root) = root_for_path(roots, path) {
            self.mark_dirty_root(root, reason);
        } else {
            self.mark_all_roots(roots, reason, true);
        }
    }

    fn mark_all_roots(
        &mut self,
        roots: &[PathBuf],
        reason: impl Into<String>,
        generation_bump: bool,
    ) {
        self.dirty_roots.extend(roots.iter().cloned());
        self.reasons.insert(reason.into());
        self.generation_bump |= generation_bump;
    }

    #[cfg(target_os = "linux")]
    fn merge(&mut self, other: Self) {
        self.dirty_roots.extend(other.dirty_roots);
        self.dirty_paths.extend(other.dirty_paths);
        self.generation_bump |= other.generation_bump;
        self.reasons.extend(other.reasons);
    }
}

#[derive(Debug, Clone)]
pub struct DirtyRootTracker {
    roots: Vec<PathBuf>,
}

impl DirtyRootTracker {
    #[must_use]
    pub fn new(root_paths: &[PathBuf]) -> Self {
        let mut roots = root_paths.to_vec();
        roots.sort();
        roots.dedup();
        Self { roots }
    }

    #[must_use]
    pub fn apply_event(&self, event: FsEvent) -> EventInvalidation {
        let mut invalidation = EventInvalidation::empty();
        match event.kind {
            FsEventKind::Overflow
            | FsEventKind::BackendRestart
            | FsEventKind::PermissionLost
            | FsEventKind::WatchBudgetExceeded => {
                invalidation.mark_all_roots(&self.roots, format!("{:?}", event.kind), true);
            }
            FsEventKind::Create
            | FsEventKind::Modify
            | FsEventKind::Remove
            | FsEventKind::Rename => {
                if let Some(path) = event.path {
                    invalidation.mark_dirty_path(&self.roots, &path, format!("{:?}", event.kind));
                } else {
                    invalidation.mark_all_roots(&self.roots, format!("{:?}", event.kind), true);
                }
            }
        }
        invalidation
    }
}

#[derive(Debug)]
pub struct ScannerEventSource {
    config: EventSourceConfig,
    capability: EventSourceCapability,
    #[cfg(target_os = "linux")]
    tracker: DirtyRootTracker,
    backend: EventSourceBackend,
    pending: EventInvalidation,
}

impl ScannerEventSource {
    #[must_use]
    pub fn start(config: EventSourceConfig) -> Self {
        #[cfg(target_os = "linux")]
        let tracker = DirtyRootTracker::new(config.root_paths());
        let plan = EventSourcePlan::for_config(&config);
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut capability = EventSourceCapability::from_plan(&plan);
        let mut pending = EventInvalidation::empty();
        if !plan.complete {
            pending.mark_all_roots(config.root_paths(), plan.reason.clone(), true);
        }

        let backend = match plan.backend {
            EventBackendKind::RecursiveInotify => {
                #[cfg(target_os = "linux")]
                {
                    match LinuxInotifyBackend::start(&plan.watched_dirs, config.watch_budget) {
                        Ok(backend) => EventSourceBackend::RecursiveInotify(backend),
                        Err(err) => {
                            capability.selected_backend = EventBackendKind::ReconciliationOnly;
                            capability.complete = false;
                            capability.reason = format!("recursive inotify unavailable: {err}");
                            pending.mark_all_roots(
                                config.root_paths(),
                                capability.reason.clone(),
                                true,
                            );
                            EventSourceBackend::ReconciliationOnly
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    EventSourceBackend::ReconciliationOnly
                }
            }
            EventBackendKind::Fanotify | EventBackendKind::ReconciliationOnly => {
                EventSourceBackend::ReconciliationOnly
            }
        };

        Self {
            config,
            capability,
            #[cfg(target_os = "linux")]
            tracker,
            backend,
            pending,
        }
    }

    #[must_use]
    pub fn matches_config(&self, config: &EventSourceConfig) -> bool {
        &self.config == config
    }

    #[must_use]
    pub fn capability(&self) -> &EventSourceCapability {
        &self.capability
    }

    pub fn drain(&mut self) -> EventInvalidation {
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut invalidation = std::mem::replace(&mut self.pending, EventInvalidation::empty());
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            EventSourceBackend::RecursiveInotify(backend) => {
                invalidation.merge(backend.drain(&self.tracker, &self.config));
            }
            EventSourceBackend::ReconciliationOnly => {}
        }
        invalidation
    }
}

#[derive(Debug)]
enum EventSourceBackend {
    #[cfg(target_os = "linux")]
    RecursiveInotify(LinuxInotifyBackend),
    ReconciliationOnly,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxInotifyBackend {
    inotify: inotify::Inotify,
    watch_paths: BTreeMap<inotify::WatchDescriptor, PathBuf>,
    buffer: Vec<u8>,
    max_watches: usize,
}

#[cfg(target_os = "linux")]
impl LinuxInotifyBackend {
    fn start(paths: &[PathBuf], max_watches: usize) -> std::io::Result<Self> {
        let inotify = inotify::Inotify::init()?;
        let mut backend = Self {
            inotify,
            watch_paths: BTreeMap::new(),
            buffer: vec![0; 64 * 1024],
            max_watches,
        };
        for path in paths {
            backend.add_watch(path)?;
        }
        Ok(backend)
    }

    fn drain(
        &mut self,
        tracker: &DirtyRootTracker,
        config: &EventSourceConfig,
    ) -> EventInvalidation {
        use std::io::ErrorKind;

        let mut invalidation = EventInvalidation::empty();
        loop {
            let events = match self.read_available_events() {
                Ok(events) => events,
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => {
                    invalidation.mark_all_roots(
                        config.root_paths(),
                        format!("recursive inotify read failed: {err}"),
                        true,
                    );
                    break;
                }
            };
            if events.is_empty() {
                break;
            }
            for event in events {
                invalidation.merge(self.handle_event(tracker, config, &event));
            }
        }
        invalidation
    }

    fn read_available_events(&mut self) -> std::io::Result<Vec<LinuxInotifyEvent>> {
        let events = self.inotify.read_events(&mut self.buffer)?;
        Ok(events
            .map(|event| LinuxInotifyEvent {
                watch: event.wd,
                mask: event.mask,
                name: event.name.map(PathBuf::from),
            })
            .collect())
    }

    fn handle_event(
        &mut self,
        tracker: &DirtyRootTracker,
        config: &EventSourceConfig,
        event: &LinuxInotifyEvent,
    ) -> EventInvalidation {
        use inotify::EventMask;

        if event.mask.contains(EventMask::Q_OVERFLOW) {
            return tracker.apply_event(FsEvent {
                kind: FsEventKind::Overflow,
                path: None,
            });
        }

        let path = self.path_for_event(event);
        let mut invalidation = if event.mask.intersects(
            EventMask::IGNORED | EventMask::UNMOUNT | EventMask::DELETE_SELF | EventMask::MOVE_SELF,
        ) {
            tracker.apply_event(FsEvent {
                kind: FsEventKind::PermissionLost,
                path: path.clone(),
            })
        } else {
            tracker.apply_event(FsEvent {
                kind: event_kind_from_inotify_mask(event.mask),
                path: path.clone(),
            })
        };

        if event.mask.contains(EventMask::ISDIR)
            && event
                .mask
                .intersects(EventMask::CREATE | EventMask::MOVED_TO)
            && let Some(path) = path
        {
            if self.watch_paths.len() >= self.max_watches {
                invalidation.merge(tracker.apply_event(FsEvent {
                    kind: FsEventKind::WatchBudgetExceeded,
                    path: Some(path),
                }));
            } else if let Err(err) = self.add_watch(&path) {
                invalidation.mark_dirty_path(
                    config.root_paths(),
                    &path,
                    format!("recursive inotify add-watch failed: {err}"),
                );
                invalidation.generation_bump = true;
            }
        }

        invalidation
    }

    fn path_for_event(&self, event: &LinuxInotifyEvent) -> Option<PathBuf> {
        let base = self.watch_paths.get(&event.watch)?;
        Some(
            event
                .name
                .as_ref()
                .map_or_else(|| base.clone(), |name| base.join(name)),
        )
    }

    fn add_watch(&mut self, path: &Path) -> std::io::Result<()> {
        let watch = self.inotify.watches().add(path, inotify_watch_mask())?;
        self.watch_paths.insert(watch, path.to_path_buf());
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxInotifyEvent {
    watch: inotify::WatchDescriptor,
    mask: inotify::EventMask,
    name: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn inotify_watch_mask() -> inotify::WatchMask {
    use inotify::WatchMask;
    WatchMask::ATTRIB
        | WatchMask::CLOSE_WRITE
        | WatchMask::CREATE
        | WatchMask::DELETE
        | WatchMask::DELETE_SELF
        | WatchMask::DONT_FOLLOW
        | WatchMask::EXCL_UNLINK
        | WatchMask::MODIFY
        | WatchMask::MOVE
        | WatchMask::MOVE_SELF
        | WatchMask::ONLYDIR
}

#[cfg(target_os = "linux")]
fn event_kind_from_inotify_mask(mask: inotify::EventMask) -> FsEventKind {
    use inotify::EventMask;
    if mask.intersects(EventMask::DELETE | EventMask::DELETE_SELF) {
        FsEventKind::Remove
    } else if mask.intersects(EventMask::MOVED_FROM | EventMask::MOVED_TO | EventMask::MOVE_SELF) {
        FsEventKind::Rename
    } else if mask.contains(EventMask::CREATE) {
        FsEventKind::Create
    } else {
        FsEventKind::Modify
    }
}

#[cfg(any(target_os = "linux", test))]
fn sorted_child_paths(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(path)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn root_for_path(roots: &[PathBuf], path: &Path) -> Option<PathBuf> {
    roots
        .iter()
        .find(|root| path == root.as_path() || path.starts_with(root))
        .cloned()
}

fn fanotify_probe() -> BackendProbe {
    BackendProbe::unavailable(
        EventBackendKind::Fanotify,
        "deferred: no safe fanotify backend is wired into the unsafe-forbidden crate",
    )
}

fn recursive_inotify_probe(selected_backend: EventBackendKind) -> BackendProbe {
    #[cfg(target_os = "linux")]
    {
        if selected_backend == EventBackendKind::RecursiveInotify {
            BackendProbe::available(
                EventBackendKind::RecursiveInotify,
                "safe inotify crate selected with recursive watch planning",
            )
        } else {
            BackendProbe::unavailable(
                EventBackendKind::RecursiveInotify,
                "recursive inotify was not selected",
            )
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = selected_backend;
        BackendProbe::unavailable(EventBackendKind::RecursiveInotify, "inotify is Linux-only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn event_config(root_paths: &[PathBuf], watch_budget: usize) -> EventSourceConfig {
        let scanner_config = ScannerConfig {
            event_watch_budget: watch_budget,
            ..Default::default()
        };
        EventSourceConfig::from_scanner_config(root_paths, &scanner_config)
    }

    #[test]
    fn recursive_plan_covers_nested_directories_within_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("a")).unwrap();
        fs::create_dir(root.join("a").join("b")).unwrap();

        let plan = EventSourcePlan::recursive_inotify(std::slice::from_ref(&root), 8);

        assert!(plan.complete);
        assert_eq!(plan.backend, EventBackendKind::RecursiveInotify);
        assert!(plan.watched_dirs.contains(&root));
        assert!(plan.watched_dirs.contains(&root.join("a")));
        assert!(plan.watched_dirs.contains(&root.join("a").join("b")));
        assert!(plan.dirty_roots.is_empty());
    }

    #[test]
    fn watch_budget_exhaustion_marks_root_dirty() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("a")).unwrap();
        fs::create_dir(root.join("a").join("b")).unwrap();

        let plan = EventSourcePlan::recursive_inotify(std::slice::from_ref(&root), 1);

        assert!(!plan.complete);
        assert_eq!(plan.backend, EventBackendKind::RecursiveInotify);
        assert_eq!(plan.watched_dirs, vec![root.clone()]);
        assert!(plan.dirty_roots.contains(&root));
    }

    #[test]
    fn forced_reconciliation_marks_roots_dirty_and_bumps_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let scanner_config = ScannerConfig {
            event_source: ScannerEventSourceMode::ReconciliationOnly,
            ..Default::default()
        };
        let config =
            EventSourceConfig::from_scanner_config(std::slice::from_ref(&root), &scanner_config);

        let mut source = ScannerEventSource::start(config);
        let invalidation = source.drain();

        assert_eq!(
            source.capability().selected_backend,
            EventBackendKind::ReconciliationOnly
        );
        assert!(invalidation.dirty_roots().contains(&root));
        assert!(invalidation.requires_index_generation_bump());
    }

    #[test]
    fn overflow_forces_all_roots_dirty_and_bumps_generation() {
        let roots = vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")];
        let tracker = DirtyRootTracker::new(&roots);

        let invalidation = tracker.apply_event(FsEvent {
            kind: FsEventKind::Overflow,
            path: None,
        });

        assert_eq!(invalidation.dirty_roots().len(), 2);
        assert!(invalidation.requires_index_generation_bump());
    }

    #[derive(Debug, serde::Serialize)]
    struct EventFallbackValidationArtifact {
        schema_version: u32,
        scenario: &'static str,
        dirty_roots: Vec<String>,
        generation_before: u64,
        generation_after: u64,
        generation_bumped: bool,
        reason_summary: String,
    }

    #[test]
    fn event_overflow_validation_artifact_records_reconciliation_fallback() {
        let roots = vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")];
        let tracker = DirtyRootTracker::new(&roots);
        let mut index = ScannerCandidateIndex::new(crate::scanner::index::ScannerIndexContext {
            root_fingerprint: "root".to_string(),
            config_fingerprint: "config".to_string(),
        });
        let generation_before = index.event_generation();

        let invalidation = tracker.apply_event(FsEvent {
            kind: FsEventKind::Overflow,
            path: None,
        });
        invalidation.apply_to_index(&mut index);

        let mut dirty_roots = invalidation
            .dirty_roots()
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        dirty_roots.sort();
        let artifact = EventFallbackValidationArtifact {
            schema_version: 1,
            scenario: "event-overflow-reconciliation",
            dirty_roots,
            generation_before,
            generation_after: index.event_generation(),
            generation_bumped: invalidation.requires_index_generation_bump(),
            reason_summary: invalidation.reason_summary(),
        };
        let payload = serde_json::to_value(&artifact).unwrap();

        assert_eq!(payload["schema_version"].as_u64(), Some(1));
        assert_eq!(
            payload["scenario"].as_str(),
            Some("event-overflow-reconciliation")
        );
        assert_eq!(artifact.dirty_roots.len(), 2);
        assert_eq!(artifact.generation_before, 0);
        assert_eq!(artifact.generation_after, 1);
        assert!(artifact.generation_bumped);
        assert!(artifact.reason_summary.contains("Overflow"));
        eprintln!(
            "scanner_v2_event_fallback_validation_artifact={}",
            serde_json::to_string(&artifact).unwrap()
        );
    }

    #[test]
    fn path_event_marks_owning_root_dirty_without_generation_bump() {
        let root = PathBuf::from("/tmp/root");
        let tracker = DirtyRootTracker::new(std::slice::from_ref(&root));

        let invalidation = tracker.apply_event(FsEvent {
            kind: FsEventKind::Modify,
            path: Some(root.join("target").join("debug")),
        });

        assert!(invalidation.dirty_roots().contains(&root));
        assert!(!invalidation.requires_index_generation_bump());
    }

    #[test]
    fn invalidation_generation_bump_applies_to_index() {
        let mut index = ScannerCandidateIndex::new(crate::scanner::index::ScannerIndexContext {
            root_fingerprint: "root".to_string(),
            config_fingerprint: "config".to_string(),
        });
        let tracker = DirtyRootTracker::new(&[PathBuf::from("/tmp/root")]);
        let invalidation = tracker.apply_event(FsEvent {
            kind: FsEventKind::BackendRestart,
            path: None,
        });

        invalidation.apply_to_index(&mut index);

        assert_eq!(index.event_generation(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_recursive_inotify_reports_nested_changes_when_enabled() {
        use std::thread;
        use std::time::{Duration, Instant};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let nested = root.join("nested");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&nested).unwrap();
        let mut source = ScannerEventSource::start(event_config(std::slice::from_ref(&root), 16));
        if source.capability().selected_backend != EventBackendKind::RecursiveInotify {
            return;
        }
        let _ = source.drain();

        let changed = nested.join("object.o");
        fs::write(&changed, b"object").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let invalidation = source.drain();
            if invalidation.dirty_paths().contains(&changed) {
                assert!(invalidation.dirty_roots().contains(&root));
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("expected nested inotify event for {}", changed.display());
    }

    /// bd-rc-master-ajg1.8.5: the capability report must say what the event
    /// source really is on this platform. Linux plans recursive inotify and
    /// reports fanotify as deferred; every other platform reconciles only,
    /// with every root dirty, and says why.
    #[test]
    fn capability_report_is_honest_about_the_platform() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        let scanner_config = ScannerConfig {
            event_watch_budget: 16,
            ..Default::default()
        };
        let config =
            EventSourceConfig::from_scanner_config(std::slice::from_ref(&root), &scanner_config);
        let plan = EventSourcePlan::for_config(&config);
        let capability = EventSourceCapability::from_plan(&plan);

        assert!(!capability.fanotify.available, "{capability:?}");
        assert!(
            capability.fanotify.reason.contains("deferred"),
            "{}",
            capability.fanotify.reason
        );
        if cfg!(target_os = "linux") {
            assert_eq!(
                capability.selected_backend,
                EventBackendKind::RecursiveInotify
            );
            assert!(capability.recursive_inotify.available, "{capability:?}");
            assert!(capability.complete, "{capability:?}");
        } else {
            assert_eq!(
                capability.selected_backend,
                EventBackendKind::ReconciliationOnly
            );
            assert!(!capability.recursive_inotify.available, "{capability:?}");
            assert_eq!(capability.dirty_roots, vec![root]);
            assert!(
                capability.reason.contains("unavailable on this platform"),
                "{}",
                capability.reason
            );
        }
    }
}
