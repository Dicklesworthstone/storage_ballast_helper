//! macOS recursive events, canonical-path translation, and retry policy.
//!
//! No unsafe code lives here. The native stream owns its callback resources
//! in sbh_mach; this layer only invalidates the existing scanner view.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use super::EventSourceBackend;
use super::{
    EventBackendKind, EventInvalidation, EventRateTracker, EventSourceCapability, EventSourceConfig,
    EventSourcePlan, OverflowBackoff, OverflowDecision, ScannerEventSourceMode,
};
#[cfg(target_os = "macos")]
use sbh_mach::fsevents::{Fsevents, MAX_ROOTS};
#[cfg(not(target_os = "macos"))]
const MAX_ROOTS: usize = 1024;

const RETRY_INTERVAL: Duration = Duration::from_secs(30);
const MAX_MAPPED_PATHS: usize = 2048;
const MAX_MAPPED_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RootAlias {
    configured: PathBuf,
    canonical: PathBuf,
}

#[derive(Debug)]
pub(super) struct RootPlan {
    pub(super) summary: EventSourcePlan,
    aliases: Vec<RootAlias>,
}

fn inspect_root(root: &Path) -> io::Result<PathBuf> {
    if !root.is_absolute() || root.components().any(|part| part == Component::ParentDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root must be absolute without ..",
        ));
    }
    // Ancestor aliases such as /tmp -> /private/tmp are supported; a leaf
    // symlink remains subject to the scanner's plain-directory rule.
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root is not a plain directory",
        ));
    }
    let canonical = fs::canonicalize(root)?;
    if canonical.to_str().is_none() || canonical.as_os_str().as_encoded_bytes().len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported FSEvents root path",
        ));
    }
    // Prove we can enumerate this root without enumerating its descendants.
    // Later access changes still require ordinary scan/preflight checks.
    let mut entries = fs::read_dir(&canonical)?;
    if let Some(entry) = entries.next() {
        entry?;
    }
    Ok(canonical)
}

pub(super) fn root_plan(config: &EventSourceConfig) -> RootPlan {
    resolve_roots(config, inspect_root)
}

fn resolve_roots(
    config: &EventSourceConfig,
    mut inspect: impl FnMut(&Path) -> io::Result<PathBuf>,
) -> RootPlan {
    let budget = config.watch_budget.min(MAX_ROOTS);
    if config.mode == ScannerEventSourceMode::ReconciliationOnly || budget == 0 {
        return RootPlan {
            summary: EventSourcePlan::reconciliation_only(
                config.root_paths(),
                "FSEvents disabled by event-source policy or zero watch budget",
            ),
            aliases: Vec::new(),
        };
    }
    let mut watched = BTreeSet::new();
    let mut dirty: BTreeSet<PathBuf> = config.root_paths().iter().cloned().collect();
    let mut aliases = Vec::new();
    let mut first_error = None;
    // Bound startup/retry metadata work as well as native stream resources.
    // Uninspected roots remain explicitly outside the event coverage.
    for configured in config.root_paths().iter().take(MAX_ROOTS) {
        match inspect(configured) {
            Ok(canonical) => {
                if !watched.contains(&canonical) && watched.len() >= budget {
                    continue;
                }
                watched.insert(canonical.clone());
                dirty.remove(configured);
                aliases.push(RootAlias {
                    configured: configured.clone(),
                    canonical,
                });
            }
            Err(err) => {
                first_error.get_or_insert_with(|| format!("{}: {err}", configured.display()));
            }
        }
    }
    let complete = dirty.is_empty() && !watched.is_empty();
    let reason = if complete {
        "FSEvents recursively covers all configured roots; periodic reconciliation remains required".to_string()
    } else {
        format!(
            "FSEvents coverage incomplete: {} roots require reconciliation{}",
            dirty.len(),
            first_error.map_or_else(String::new, |err| format!("; {err}")),
        )
    };
    RootPlan {
        summary: EventSourcePlan {
            backend: if watched.is_empty() {
                EventBackendKind::ReconciliationOnly
            } else {
                EventBackendKind::Fsevents
            },
            complete,
            watched_dirs: watched.into_iter().collect(),
            frontier_dirs: dirty.len(),
            dirty_roots: dirty,
            reason,
        },
        aliases,
    }
}

pub(super) fn retry_due(
    config: &EventSourceConfig,
    capability: &EventSourceCapability,
    planned_at: Instant,
    now: Instant,
) -> bool {
    config.mode != ScannerEventSourceMode::ReconciliationOnly
        && config.watch_budget > 0
        && !capability.complete
        && now.saturating_duration_since(planned_at) >= RETRY_INTERVAL
}

fn record_loss(roots: &[PathBuf], backoff: &mut OverflowBackoff, now: Instant) -> EventInvalidation {
    let mut invalidation = EventInvalidation::empty();
    // Pace the expensive rescan, never the revocation of stale candidates.
    invalidation.generation_bump = true;
    match backoff.record(now) {
        OverflowDecision::Reconcile { .. } => {
            invalidation.mark_all_roots(roots, "FSEvents overflow: reconcile all roots", true);
        }
        OverflowDecision::Coalesced { .. } => {
            invalidation
                .reasons
                .insert("FSEvents overflow: rescan deferred, generation revoked".to_string());
        }
    }
    invalidation
}

fn translate_paths(
    aliases: &[RootAlias],
    roots: &[PathBuf],
    paths: &[PathBuf],
    rates: &mut EventRateTracker,
    backoff: &mut OverflowBackoff,
    now: Instant,
) -> EventInvalidation {
    let mut invalidation = EventInvalidation::empty();
    let mut bytes = 0usize;
    let mut touched = BTreeSet::new();
    for path in paths {
        if path.components().any(|part| part == Component::ParentDir) {
            return record_loss(roots, backoff, now);
        }
        let mut mapped = false;
        for alias in aliases {
            let Ok(relative) = path.strip_prefix(&alias.canonical) else {
                continue;
            };
            mapped = true;
            let configured_path = alias.configured.join(relative);
            if !invalidation.dirty_paths.contains(&configured_path) {
                let length = configured_path.as_os_str().as_encoded_bytes().len();
                if invalidation.dirty_paths.len() >= MAX_MAPPED_PATHS
                    || length > MAX_MAPPED_BYTES.saturating_sub(bytes)
                {
                    return record_loss(roots, backoff, now);
                }
                bytes += length;
                invalidation.mark_dirty_path(roots, &configured_path, "FSEvents path change");
            }
            touched.insert(alias.configured.clone());
        }
        if !mapped {
            // RootChanged can use a parent path; an untranslatable ordinary
            // path must not silently disappear or escape the configured scope.
            return record_loss(roots, backoff, now);
        }
    }
    // Rates are per configured root, not per ever-changing event filename.
    for root in touched {
        rates.record(&root, now);
    }
    invalidation
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(super) struct MacOsFseventsBackend {
    stream: Fsevents,
    aliases: Vec<RootAlias>,
    identities: Vec<(u64, u64)>,
    checked_at: Instant,
    restart_pending: bool,
}

#[cfg(target_os = "macos")]
fn root_identity(alias: &RootAlias) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    if inspect_root(&alias.configured)? != alias.canonical {
        return Err(io::Error::other(
            "configured root resolves to a different directory",
        ));
    }
    let metadata = fs::metadata(&alias.configured)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(target_os = "macos")]
impl MacOsFseventsBackend {
    fn start(plan: &RootPlan, now: Instant) -> io::Result<Self> {
        let identities: Vec<_> = plan
            .aliases
            .iter()
            .map(root_identity)
            .collect::<io::Result<_>>()?;
        let stream = Fsevents::start(&plan.summary.watched_dirs)?;
        let backend = Self {
            stream,
            aliases: plan.aliases.clone(),
            identities,
            checked_at: now,
            restart_pending: false,
        };
        if !backend.roots_unchanged() {
            return Err(io::Error::other("root changed while starting FSEvents"));
        }
        Ok(backend)
    }

    fn roots_unchanged(&self) -> bool {
        self.aliases
            .iter()
            .zip(&self.identities)
            .all(|(alias, identity)| root_identity(alias).is_ok_and(|current| current == *identity))
    }

    pub(super) fn drain(
        &mut self,
        config: &EventSourceConfig,
        rates: &mut EventRateTracker,
        backoff: &mut OverflowBackoff,
        capability: &mut EventSourceCapability,
        now: Instant,
    ) -> EventInvalidation {
        let batch = self.stream.drain();
        if self.restart_pending {
            // Events from a stream whose roots changed are not fresh coverage.
            return EventInvalidation::empty();
        }
        let mut roots_changed = batch.restart_required;
        if now.saturating_duration_since(self.checked_at) >= RETRY_INTERVAL {
            self.checked_at = now;
            roots_changed |= !self.roots_unchanged();
        }
        if roots_changed {
            self.restart_pending = true;
            capability.complete = false;
            capability.dirty_roots = config.root_paths().to_vec();
            capability.reason =
                "FSEvents root identity or stream coverage changed; restart pending".to_string();
            let mut invalidation = EventInvalidation::empty();
            invalidation.mark_all_roots(config.root_paths(), capability.reason.clone(), true);
            return invalidation;
        }
        if batch.must_rescan {
            return record_loss(config.root_paths(), backoff, now);
        }
        translate_paths(
            &self.aliases,
            config.root_paths(),
            &batch.paths,
            rates,
            backoff,
            now,
        )
    }
}

#[cfg(target_os = "macos")]
fn install_plan(
    config: &EventSourceConfig,
    plan: RootPlan,
    capability: &mut EventSourceCapability,
    pending: &mut EventInvalidation,
    now: Instant,
) -> EventSourceBackend {
    *capability = EventSourceCapability::from_plan(&plan.summary);
    let backend = if plan.summary.backend == EventBackendKind::Fsevents {
        match MacOsFseventsBackend::start(&plan, now) {
            Ok(backend) => EventSourceBackend::Fsevents(backend),
            Err(err) => {
                capability.selected_backend = EventBackendKind::ReconciliationOnly;
                capability.complete = false;
                capability.watched_dirs = 0;
                capability.frontier_dirs = config.root_paths().len();
                capability.dirty_roots = config.root_paths().to_vec();
                capability.reason = format!("FSEvents startup failed; reconciliation fallback: {err}");
                EventSourceBackend::ReconciliationOnly
            }
        }
    } else {
        EventSourceBackend::ReconciliationOnly
    };
    // SinceNow supplies future events, not a scan of the already existing
    // tree. This also closes the event gap on every successful replacement.
    pending.mark_all_roots(
        config.root_paths(),
        format!("FSEvents startup/replan: {}", capability.reason),
        true,
    );
    backend
}

#[cfg(target_os = "macos")]
pub(super) fn start_backend(
    config: &EventSourceConfig,
    capability: &mut EventSourceCapability,
    pending: &mut EventInvalidation,
    now: Instant,
) -> EventSourceBackend {
    install_plan(config, root_plan(config), capability, pending, now)
}

#[cfg(target_os = "macos")]
pub(super) fn refresh_backend(
    config: &EventSourceConfig,
    backend: &mut EventSourceBackend,
    capability: &mut EventSourceCapability,
    pending: &mut EventInvalidation,
    now: Instant,
) {
    let plan = root_plan(config);
    if matches!(backend, EventSourceBackend::ReconciliationOnly)
        && plan.summary.backend == EventBackendKind::ReconciliationOnly
    {
        // Still no usable root: report the retry's coverage, but do not
        // trigger another full scan of the same unavailable filesystem.
        *capability = EventSourceCapability::from_plan(&plan.summary);
        return;
    }
    if let EventSourceBackend::Fsevents(current) = backend
        && !current.restart_pending
        && current.aliases == plan.aliases
        && current.roots_unchanged()
    {
        // A permanently absent or budget-excluded root must not cause a
        // whole-tree scan and native stream churn on every retry interval.
        *capability = EventSourceCapability::from_plan(&plan.summary);
        return;
    }
    *backend = install_plan(config, plan, capability, pending, now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ScannerConfig;

    fn config(roots: &[&str], budget: usize) -> EventSourceConfig {
        EventSourceConfig::from_scanner_config(
            &roots.iter().map(PathBuf::from).collect::<Vec<_>>(),
            &ScannerConfig {
                event_watch_budget: budget,
                ..Default::default()
            },
        )
    }

    #[test]
    fn budget_and_unreadable_roots_preserve_healthy_coverage() {
        let cfg = config(&["/a", "/b", "/c"], 1);
        let plan = resolve_roots(&cfg, |path| {
            if path == Path::new("/a") {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
            } else {
                Ok(path.to_path_buf())
            }
        });
        assert_eq!(plan.summary.backend, EventBackendKind::Fsevents);
        assert_eq!(plan.summary.watched_dirs, vec![PathBuf::from("/b")]);
        assert_eq!(
            plan.summary.dirty_roots,
            BTreeSet::from([PathBuf::from("/a"), PathBuf::from("/c")])
        );
        assert!(!plan.summary.complete);
        assert!(plan.summary.reason.contains("denied"));
    }

    #[test]
    fn canonical_aliases_share_one_recursive_watch_and_translate_both_ways() {
        let cfg = config(&["/tmp/work", "/private/tmp/work"], 1);
        let plan = resolve_roots(&cfg, |_| Ok(PathBuf::from("/private/tmp/work")));
        assert!(plan.summary.complete);
        assert_eq!(plan.summary.watched_dirs.len(), 1);
        let mut rates = EventRateTracker::default();
        let mut backoff = OverflowBackoff::default();
        let mut changed = translate_paths(
            &plan.aliases,
            cfg.root_paths(),
            &[PathBuf::from("/private/tmp/work/project/src/a.rs")],
            &mut rates,
            &mut backoff,
            Instant::now(),
        );
        assert_eq!(changed.dirty_paths.len(), 2);
        assert!(
            changed
                .dirty_paths
                .contains(Path::new("/tmp/work/project/src/a.rs"))
        );
        changed.resolve_scan_roots(cfg.root_paths());
        assert!(changed.dirty_roots.contains(Path::new("/tmp/work/project")));
        assert!(
            changed
                .dirty_roots
                .contains(Path::new("/private/tmp/work/project"))
        );
        assert!(!changed.requires_index_generation_bump());
        assert_eq!(rates.tracked_dirs(), 2);
    }

    #[test]
    fn translation_is_component_aware_and_unknown_paths_revoke_the_index() {
        let cfg = config(&["/root"], 1);
        let plan = resolve_roots(&cfg, |path| Ok(path.to_path_buf()));
        for path in ["/root-other/a", "/outside/a", "/root/../outside/a"] {
            let result = translate_paths(
                &plan.aliases,
                cfg.root_paths(),
                &[PathBuf::from(path)],
                &mut EventRateTracker::default(),
                &mut OverflowBackoff::default(),
                Instant::now(),
            );
            assert!(result.requires_index_generation_bump(), "{path}");
            assert!(result.dirty_roots.contains(Path::new("/root")));
            assert!(result.dirty_paths.is_empty());
        }
    }

    #[test]
    fn mapped_path_growth_fails_closed_instead_of_amplifying_aliases() {
        let cfg = config(&["/root"], 1);
        let plan = resolve_roots(&cfg, |path| Ok(path.to_path_buf()));
        let paths = (0..=MAX_MAPPED_PATHS)
            .map(|i| PathBuf::from(format!("/root/file{i}")))
            .collect::<Vec<_>>();
        let result = translate_paths(
            &plan.aliases,
            cfg.root_paths(),
            &paths,
            &mut EventRateTracker::default(),
            &mut OverflowBackoff::default(),
            Instant::now(),
        );
        assert!(result.dirty_paths.is_empty());
        assert!(result.requires_index_generation_bump());
        assert!(result.dirty_roots.contains(Path::new("/root")));
    }

    #[test]
    fn coalesced_overflow_still_revokes_candidates_from_intervening_scans() {
        let roots = vec![PathBuf::from("/root")];
        let mut backoff = OverflowBackoff::default();
        let now = Instant::now();
        assert!(record_loss(&roots, &mut backoff, now).requires_reconciliation());
        let next = record_loss(&roots, &mut backoff, now + Duration::from_secs(1));
        assert!(next.requires_index_generation_bump());
        assert!(!next.requires_reconciliation());
        assert!(backoff.take_deferred(now + RETRY_INTERVAL));
    }

    #[test]
    fn unavailable_backends_retry_without_events_but_never_spin_or_override_opt_out() {
        let mut cfg = config(&["/root"], 1);
        let plan = resolve_roots(&cfg, |_| Err(io::Error::other("offline")));
        let capability = EventSourceCapability::from_plan(&plan.summary);
        let now = Instant::now();
        assert!(!retry_due(
            &cfg,
            &capability,
            now,
            now + Duration::from_secs(29)
        ));
        assert!(retry_due(&cfg, &capability, now, now + RETRY_INTERVAL));
        cfg.mode = ScannerEventSourceMode::ReconciliationOnly;
        assert!(!retry_due(
            &cfg,
            &capability,
            now,
            now + Duration::from_secs(3600)
        ));
        cfg.watch_budget = 0;
        let disabled = resolve_roots(&cfg, |_| {
            panic!("disabled plans must not touch the filesystem")
        });
        assert_eq!(disabled.summary.backend, EventBackendKind::ReconciliationOnly);
    }

    #[test]
    fn root_inspection_rejects_files_and_traversal_and_accepts_real_directories() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            inspect_root(dir.path()).unwrap(),
            fs::canonicalize(dir.path()).unwrap()
        );
        let cfg = EventSourceConfig::from_scanner_config(
            &[dir.path().to_path_buf()],
            &ScannerConfig::default(),
        );
        assert!(root_plan(&cfg).summary.complete);
        let file = dir.path().join("not-a-directory");
        fs::write(&file, b"data").unwrap();
        assert!(inspect_root(&file).is_err());
        assert!(inspect_root(&dir.path().join("../elsewhere")).is_err());
        assert!(inspect_root(Path::new("relative")).is_err());
    }
}
