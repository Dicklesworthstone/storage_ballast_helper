//! Bounded read-only startup and reload discovery.
//!
//! A native lookup cannot be cancelled safely. Its single slot remains occupied
//! across new requests, expiry and shutdown until the thread has really exited.
//! Discovery is atomic: an incomplete or obsolete plan grants no new authority.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::ballast::coordinator::{
    BallastDiscoveryRevision, BallastPoolCoordinator, PoolInventory,
};
use crate::ballast::release::BallastReleaseController;
use crate::core::config::Config;
use crate::core::errors::Result;
use crate::daemon::self_monitor::{
    BallastPoolState, LoggingState, SelfMonitor, assess_logging_placement,
    nearest_existing_ancestor,
};
use crate::monitor::fs_stats::FsStatsCollector;
use crate::monitor::special_locations::SpecialLocationRegistry;
use crate::platform::pal::Platform;

const DISCOVERY_MAX_AGE: Duration = Duration::from_secs(60);
const DISCOVERY_RETRY: Duration = Duration::from_secs(30);

struct Worker<T> {
    generation: u64,
    started_at: Instant,
    handle: JoinHandle<std::result::Result<T, String>>,
}

/// One read-only operation, coalescing requests without replacing blocked jobs.
pub(super) struct RetainedDiscovery<T> {
    generation: u64,
    pending: bool,
    worker: Option<Worker<T>>,
    retry_at: Option<Instant>,
    error: Option<String>,
}

impl<T> Default for RetainedDiscovery<T> {
    fn default() -> Self {
        Self {
            generation: 0,
            pending: false,
            worker: None,
            retry_at: None,
            error: None,
        }
    }
}

impl<T: Send + 'static> RetainedDiscovery<T> {
    pub(super) fn request(&mut self) {
        let Some(next) = self
            .generation
            .checked_add(1)
            .filter(|next| *next < u64::MAX)
        else {
            self.generation = u64::MAX;
            self.pending = true;
            self.retry_at = None;
            self.error = Some("discovery generation exhausted; restart the daemon".into());
            return;
        };
        self.generation = next;
        self.pending = true;
        self.retry_at = None;
        self.error = None;
    }

    pub(super) fn pending(&self) -> bool {
        self.pending
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[cfg(test)]
    pub(super) fn occupied(&self) -> bool {
        self.worker.is_some()
    }

    /// Poll without native I/O or waiting. The timestamp predates the entire
    /// native operation; late delivery never makes an old plan fresh again.
    pub(super) fn poll(
        &mut self,
        now: Instant,
        work: impl FnOnce() -> std::result::Result<T, String> + Send + 'static,
    ) -> Option<T> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.handle.is_finished())
        {
            let worker = self.worker.take().expect("finished worker was present");
            let result = worker
                .handle
                .join()
                .unwrap_or_else(|_| Err("discovery worker panicked".into()));
            if worker.generation == self.generation {
                let result = if now
                    .checked_duration_since(worker.started_at)
                    .is_some_and(|age| age <= DISCOVERY_MAX_AGE)
                {
                    result
                } else {
                    Err("discovery result expired before it could be accepted".into())
                };
                match result {
                    Ok(result) => {
                        self.pending = false;
                        self.error = None;
                        return Some(result);
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.retry_at = Some(now + DISCOVERY_RETRY);
                    }
                }
            }
        }
        if self.pending
            && self.generation < u64::MAX
            && self.worker.is_none()
            && self.retry_at.is_none_or(|at| now >= at)
        {
            match std::thread::Builder::new()
                .name("sbh-discovery".into())
                .spawn(work)
            {
                Ok(handle) => {
                    self.worker = Some(Worker {
                        generation: self.generation,
                        started_at: now,
                        handle,
                    });
                }
                Err(error) => {
                    self.error = Some(format!("could not start discovery: {error}"));
                    self.retry_at = Some(now + DISCOVERY_RETRY);
                }
            }
        }
        None
    }
}

/// A complete discovery result. All native inventory and placement work is
/// finished before this value crosses onto the monitoring thread.
pub(super) struct DiscoverySnapshot {
    pub(super) prior_revision: Option<BallastDiscoveryRevision>,
    pub(super) special_locations: SpecialLocationRegistry,
    pub(super) ballast_coordinator: BallastPoolCoordinator,
    pub(super) logging_placement: LoggingState,
    pub(super) inventory: Vec<PoolInventory>,
    pub(super) release_controller: BallastReleaseController,
}

impl DiscoverySnapshot {
    pub(super) fn collect(config: &Config, platform: &Arc<dyn Platform>) -> Result<Self> {
        let previous = SelfMonitor::read_state(&config.paths.state_file)
            .map(|state| state.ballast_pools)
            .unwrap_or_default();
        Self::collect_with_history(config, platform, previous)
    }

    pub(super) fn collect_with_history(
        config: &Config,
        platform: &Arc<dyn Platform>,
        previous_pools: Vec<BallastPoolState>,
    ) -> Result<Self> {
        let special_locations = SpecialLocationRegistry::discover(platform.as_ref(), &[])?;
        let paths = super::loop_main::ballast_discovery_paths(config, &special_locations);
        let mut ballast_coordinator = BallastPoolCoordinator::discover_inner(
            &config.ballast,
            &paths,
            platform.as_ref(),
            platform,
            Some(&config.paths.ballast_dir),
        )?;
        ballast_coordinator.set_provision_floor_rule(config.ballast_provision_floor());
        let inventory = ballast_coordinator.inventory();
        let fs_collector = FsStatsCollector::new(
            Arc::clone(platform),
            Duration::from_millis(config.telemetry.fs_cache_ttl_ms),
        );
        let mut monitored = BTreeSet::new();
        for path in config.scanner.root_paths.iter().chain(
            special_locations
                .all()
                .iter()
                .map(|location| &location.path),
        ) {
            if let Ok(stats) = fs_collector.collect(path) {
                monitored.insert(stats.mount_point);
            }
        }
        monitored.extend(
            inventory
                .iter()
                .filter(|pool| !pool.skipped)
                .map(|pool| pool.mount_point.clone()),
        );
        let logging_placement = assess_logging_placement(
            |path| {
                nearest_existing_ancestor(path)
                    .and_then(|existing| fs_collector.collect(&existing).ok())
                    .map(|stats| stats.mount_point)
            },
            &[
                &config.paths.sqlite_db,
                &config.paths.jsonl_log,
                &config.paths.state_file,
            ],
            &monitored,
        );
        let mut release_controller =
            BallastReleaseController::new(config.ballast.replenish_cooldown_minutes);
        for saved in previous_pools {
            let mount = std::path::PathBuf::from(&saved.mount);
            let Some(pool) = ballast_coordinator.pool_for_mount(&mount) else {
                continue;
            };
            if !saved.skipped
                && let Some(history) = saved.release_history
                && release_controller.restore_pool_history(&mount, &pool.ballast_dir, history)
                && let Some(efficiency) = saved.release_efficiency
            {
                release_controller.set_release_efficiency(&mount, efficiency);
            }
        }
        for pool in inventory.iter().filter(|pool| !pool.skipped) {
            let _ = release_controller.pool_history(
                &pool.mount_point,
                &pool.ballast_dir,
                pool.files_available,
            );
        }
        Ok(Self {
            prior_revision: None,
            special_locations,
            ballast_coordinator,
            logging_placement,
            inventory,
            release_controller,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn finish<T>(discovery: &RetainedDiscovery<T>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !discovery.worker.as_ref().unwrap().handle.is_finished() {
            assert!(Instant::now() < deadline, "worker did not finish");
            std::thread::yield_now();
        }
    }

    #[test]
    fn reload_retains_occupied_slot_and_discards_obsolete_completion() {
        let mut discovery = RetainedDiscovery::default();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        discovery.request();
        let now = Instant::now();
        assert!(
            discovery
                .poll(now, move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(1)
                })
                .is_none()
        );
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..32 {
            discovery.request();
            assert!(
                discovery
                    .poll(now, || panic!("occupied slot replaced"))
                    .is_none()
            );
        }
        release_tx.send(()).unwrap();
        finish(&discovery);
        assert!(discovery.poll(now, || Ok(2)).is_none());
        finish(&discovery);
        assert_eq!(discovery.poll(now, || unreachable!()), Some(2));
        assert!(!discovery.pending());
    }

    #[test]
    fn expired_results_and_panics_retry_without_granting_authority() {
        let mut discovery = RetainedDiscovery::default();
        discovery.request();
        let now = Instant::now();
        assert!(discovery.poll(now, || Ok(1)).is_none());
        finish(&discovery);
        let late = now + DISCOVERY_MAX_AGE + Duration::from_secs(1);
        assert!(discovery.poll(late, || unreachable!()).is_none());
        assert!(discovery.pending());
        assert!(discovery.error().unwrap().contains("expired"));
        assert!(
            discovery
                .poll(late + DISCOVERY_RETRY, || panic!("native failure"))
                .is_none()
        );
        finish(&discovery);
        assert!(
            discovery
                .poll(late + DISCOVERY_RETRY, || unreachable!())
                .is_none()
        );
        assert!(discovery.error().unwrap().contains("panicked"));
    }

    #[test]
    fn generation_exhaustion_never_reuses_old_authority() {
        let mut discovery = RetainedDiscovery::<()> {
            generation: u64::MAX - 1,
            ..RetainedDiscovery::default()
        };
        discovery.request();
        assert!(discovery.pending());
        assert!(discovery.error().unwrap().contains("generation exhausted"));
        assert!(
            discovery
                .poll(Instant::now(), || panic!("exhausted generation spawned"))
                .is_none()
        );
    }

    #[test]
    fn dropping_discovery_does_not_wait_for_native_io() {
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (exited_tx, exited_rx) = mpsc::sync_channel(1);
        let mut discovery = RetainedDiscovery::<()>::default();
        discovery.request();
        discovery.poll(Instant::now(), move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            exited_tx.send(()).unwrap();
            Ok(())
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(discovery);
        release_tx.send(()).unwrap();
        exited_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}
