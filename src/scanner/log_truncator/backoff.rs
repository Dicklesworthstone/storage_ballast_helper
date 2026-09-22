//! Bounded, process-local cooldown for failed log-reclamation attempts.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub(super) const RETRY_INTERVAL: Duration = Duration::from_secs(60);
const MAX_FAILURES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum FailureKey {
    Pattern(PathBuf),
    Candidate(PathBuf),
}

#[derive(Debug, Default)]
pub(super) struct FailureBackoff {
    failed_at: HashMap<FailureKey, Instant>,
    overflow_at: Option<Instant>,
}

impl FailureBackoff {
    /// Expired entries disappear without touching the filesystem. At the
    /// capacity limit, defer new attempts instead of evicting a still-cooling
    /// failure and allowing a failure storm to defeat the cooldown.
    pub(super) fn blocked(&mut self, key: &FailureKey, now: Instant) -> bool {
        self.failed_at
            .retain(|_, at| now.saturating_duration_since(*at) < RETRY_INTERVAL);
        if self
            .overflow_at
            .is_some_and(|at| now.saturating_duration_since(at) >= RETRY_INTERVAL)
        {
            self.overflow_at = None;
        }
        self.overflow_at.is_some()
            || self.failed_at.contains_key(key)
            || self.failed_at.len() >= MAX_FAILURES
    }

    pub(super) fn failed(&mut self, key: FailureKey, now: Instant) {
        if self.failed_at.contains_key(&key) || self.failed_at.len() < MAX_FAILURES {
            self.failed_at.insert(key, now);
        } else {
            // Concurrent sweeps can pass admission before either records its
            // failure. Keep the map bounded without forgetting that last
            // failure's full cooldown.
            self.overflow_at = Some(now);
        }
    }

    pub(super) fn succeeded(&mut self, key: &FailureKey) {
        self.failed_at.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> FailureKey {
        FailureKey::Candidate(PathBuf::from(name))
    }

    #[test]
    fn failures_retry_at_the_boundary_and_never_slide_on_a_skipped_attempt() {
        let now = Instant::now();
        let mut backoff = FailureBackoff::default();
        let path = key("/bad.log");
        assert!(!backoff.blocked(&path, now));
        backoff.failed(path.clone(), now);
        for second in 0..60 {
            assert!(backoff.blocked(&path, now + Duration::from_secs(second)));
        }
        assert!(!backoff.blocked(&path, now + RETRY_INTERVAL));
        assert!(backoff.failed_at.is_empty());
    }

    #[test]
    fn one_failure_does_not_block_an_independent_log_or_pattern() {
        let now = Instant::now();
        let mut backoff = FailureBackoff::default();
        let path = key("/bad.log");
        backoff.failed(path.clone(), now);
        assert!(backoff.blocked(&path, now));
        assert!(!backoff.blocked(&key("/good.log"), now));
        assert!(!backoff.blocked(&FailureKey::Pattern(PathBuf::from("/bad.log")), now));
        backoff.succeeded(&path);
        assert!(!backoff.blocked(&path, now));
    }

    #[test]
    fn failure_storm_bounds_memory_without_evicting_live_cooldowns() {
        let now = Instant::now();
        let mut backoff = FailureBackoff::default();
        for i in 0..MAX_FAILURES {
            backoff.failed(key(&format!("/{i}.log")), now);
        }
        let late = now + Duration::from_secs(10);
        assert!(backoff.blocked(&key("/another.log"), late));
        backoff.failed(key("/concurrent.log"), late);
        assert_eq!(backoff.failed_at.len(), MAX_FAILURES);
        assert!(backoff.blocked(&key("/concurrent.log"), now + RETRY_INTERVAL));
        assert!(!backoff.blocked(&key("/concurrent.log"), late + RETRY_INTERVAL));
        assert!(backoff.failed_at.is_empty());
    }

    #[test]
    fn earlier_clock_observations_do_not_expire_a_failure() {
        let now = Instant::now();
        let mut backoff = FailureBackoff::default();
        backoff.failed(key("/bad.log"), now + Duration::from_secs(1));
        assert!(backoff.blocked(&key("/bad.log"), now));
    }
}
