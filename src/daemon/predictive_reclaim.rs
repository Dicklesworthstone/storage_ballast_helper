//! Short-lived scoring permission from one filesystem's current forecast.
//!
//! This admission changes only a request's score threshold. Its caller must
//! also carry matching filesystem reclaim scope and renew that scope before
//! mutation. Certainty, idleness, regret, policy and deletion vetoes continue
//! to apply. Forecasts never modify the score floor shared by other requests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::core::config::{PredictionConfig, ScoringConfig};
use crate::monitor::predictive::PredictiveAction;
use crate::scanner::deletion::SkipReason;

/// A forecast and its original policy, shared by all batches from one pass.
#[derive(Debug, Clone)]
pub struct PredictiveScanAdmission {
    admitted: Arc<AdmittedForecast>,
}

#[derive(Debug)]
struct AdmittedForecast {
    mount: PathBuf,
    prediction: PredictionConfig,
    scoring: ScoringConfig,
    min_score: f64,
    runway_deadline: Instant,
    life: Mutex<ForecastLife>,
    revoked: AtomicBool,
}

#[derive(Debug)]
struct ForecastLife {
    last_collected_at: Instant,
    fresh_until: Instant,
}

/// A gated action paired with the actual filesystem sample that produced it.
#[derive(Debug, Clone)]
pub struct PredictiveObservation {
    /// The mount-local action after prediction and physical-pressure gates.
    pub action: PredictiveAction,
    /// Original collection time, unchanged when the collector returns a cache hit.
    pub collected_at: Instant,
    /// Maximum age allowed by the current filesystem observation policy.
    pub max_age: Duration,
}

#[derive(Debug, Clone, Copy)]
struct ObservedForecast {
    min_score: f64,
    collected_at: Instant,
    fresh_until: Instant,
    runway_deadline: Instant,
}

/// Bound retained queue permissions even if many scans arrive before time moves.
const MAX_TRACKED_ADMISSIONS: usize = 512;

/// Live forecast policy and the permissions it can withdraw from queued work.
///
/// The daemon keeps this owner behind its shared executor configuration lock.
/// Observing a cleared forecast or reloading policy revokes every affected
/// queued clone immediately, even if no worker ran during that transition.
#[derive(Debug)]
pub struct PredictiveReclaimPolicy {
    prediction: PredictionConfig,
    scoring: ScoringConfig,
    active: Vec<PredictiveScanAdmission>,
}

impl PredictiveReclaimPolicy {
    /// Start with the current prediction and scoring policies and no permission.
    #[must_use]
    pub fn new(prediction: &PredictionConfig, scoring: &ScoringConfig) -> Self {
        Self {
            prediction: prediction.clone(),
            scoring: scoring.clone(),
            active: Vec::new(),
        }
    }

    /// Withdraw queued permissions before publishing any changed policy.
    pub fn update(&mut self, prediction: &PredictionConfig, scoring: &ScoringConfig) {
        if *prediction != self.prediction || *scoring != self.scoring {
            self.revoke_all();
            self.prediction = prediction.clone();
            self.scoring = scoring.clone();
        }
    }

    /// Renew one queued permission against the live policy and its deadline.
    pub fn authorize(
        &self,
        admission: &PredictiveScanAdmission,
        now: Instant,
    ) -> Result<(), SkipReason> {
        admission.authorize_policy(&self.prediction, &self.scoring, now)
    }

    /// Derive one pass's scoring model from the unchanged live configuration.
    ///
    /// The scanner may have read its configuration before a concurrent reload.
    /// It must not apply a current forecast to that old model, nor feed an
    /// already-relaxed pass configuration back into this admission check.
    pub fn scoring_config(
        &self,
        admission: &PredictiveScanAdmission,
        configured: &ScoringConfig,
        now: Instant,
    ) -> Result<ScoringConfig, SkipReason> {
        self.authorize(admission, now)?;
        if *configured != self.scoring {
            admission.revoke();
            return Err(SkipReason::PolicyChanged);
        }
        let mut scoring = configured.clone();
        scoring.min_score = admission.min_score();
        Ok(scoring)
    }

    /// Admit one current action and retain a clone so later ticks can revoke it.
    ///
    /// Collection time remains the original observation time. Queue arrival
    /// and cached forecasts cannot extend its runway or freshness. Only
    /// [`Self::observe_samples`] can renew freshness from a newer sample.
    #[must_use]
    pub fn admit(
        &mut self,
        action: &PredictiveAction,
        observed_at: Instant,
        max_age: Duration,
        now: Instant,
    ) -> Option<PredictiveScanAdmission> {
        self.active.retain(|admission| {
            admission
                .authorize_policy(&self.prediction, &self.scoring, now)
                .is_ok()
        });
        let admission = PredictiveScanAdmission::new(
            action,
            &self.prediction,
            &self.scoring,
            observed_at,
            max_age,
        )?;
        self.authorize(&admission, now).ok()?;
        if self.active.len() == MAX_TRACKED_ADMISSIONS {
            // Forgetting a live entry would make later withdrawal incomplete.
            // Retire its authority first; fresh work can retry its candidates.
            self.active.remove(0).revoke();
        }
        self.active.push(admission.clone());
        Some(admission)
    }

    /// Withdraw forecasts absent from the current, mount-local physical tick.
    ///
    /// Callers supply only actions whose effective and physical filesystem
    /// readings match. Missing, warning-only or invalid actions cannot retain
    /// old authority. A higher current score floor also withdraws a previously
    /// lower one; a lower floor never silently widens the old permission.
    pub fn observe(&mut self, actions: &[PredictiveAction], now: Instant) {
        let mut floors: HashMap<&Path, Option<f64>> = HashMap::new();
        for action in actions {
            let Some(mount) = action_mount(action) else {
                continue;
            };
            let floor =
                action_floor(action, &self.prediction, &self.scoring).map(|(_, _, floor)| floor);
            floors
                .entry(mount)
                .and_modify(|previous| {
                    // Conflicting evidence for the same mount is conservative:
                    // an invalid action wins; otherwise the higher floor wins.
                    *previous = previous.zip(floor).map(|(old, new)| old.max(new));
                })
                .or_insert(floor);
        }
        self.active.retain(|admission| {
            if admission
                .authorize_policy(&self.prediction, &self.scoring, now)
                .is_ok()
                && floors
                    .get(admission.mount())
                    .copied()
                    .flatten()
                    .is_some_and(|floor| floor <= admission.min_score())
            {
                true
            } else {
                admission.revoke();
                false
            }
        });
    }

    /// Keep a slow pass current using genuinely newer mount observations.
    ///
    /// Renew only permissions that are still live now. A cached timestamp,
    /// observation gap, withdrawn action or changed policy cannot revive one.
    /// The score and original runway stay fixed; current shorter runways can
    /// only tighten that bound. Callers must preserve original collection
    /// times and supply only coherent physical/effective mount observations.
    pub fn observe_samples(&mut self, samples: &[PredictiveObservation], now: Instant) {
        let mut current: HashMap<&Path, Option<ObservedForecast>> = HashMap::new();
        for sample in samples {
            let Some(mount) = action_mount(&sample.action) else {
                continue;
            };
            let forecast = ObservedForecast::new(sample, &self.prediction, &self.scoring, now);
            current
                .entry(mount)
                .and_modify(|previous| {
                    // Conflicting observations never erase stricter evidence.
                    *previous = previous
                        .zip(forecast)
                        .map(|(old, new)| old.conservative_merge(new));
                })
                .or_insert(forecast);
        }
        self.active.retain(|admission| {
            let forecast = current.get(admission.mount()).copied().flatten();
            if admission
                .authorize_policy(&self.prediction, &self.scoring, now)
                .is_ok()
                && forecast.is_some_and(|forecast| {
                    forecast.min_score <= admission.min_score()
                        && admission.renew_freshness(forecast, now)
                })
            {
                true
            } else {
                admission.revoke();
                false
            }
        });
    }

    /// A replaced filesystem cannot renew the former mount's queued forecasts.
    /// Other mounts retain their independently observed permissions.
    pub fn revoke_mount(&mut self, mount: &Path) {
        self.active.retain(|admission| {
            if admission.mount() == mount {
                admission.revoke();
                false
            } else {
                true
            }
        });
    }

    /// Missing pressure evidence and shutdown revoke every outstanding pass.
    pub fn revoke_all(&mut self) {
        for admission in self.active.drain(..) {
            admission.revoke();
        }
    }
}

impl PredictiveScanAdmission {
    /// Capture an already-gated cleanup forecast without performing any I/O.
    ///
    /// `observed_at` is the filesystem observation's original collection time,
    /// not the request's enqueue time. Initial validity lasts no longer than
    /// either `max_age` or the original forecast runway. Newer samples can
    /// renew freshness while the original runway remains an absolute bound.
    /// Invalid or non-cleanup actions confer no permission. Only preemptive
    /// cleanup lowers a score; imminent danger retains the configured floor.
    #[must_use]
    pub fn new(
        action: &PredictiveAction,
        prediction: &PredictionConfig,
        scoring: &ScoringConfig,
        observed_at: Instant,
        max_age: Duration,
    ) -> Option<Self> {
        if max_age.is_zero() {
            return None;
        }
        let (mount, minutes_remaining, min_score) = action_floor(action, prediction, scoring)?;
        let runway = Duration::try_from_secs_f64(minutes_remaining * 60.0).ok()?;
        let lifetime = max_age.min(runway);
        if lifetime.is_zero() {
            return None;
        }
        let fresh_until = observed_at.checked_add(lifetime)?;
        let runway_deadline = observed_at.checked_add(runway)?;
        Some(Self {
            admitted: Arc::new(AdmittedForecast {
                mount: mount.to_path_buf(),
                prediction: prediction.clone(),
                scoring: scoring.clone(),
                min_score,
                runway_deadline,
                life: Mutex::new(ForecastLife {
                    last_collected_at: observed_at,
                    fresh_until,
                }),
                revoked: AtomicBool::new(false),
            }),
        })
    }

    /// The forecast's exact mount; it must match the filesystem admission.
    #[must_use]
    pub fn mount(&self) -> &Path {
        &self.admitted.mount
    }

    /// The pass-local floor, valid only while [`Self::authorize_policy`] holds.
    #[must_use]
    pub fn min_score(&self) -> f64 {
        self.admitted.min_score
    }

    /// Withdraw this permission and every queued clone of it permanently.
    pub fn revoke(&self) {
        self.admitted.revoked.store(true, Ordering::Release);
    }

    /// Renew the exact policy and observation lifetime without cloning configs.
    ///
    /// A changed score model requires fresh scoring, even when its new floor
    /// is lower. Disabling prediction or changing any prediction setting also
    /// requires a new forecast. Once observed, withdrawal is permanent across
    /// clones, including if the operator later restores the original settings.
    pub fn authorize_policy(
        &self,
        prediction: &PredictionConfig,
        scoring: &ScoringConfig,
        now: Instant,
    ) -> Result<(), SkipReason> {
        if self.admitted.revoked.load(Ordering::Acquire)
            || !prediction.enabled
            || *prediction != self.admitted.prediction
            || *scoring != self.admitted.scoring
            || !self.fresh_at(now)
        {
            self.revoke();
            return Err(SkipReason::PolicyChanged);
        }
        Ok(())
    }

    fn fresh_at(&self, now: Instant) -> bool {
        let life = self.admitted.life.lock();
        now >= life.last_collected_at && now < life.fresh_until
    }

    fn renew_freshness(&self, observation: ObservedForecast, now: Instant) -> bool {
        let mut life = self.admitted.life.lock();
        if self.admitted.revoked.load(Ordering::Acquire)
            || now < life.last_collected_at
            || now >= life.fresh_until
        {
            return false;
        }
        let deadline = self
            .admitted
            .runway_deadline
            .min(observation.runway_deadline);
        if observation.collected_at > life.last_collected_at {
            life.last_collected_at = observation.collected_at;
            life.fresh_until = observation.fresh_until.min(deadline);
        } else {
            // A cached or out-of-order sample cannot extend freshness. A
            // shorter current runway remains a conservative stop condition.
            life.fresh_until = life.fresh_until.min(deadline);
        }
        now < life.fresh_until
    }
}

impl ObservedForecast {
    fn new(
        sample: &PredictiveObservation,
        prediction: &PredictionConfig,
        scoring: &ScoringConfig,
        now: Instant,
    ) -> Option<Self> {
        if sample.max_age.is_zero() || sample.collected_at > now {
            return None;
        }
        let (_, minutes, min_score) = action_floor(&sample.action, prediction, scoring)?;
        let runway = Duration::try_from_secs_f64(minutes * 60.0).ok()?;
        let fresh_until = sample
            .collected_at
            .checked_add(sample.max_age.min(runway))?;
        let runway_deadline = sample.collected_at.checked_add(runway)?;
        (now < fresh_until).then_some(Self {
            min_score,
            collected_at: sample.collected_at,
            fresh_until,
            runway_deadline,
        })
    }

    fn conservative_merge(self, other: Self) -> Self {
        let mut latest = if other.collected_at > self.collected_at {
            other
        } else {
            self
        };
        latest.min_score = self.min_score.max(other.min_score);
        latest.runway_deadline = self.runway_deadline.min(other.runway_deadline);
        latest.fresh_until = latest.fresh_until.min(latest.runway_deadline);
        if self.collected_at == other.collected_at {
            latest.fresh_until = latest.fresh_until.min(other.fresh_until);
        }
        latest
    }
}

fn action_mount(action: &PredictiveAction) -> Option<&Path> {
    match action {
        PredictiveAction::Clear => None,
        PredictiveAction::EarlyWarning { mount, .. }
        | PredictiveAction::PreemptiveCleanup { mount, .. }
        | PredictiveAction::ImminentDanger { mount, .. } => Some(mount),
    }
}

/// Validate action evidence once for both initial admission and later ticks.
fn action_floor<'a>(
    action: &'a PredictiveAction,
    prediction: &PredictionConfig,
    scoring: &ScoringConfig,
) -> Option<(&'a Path, f64, f64)> {
    if !prediction_valid(prediction) || !(0.0..=1.0).contains(&scoring.min_score) {
        return None;
    }
    let (mount, minutes_remaining, min_score) = match action {
        PredictiveAction::PreemptiveCleanup {
            mount,
            minutes_remaining,
            confidence,
            rate_bytes_per_second,
            recommended_min_score,
            recommended_free_target_pct,
        } => {
            if !positive_within(*recommended_min_score, 1.0)
                || !(prediction.min_confidence..=1.0).contains(confidence)
                || !rate_bytes_per_second.is_finite()
                || *rate_bytes_per_second <= 0.0
                || !positive_within(*recommended_free_target_pct, 100.0)
                || !positive_within(*minutes_remaining, prediction.action_horizon_minutes)
                || *minutes_remaining <= prediction.imminent_danger_minutes
            {
                return None;
            }
            (
                mount,
                *minutes_remaining,
                scoring.min_score.min(*recommended_min_score),
            )
        }
        PredictiveAction::ImminentDanger {
            mount,
            minutes_remaining,
            critical,
        } => {
            if !positive_within(*minutes_remaining, prediction.imminent_danger_minutes)
                || *critical != (*minutes_remaining <= prediction.critical_danger_minutes)
            {
                return None;
            }
            (mount, *minutes_remaining, scoring.min_score)
        }
        PredictiveAction::Clear | PredictiveAction::EarlyWarning { .. } => return None,
    };
    mount
        .is_absolute()
        .then_some((mount.as_path(), minutes_remaining, min_score))
}

fn positive_within(value: f64, maximum: f64) -> bool {
    value.is_finite() && value > 0.0 && value <= maximum
}

fn prediction_valid(prediction: &PredictionConfig) -> bool {
    prediction.enabled
        && positive_within(prediction.warning_horizon_minutes, f64::MAX / 60.0)
        && positive_within(
            prediction.action_horizon_minutes,
            prediction.warning_horizon_minutes,
        )
        && Duration::try_from_secs_f64(prediction.action_horizon_minutes * 60.0).is_ok()
        && prediction.action_horizon_minutes < prediction.warning_horizon_minutes
        && positive_within(
            prediction.imminent_danger_minutes,
            prediction.action_horizon_minutes,
        )
        && prediction.imminent_danger_minutes < prediction.action_horizon_minutes
        && (0.0..prediction.imminent_danger_minutes).contains(&prediction.critical_danger_minutes)
        && (0.0..=1.0).contains(&prediction.min_confidence)
        && (0.0..=1.0).contains(&prediction.burst_min_confidence)
        && (0.5..1.0).contains(&prediction.coverage_target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::ewma::Trend;

    fn action(score: f64) -> PredictiveAction {
        PredictiveAction::PreemptiveCleanup {
            mount: PathBuf::from("/data"),
            minutes_remaining: 10.0,
            confidence: 0.95,
            rate_bytes_per_second: 1_000_000.0,
            recommended_min_score: score,
            recommended_free_target_pct: 20.0,
        }
    }

    fn admission(now: Instant) -> PredictiveScanAdmission {
        PredictiveScanAdmission::new(
            &action(0.30),
            &PredictionConfig::default(),
            &ScoringConfig::default(),
            now,
            Duration::from_secs(60),
        )
        .unwrap()
    }

    #[test]
    fn a_forecast_lowers_only_its_own_floor_and_never_raises_a_lower_configured_floor() {
        let now = Instant::now();
        let prediction = PredictionConfig::default();
        for (configured, recommended, expected) in
            [(0.35, 0.30, 0.30), (0.20, 0.60, 0.20), (0.0, 0.30, 0.0)]
        {
            let scoring = ScoringConfig {
                min_score: configured,
                ..Default::default()
            };
            let admitted = PredictiveScanAdmission::new(
                &action(recommended),
                &prediction,
                &scoring,
                now,
                Duration::from_secs(60),
            )
            .unwrap();
            assert_eq!(admitted.mount(), Path::new("/data"));
            assert_eq!(admitted.min_score(), expected);
            assert_eq!(
                scoring.min_score, configured,
                "shared config stays unchanged"
            );
            assert!(
                admitted
                    .authorize_policy(&prediction, &scoring, now)
                    .is_ok()
            );
        }
    }

    #[test]
    fn only_current_cleanup_actions_can_admit_predictive_work() {
        let now = Instant::now();
        let prediction = PredictionConfig::default();
        let scoring = ScoringConfig::default();
        let warning = PredictiveAction::EarlyWarning {
            mount: PathBuf::from("/data"),
            minutes_remaining: 40.0,
            confidence: 0.95,
            rate_bytes_per_second: 1_000_000.0,
            trend: Trend::Stable,
        };
        for refused in [PredictiveAction::Clear, warning] {
            assert!(
                PredictiveScanAdmission::new(
                    &refused,
                    &prediction,
                    &scoring,
                    now,
                    Duration::from_secs(60),
                )
                .is_none()
            );
        }
        for (minutes_remaining, critical) in [(4.0, false), (1.0, true)] {
            let imminent = PredictiveAction::ImminentDanger {
                mount: PathBuf::from("/data"),
                minutes_remaining,
                critical,
            };
            let admitted = PredictiveScanAdmission::new(
                &imminent,
                &prediction,
                &scoring,
                now,
                Duration::from_secs(60),
            )
            .unwrap();
            assert_eq!(admitted.min_score(), scoring.min_score);
        }
        for (minutes_remaining, critical) in [(4.0, true), (1.0, false), (6.0, false), (0.0, true)]
        {
            let malformed = PredictiveAction::ImminentDanger {
                mount: PathBuf::from("/data"),
                minutes_remaining,
                critical,
            };
            assert!(
                PredictiveScanAdmission::new(
                    &malformed,
                    &prediction,
                    &scoring,
                    now,
                    Duration::from_secs(60),
                )
                .is_none()
            );
        }
    }

    #[test]
    fn malformed_recommendations_and_evidence_never_lower_a_floor() {
        let now = Instant::now();
        let prediction = PredictionConfig::default();
        let scoring = ScoringConfig::default();
        let admitted = |action: &PredictiveAction| {
            PredictiveScanAdmission::new(
                action,
                &prediction,
                &scoring,
                now,
                Duration::from_secs(60),
            )
        };
        for score in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0, 1.01] {
            assert!(admitted(&action(score)).is_none(), "score={score}");
        }
        for case in 0..9 {
            let mut malformed = action(0.3);
            let PredictiveAction::PreemptiveCleanup {
                mount,
                minutes_remaining,
                confidence,
                rate_bytes_per_second,
                recommended_free_target_pct,
                ..
            } = &mut malformed
            else {
                unreachable!()
            };
            match case {
                0 => *mount = PathBuf::from("relative"),
                1 => *minutes_remaining = f64::NAN,
                2 => *minutes_remaining = 31.0,
                3 => *minutes_remaining = 5.0,
                4 => *confidence = 0.69,
                5 => *confidence = f64::NAN,
                6 => *rate_bytes_per_second = 0.0,
                7 => *rate_bytes_per_second = f64::INFINITY,
                _ => *recommended_free_target_pct = f64::NAN,
            }
            assert!(admitted(&malformed).is_none(), "case={case}");
        }
    }

    #[test]
    fn prediction_and_score_policy_changes_revoke_every_clone_permanently() {
        let now = Instant::now();
        let prediction = PredictionConfig::default();
        let scoring = ScoringConfig::default();
        for case in 0..11 {
            let admitted = admission(now);
            let queued = admitted.clone();
            let mut changed_prediction = prediction.clone();
            let mut changed_scoring = scoring.clone();
            match case {
                0 => changed_prediction.enabled = false,
                1 => changed_prediction.min_confidence += 0.1,
                2 => changed_prediction.action_horizon_minutes += 1.0,
                3 => changed_prediction.min_samples += 1,
                4 => changed_scoring.min_score += 0.01,
                5 => changed_scoring.min_score -= 0.01,
                6 => changed_scoring.false_positive_loss += 1.0,
                7 => changed_scoring.location_weight += 0.01,
                8 => changed_scoring.definite_floor_maintenance_idle_hours += 1,
                9 => changed_scoring.regret_alpha_definite += 0.01,
                _ => changed_scoring.batch_risk_budget_by_level.green += 1.0,
            }
            assert_eq!(
                admitted.authorize_policy(&changed_prediction, &changed_scoring, now),
                Err(SkipReason::PolicyChanged),
                "case={case}"
            );
            assert_eq!(
                queued.authorize_policy(&prediction, &scoring, now),
                Err(SkipReason::PolicyChanged),
                "restoring settings cannot revive case={case}"
            );
        }
    }

    #[test]
    fn original_observation_time_and_runway_bound_all_queued_copies() {
        let now = Instant::now();
        let prediction = PredictionConfig::default();
        let scoring = ScoringConfig::default();
        let admitted = admission(now);
        let queued = admitted.clone();
        assert!(
            queued
                .authorize_policy(&prediction, &scoring, now + Duration::from_secs(59))
                .is_ok()
        );
        assert_eq!(
            queued.authorize_policy(&prediction, &scoring, now + Duration::from_secs(60)),
            Err(SkipReason::PolicyChanged)
        );
        assert_eq!(
            admitted.authorize_policy(&prediction, &scoring, now),
            Err(SkipReason::PolicyChanged)
        );

        let imminent = PredictiveAction::ImminentDanger {
            mount: PathBuf::from("/data"),
            minutes_remaining: 0.5,
            critical: true,
        };
        let admitted = PredictiveScanAdmission::new(
            &imminent,
            &prediction,
            &scoring,
            now,
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(
            admitted
                .authorize_policy(&prediction, &scoring, now + Duration::from_secs(29))
                .is_ok()
        );
        assert_eq!(
            admitted.authorize_policy(&prediction, &scoring, now + Duration::from_secs(30)),
            Err(SkipReason::PolicyChanged)
        );
        assert!(
            PredictiveScanAdmission::new(&action(0.3), &prediction, &scoring, now, Duration::ZERO)
                .is_none()
        );
    }

    #[test]
    fn explicit_withdrawal_and_future_observations_fail_closed() {
        let now = Instant::now();
        let prediction = PredictionConfig::default();
        let scoring = ScoringConfig::default();
        let admitted = admission(now);
        let queued = admitted.clone();
        std::thread::spawn(move || queued.revoke()).join().unwrap();
        assert_eq!(
            admitted.authorize_policy(&prediction, &scoring, now),
            Err(SkipReason::PolicyChanged)
        );
        let future = admission(now + Duration::from_secs(1));
        assert_eq!(
            future.authorize_policy(&prediction, &scoring, now),
            Err(SkipReason::PolicyChanged)
        );
    }

    #[test]
    fn disabled_or_invalid_policy_cannot_mint_an_admission() {
        let now = Instant::now();
        for case in 0..11 {
            let mut prediction = PredictionConfig::default();
            let mut scoring = ScoringConfig::default();
            match case {
                0 => prediction.enabled = false,
                1 => prediction.action_horizon_minutes = f64::NAN,
                2 => prediction.warning_horizon_minutes = f64::INFINITY,
                3 => prediction.warning_horizon_minutes = prediction.action_horizon_minutes,
                4 => prediction.critical_danger_minutes = prediction.imminent_danger_minutes,
                5 => prediction.min_confidence = f64::NAN,
                6 => prediction.burst_min_confidence = -1.0,
                7 => prediction.coverage_target = 1.0,
                8 => scoring.min_score = f64::NAN,
                9 => scoring.min_score = -1.0,
                _ => {
                    prediction.action_horizon_minutes = 1e30;
                    prediction.warning_horizon_minutes = 2e30;
                }
            }
            assert!(
                PredictiveScanAdmission::new(
                    &action(0.3),
                    &prediction,
                    &scoring,
                    now,
                    Duration::from_secs(60),
                )
                .is_none(),
                "case={case}"
            );
        }
    }

    fn policy() -> PredictiveReclaimPolicy {
        PredictiveReclaimPolicy::new(&PredictionConfig::default(), &ScoringConfig::default())
    }

    fn admit(
        policy: &mut PredictiveReclaimPolicy,
        action: &PredictiveAction,
        now: Instant,
    ) -> PredictiveScanAdmission {
        policy
            .admit(action, now, Duration::from_secs(60), now)
            .unwrap()
    }

    fn action_on(mount: &str, score: f64) -> PredictiveAction {
        let mut action = action(score);
        let PredictiveAction::PreemptiveCleanup { mount: path, .. } = &mut action else {
            unreachable!()
        };
        *path = PathBuf::from(mount);
        action
    }

    #[test]
    fn live_policy_reload_revokes_old_work_even_if_settings_are_restored_before_a_worker_runs() {
        let now = Instant::now();
        let prediction = PredictionConfig::default();
        let scoring = ScoringConfig::default();
        for scoring_change in [false, true] {
            let mut policy = policy();
            let queued = admit(&mut policy, &action(0.3), now);
            policy.update(&prediction, &scoring);
            assert!(policy.authorize(&queued, now).is_ok(), "unchanged reload");
            let mut changed_prediction = prediction.clone();
            let mut changed_scoring = scoring.clone();
            if scoring_change {
                changed_scoring.definite_floor_maintenance_idle_hours += 1;
            } else {
                changed_prediction.enabled = false;
            }
            policy.update(&changed_prediction, &changed_scoring);
            policy.update(&prediction, &scoring);
            assert_eq!(
                policy.authorize(&queued, now),
                Err(SkipReason::PolicyChanged)
            );
            assert!(policy.active.is_empty());
            let fresh = admit(&mut policy, &action(0.3), now);
            assert!(policy.authorize(&fresh, now).is_ok());
        }
    }

    #[test]
    fn a_pass_changes_only_its_score_floor_and_cannot_borrow_a_different_scoring_snapshot() {
        let now = Instant::now();
        let mut policy = policy();
        let scoring = ScoringConfig::default();
        let queued = admit(&mut policy, &action(0.3), now);
        let effective = policy.scoring_config(&queued, &scoring, now).unwrap();
        let mut expected = scoring.clone();
        expected.min_score = queued.min_score();
        assert_eq!(effective, expected);
        assert_eq!(scoring, ScoringConfig::default());

        let mut stale = scoring.clone();
        stale.false_positive_loss += 1.0;
        assert_eq!(
            policy.scoring_config(&queued, &stale, now),
            Err(SkipReason::PolicyChanged)
        );
        assert_eq!(
            policy.scoring_config(&queued, &scoring, now),
            Err(SkipReason::PolicyChanged)
        );
    }

    #[test]
    fn a_withdrawn_forecast_revokes_its_queued_pass_without_touching_a_filling_peer() {
        let now = Instant::now();
        for withdrawal in [
            PredictiveAction::Clear,
            PredictiveAction::EarlyWarning {
                mount: PathBuf::from("/data"),
                minutes_remaining: 40.0,
                confidence: 0.95,
                rate_bytes_per_second: 1_000_000.0,
                trend: Trend::Stable,
            },
            action(f64::NAN),
            action(0.34),
        ] {
            let mut policy = policy();
            let withdrawn = admit(&mut policy, &action(0.3), now);
            let peer_action = action_on("/peer", 0.3);
            let peer = admit(&mut policy, &peer_action, now);
            policy.observe(&[withdrawal, peer_action.clone()], now);
            assert_eq!(
                policy.authorize(&withdrawn, now),
                Err(SkipReason::PolicyChanged)
            );
            assert!(policy.authorize(&peer, now).is_ok());
            assert_eq!(policy.active.len(), 1);
            // A returning forecast needs a new pass; the queued one is gone.
            policy.observe(&[action(0.3), peer_action], now);
            assert_eq!(
                policy.authorize(&withdrawn, now),
                Err(SkipReason::PolicyChanged)
            );
            let replacement = admit(&mut policy, &action(0.3), now);
            policy.revoke_mount(Path::new("/data"));
            assert_eq!(
                policy.authorize(&replacement, now),
                Err(SkipReason::PolicyChanged)
            );
            assert!(policy.authorize(&peer, now).is_ok());
            assert_eq!(policy.active.len(), 1);
        }
    }

    #[test]
    fn observing_a_stronger_forecast_does_not_widen_or_extend_an_existing_permission() {
        let now = Instant::now();
        let mut policy = policy();
        let original = admit(&mut policy, &action(0.3), now);
        policy.observe(&[action(0.2)], now + Duration::from_secs(59));
        assert!(
            policy
                .authorize(&original, now + Duration::from_secs(59))
                .is_ok()
        );
        assert_eq!(original.min_score(), 0.3);
        policy.observe(&[action(0.2)], now + Duration::from_secs(60));
        assert_eq!(
            policy.authorize(&original, now + Duration::from_secs(60)),
            Err(SkipReason::PolicyChanged)
        );
        assert!(policy.active.is_empty());
    }

    #[test]
    fn expired_observations_cannot_reenter_a_policy_and_new_admission_prunes_old_work() {
        let now = Instant::now();
        let mut policy = policy();
        let original = admit(&mut policy, &action(0.3), now);
        let later = now + Duration::from_secs(60);
        assert!(
            policy
                .admit(&action(0.3), now, Duration::from_secs(60), later)
                .is_none()
        );
        assert!(policy.active.is_empty());
        assert_eq!(
            policy.authorize(&original, later),
            Err(SkipReason::PolicyChanged)
        );
        let fresh = admit(&mut policy, &action(0.3), later);
        assert!(policy.authorize(&fresh, later).is_ok());
    }

    #[test]
    fn conflicting_mount_actions_do_not_restore_a_lower_floor() {
        let now = Instant::now();
        for actions in [
            vec![action(0.34), action(0.2)],
            vec![action(0.2), action(0.34)],
            vec![action(f64::NAN), action(0.2)],
            vec![action(0.2), action(f64::NAN)],
        ] {
            let mut policy = policy();
            let queued = admit(&mut policy, &action(0.3), now);
            policy.observe(&actions, now);
            assert_eq!(
                policy.authorize(&queued, now),
                Err(SkipReason::PolicyChanged)
            );
        }
    }

    #[test]
    fn explicit_withdrawal_and_tracking_bound_never_abandon_live_authority() {
        let now = Instant::now();
        let mut policy = policy();
        let oldest = admit(&mut policy, &action(0.3), now);
        let mut newest = oldest.clone();
        for _ in 0..MAX_TRACKED_ADMISSIONS {
            newest = admit(&mut policy, &action(0.3), now);
        }
        assert_eq!(policy.active.len(), MAX_TRACKED_ADMISSIONS);
        assert_eq!(
            policy.authorize(&oldest, now),
            Err(SkipReason::PolicyChanged)
        );
        assert!(policy.authorize(&newest, now).is_ok());
        policy.revoke_all();
        assert!(policy.active.is_empty());
        assert_eq!(
            policy.authorize(&newest, now),
            Err(SkipReason::PolicyChanged)
        );
    }

    fn observation(
        action: PredictiveAction,
        collected_at: Instant,
        max_age_secs: u64,
    ) -> PredictiveObservation {
        PredictiveObservation {
            action,
            collected_at,
            max_age: Duration::from_secs(max_age_secs),
        }
    }

    fn imminent(minutes_remaining: f64) -> PredictiveAction {
        PredictiveAction::ImminentDanger {
            mount: PathBuf::from("/data"),
            minutes_remaining,
            critical: minutes_remaining <= 2.0,
        }
    }

    #[test]
    fn consecutive_new_samples_keep_a_slow_pass_and_its_queued_clones_current() {
        let started = Instant::now();
        let mut policy = policy();
        let original = policy
            .admit(&action(0.3), started, Duration::from_secs(10), started)
            .unwrap();
        let queued = original.clone();
        for elapsed in [5, 10, 15, 20, 25] {
            let now = started + Duration::from_secs(elapsed);
            policy.observe_samples(&[observation(action(0.2), now, 10)], now);
            assert!(policy.authorize(&original, now).is_ok(), "at {elapsed}s");
            assert!(
                policy.authorize(&queued, now).is_ok(),
                "queued at {elapsed}s"
            );
            assert_eq!(
                queued.min_score(),
                0.3,
                "renewal cannot lower the captured floor"
            );
        }
        assert!(
            policy
                .authorize(&queued, started + Duration::from_secs(34))
                .is_ok()
        );
        assert_eq!(
            policy.authorize(&queued, started + Duration::from_secs(35)),
            Err(SkipReason::PolicyChanged),
            "freshness still expires after observations stop"
        );
    }

    #[test]
    fn repeated_cached_timestamps_do_not_refresh_even_with_a_larger_claimed_max_age() {
        let started = Instant::now();
        let mut policy = policy();
        let queued = policy
            .admit(&action(0.3), started, Duration::from_secs(10), started)
            .unwrap();
        for elapsed in [5, 9] {
            let now = started + Duration::from_secs(elapsed);
            policy.observe_samples(&[observation(action(0.2), started, 60)], now);
            assert!(policy.authorize(&queued, now).is_ok());
        }
        let expired = started + Duration::from_secs(10);
        policy.observe_samples(&[observation(action(0.2), started, 60)], expired);
        assert_eq!(
            policy.authorize(&queued, expired),
            Err(SkipReason::PolicyChanged)
        );
        assert!(policy.active.is_empty());
    }

    #[test]
    fn a_fresh_sample_cannot_revive_an_observation_gap_or_withdrawn_permission() {
        let started = Instant::now();
        for case in ["exact expiry", "gap", "withdrawn", "disabled then restored"] {
            let mut policy = policy();
            let queued = policy
                .admit(&action(0.3), started, Duration::from_secs(10), started)
                .unwrap();
            let elapsed = match case {
                "exact expiry" => 10,
                "gap" => 11,
                "withdrawn" => {
                    policy.revoke_all();
                    5
                }
                _ => {
                    let enabled = PredictionConfig::default();
                    let mut disabled = enabled.clone();
                    disabled.enabled = false;
                    policy.update(&disabled, &ScoringConfig::default());
                    policy.update(&enabled, &ScoringConfig::default());
                    5
                }
            };
            let now = started + Duration::from_secs(elapsed);
            policy.observe_samples(&[observation(action(0.2), now, 10)], now);
            assert_eq!(
                policy.authorize(&queued, now),
                Err(SkipReason::PolicyChanged),
                "{case}"
            );
            let fresh = policy
                .admit(&action(0.2), now, Duration::from_secs(10), now)
                .unwrap();
            assert!(
                policy.authorize(&fresh, now).is_ok(),
                "{case}: fresh work can proceed"
            );
        }
    }

    #[test]
    fn renewed_freshness_never_exceeds_the_original_or_current_shorter_runway() {
        let started = Instant::now();
        let mut original_policy = policy();
        let queued = original_policy
            .admit(&imminent(0.5), started, Duration::from_secs(10), started)
            .unwrap();
        for elapsed in [5, 10, 15, 20, 25] {
            let now = started + Duration::from_secs(elapsed);
            original_policy.observe_samples(&[observation(imminent(1.5), now, 10)], now);
            assert!(original_policy.authorize(&queued, now).is_ok());
        }
        assert!(
            original_policy
                .authorize(&queued, started + Duration::from_secs(29))
                .is_ok()
        );
        let original_deadline = started + Duration::from_secs(30);
        original_policy.observe_samples(
            &[observation(imminent(1.5), original_deadline, 10)],
            original_deadline,
        );
        assert_eq!(
            original_policy.authorize(&queued, original_deadline),
            Err(SkipReason::PolicyChanged)
        );

        let mut policy = policy();
        let queued = policy
            .admit(&imminent(1.0), started, Duration::from_secs(10), started)
            .unwrap();
        let renewed = started + Duration::from_secs(5);
        policy.observe_samples(&[observation(imminent(0.1), renewed, 10)], renewed);
        assert!(
            policy
                .authorize(&queued, started + Duration::from_secs(10))
                .is_ok()
        );
        assert_eq!(
            policy.authorize(&queued, started + Duration::from_secs(11)),
            Err(SkipReason::PolicyChanged),
            "the newer six-second runway ends at t=11s"
        );
    }

    #[test]
    fn invalid_or_missing_samples_revoke_only_their_mount_without_borrowing_peer_freshness() {
        let started = Instant::now();
        let now = started + Duration::from_secs(5);
        for case in [
            "missing",
            "future",
            "stale",
            "zero max age",
            "invalid action",
            "tightened floor",
        ] {
            let mut policy = policy();
            let selected = policy
                .admit(&action(0.3), started, Duration::from_secs(10), started)
                .unwrap();
            let peer_action = action_on("/peer", 0.3);
            let peer = policy
                .admit(&peer_action, started, Duration::from_secs(10), started)
                .unwrap();
            let mut samples = vec![observation(peer_action, now, 10)];
            let mut invalid = observation(action(0.3), now, 10);
            match case {
                "future" => invalid.collected_at = now + Duration::from_secs(1),
                "stale" => {
                    invalid.collected_at = started;
                    invalid.max_age = Duration::from_secs(5);
                }
                "zero max age" => invalid.max_age = Duration::ZERO,
                "invalid action" => invalid.action = action(f64::NAN),
                "tightened floor" => invalid.action = action(0.34),
                _ => {}
            }
            if case != "missing" {
                samples.push(invalid);
            }
            policy.observe_samples(&samples, now);
            assert_eq!(
                policy.authorize(&selected, now),
                Err(SkipReason::PolicyChanged),
                "{case}"
            );
            assert!(
                policy
                    .authorize(&peer, started + Duration::from_secs(11))
                    .is_ok(),
                "{case}"
            );
        }
    }

    #[test]
    fn fresh_observations_do_not_preserve_work_across_a_scoring_reload_round_trip() {
        let started = Instant::now();
        let mut policy = policy();
        let queued = policy
            .admit(&action(0.3), started, Duration::from_secs(10), started)
            .unwrap();
        let now = started + Duration::from_secs(5);
        policy.observe_samples(&[observation(action(0.3), now, 10)], now);
        assert!(policy.authorize(&queued, now).is_ok());
        let scoring = ScoringConfig::default();
        let mut changed = scoring.clone();
        changed.false_positive_loss += 1.0;
        policy.update(&PredictionConfig::default(), &changed);
        policy.update(&PredictionConfig::default(), &scoring);
        let later = started + Duration::from_secs(10);
        policy.observe_samples(&[observation(action(0.3), later, 10)], later);
        assert_eq!(
            policy.authorize(&queued, later),
            Err(SkipReason::PolicyChanged)
        );
    }
}
