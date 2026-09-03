//! Regret labels and regret-calibrated delete thresholds (Q4).
//!
//! A deletion was a mistake when the same directory entry (parent device
//! and inode, name) is recreated within `window` of the deletion while a
//! process with its working directory or an open file under the parent is
//! alive: something was still using it. That is a `regret` outcome; a
//! window that passes without a recreation is `clean`; a recreation with no
//! live user is `unknown` (a later rebuild, not evidence either way).
//!
//! Outcomes calibrate the fast lane per category. Each category keeps a
//! Beta posterior on its regret rate under an empirical-Bayes prior pooled
//! across categories, and reports a Clopper-Pearson upper bound
//! (`delta` 0.05) on that rate. The bound's excess over the tolerated rate
//! (`alpha` 0.02 for Definite-dominated categories, 0.005 otherwise) lowers
//! the category's `calibration` factor, which the decision layer already
//! turns into a higher required posterior for Delete. Zero regrets never
//! tighten anything. A per-category e-process (H0: regret rate <= alpha)
//! suspends only that category's deletions for `suspend` when it alarms.

#![allow(clippy::cast_precision_loss)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::scanner::scoring::ArtifactCertainty;

/// Tunables (`[scoring]` regret keys).
#[derive(Debug, Clone, PartialEq)]
pub struct RegretConfig {
    /// How long after a deletion a recreation counts as regret.
    pub window: Duration,
    /// Tolerated regret rate for a category whose decisions are mostly
    /// Definite.
    pub alpha_definite: f64,
    /// Tolerated regret rate otherwise.
    pub alpha_likely: f64,
    /// Confidence level complement of the Clopper-Pearson bound.
    pub delta: f64,
    /// Strength (pseudo-observations) of the pooled prior.
    pub prior_strength: f64,
    /// E-process alarm threshold (H0: regret rate <= alpha).
    pub e_threshold: f64,
    /// How long an alarm suspends the category's deletions.
    pub suspend: Duration,
}

impl Default for RegretConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_mins(30),
            alpha_definite: 0.02,
            alpha_likely: 0.005,
            delta: 0.05,
            prior_strength: 10.0,
            e_threshold: 20.0,
            suspend: Duration::from_hours(1),
        }
    }
}

/// What became of a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Recreated inside the window while a process used the parent.
    Regret,
    /// The window passed without a recreation.
    Clean,
    /// Recreated with no live user under the parent.
    Unknown,
}

impl Outcome {
    /// The stored outcome for a name (`None` for anything else).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "regret" => Some(Self::Regret),
            "clean" => Some(Self::Clean),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// The stored name of the outcome.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regret => "regret",
            Self::Clean => "clean",
            Self::Unknown => "unknown",
        }
    }
}

/// The identity of a directory entry: its parent's device and inode plus
/// its name. Survives a delete-and-recreate of the entry itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryIdentity {
    /// Device of the parent directory.
    pub parent_device: u64,
    /// Inode of the parent directory.
    pub parent_inode: u64,
    /// The entry's file name within that parent.
    pub name: String,
}

impl EntryIdentity {
    /// The identity of `path` from its parent's metadata; `None` when the
    /// parent cannot be stat'ed or the path has no name.
    #[must_use]
    pub fn of(path: &Path) -> Option<Self> {
        let parent = path.parent()?;
        let name = path.file_name()?.to_string_lossy().into_owned();
        let meta = std::fs::metadata(parent).ok()?;
        Some(Self::from_parent_meta(&meta, name))
    }

    #[cfg(unix)]
    fn from_parent_meta(meta: &std::fs::Metadata, name: String) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            parent_device: meta.dev(),
            parent_inode: meta.ino(),
            name,
        }
    }

    #[cfg(not(unix))]
    fn from_parent_meta(_meta: &std::fs::Metadata, name: String) -> Self {
        Self {
            parent_device: 0,
            parent_inode: 0,
            name,
        }
    }
}

/// A deletion under watch.
#[derive(Debug, Clone)]
pub struct Watch {
    /// The decision that removed the entry.
    pub decision_id: String,
    /// Where the entry was.
    pub path: PathBuf,
    /// The entry's identity, captured before the removal.
    pub identity: EntryIdentity,
    /// Artifact category key (`{:?}` of the classification category).
    pub category: String,
    /// Structural certainty at decision time.
    pub certainty: ArtifactCertainty,
    /// When the entry was removed.
    pub deleted_at: Instant,
}

/// A resolved outcome, ready for the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOutcome {
    /// The decision the outcome belongs to.
    pub decision_id: String,
    /// The deleted entry's original path.
    pub path: PathBuf,
    /// Artifact category key at decision time.
    pub category: String,
    /// `definite`, `likely` or `unclear` at decision time.
    pub certainty: String,
    /// What became of the deletion.
    pub outcome: Outcome,
    /// Unix seconds.
    pub observed_at: u64,
    /// Seconds between the deletion and the observation.
    pub after_secs: u64,
    /// A one-line reason.
    pub detail: String,
}

/// What the detector sees when it looks at a watched path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    /// The entry exists again with the same parent identity.
    pub recreated: bool,
    /// A process has its cwd or an open file under the parent.
    pub parent_in_use: bool,
}

/// Watches deletions and labels them.
#[derive(Debug, Clone)]
pub struct RegretDetector {
    window: Duration,
    watches: Vec<Watch>,
}

impl RegretDetector {
    /// A detector with no watches; `window` is the regret window.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            watches: Vec::new(),
        }
    }

    /// Deletions still under watch.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.watches.len()
    }

    /// Start watching a deletion. The identity must have been captured
    /// before the entry was removed.
    pub fn watch(&mut self, watch: Watch) {
        self.watches.retain(|w| w.decision_id != watch.decision_id);
        self.watches.push(watch);
    }

    /// Resolve watches: `look` reports what is at each watched path now.
    /// Recreated entries resolve immediately; the rest resolve `clean`
    /// when their window passes.
    pub fn check(
        &mut self,
        now: Instant,
        mut look: impl FnMut(&Watch) -> Sighting,
    ) -> Vec<DecisionOutcome> {
        let window = self.window;
        let mut outcomes = Vec::new();
        let mut keep = Vec::with_capacity(self.watches.len());
        for watch in self.watches.drain(..) {
            let age = now.saturating_duration_since(watch.deleted_at);
            let sighting = look(&watch);
            let outcome = if sighting.recreated {
                if sighting.parent_in_use {
                    Some((Outcome::Regret, "recreated while a process used the parent"))
                } else {
                    Some((
                        Outcome::Unknown,
                        "recreated with no live user under the parent",
                    ))
                }
            } else if age >= window {
                Some((Outcome::Clean, "window passed without a recreation"))
            } else {
                None
            };
            match outcome {
                Some((outcome, detail)) => outcomes.push(DecisionOutcome {
                    decision_id: watch.decision_id,
                    path: watch.path,
                    category: watch.category,
                    certainty: certainty_name(watch.certainty).to_string(),
                    outcome,
                    observed_at: now_unix(),
                    after_secs: age.as_secs(),
                    detail: detail.to_string(),
                }),
                None => keep.push(watch),
            }
        }
        self.watches = keep;
        outcomes
    }
}

/// The stored name of a certainty class.
#[must_use]
pub fn certainty_name(certainty: ArtifactCertainty) -> &'static str {
    match certainty {
        ArtifactCertainty::Definite => "definite",
        ArtifactCertainty::Likely => "likely",
        ArtifactCertainty::Unclear => "unclear",
    }
}

/// The certainty class a stored name denotes (`Unclear` for anything else).
#[must_use]
pub fn certainty_from_name(name: &str) -> ArtifactCertainty {
    match name {
        "definite" => ArtifactCertainty::Definite,
        "likely" => ArtifactCertainty::Likely,
        _ => ArtifactCertainty::Unclear,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One category's regret evidence.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CategoryStats {
    /// Resolved outcomes counted as evidence (`regret` or `clean`).
    pub decisions: u64,
    /// Of those, regrets.
    pub regrets: u64,
    /// Of those, decisions whose candidate was Definite.
    pub definite_decisions: u64,
    /// Log e-process value against H0: regret rate <= alpha.
    #[serde(skip)]
    e_log: f64,
    /// Suspension end, if the e-process alarmed.
    #[serde(skip)]
    suspended_until: Option<Instant>,
}

/// The per-category picture the decision layer and `sbh explain` read.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CategoryCalibration {
    /// Artifact category key.
    pub category: String,
    /// Resolved outcomes counted as evidence.
    pub decisions: u64,
    /// Of those, regrets.
    pub regrets: u64,
    /// Tolerated regret rate for the category.
    pub alpha: f64,
    /// Posterior mean regret rate under the pooled prior.
    pub posterior_mean: f64,
    /// Clopper-Pearson upper bound on the regret rate.
    pub upper_bound: f64,
    /// `1 - excess of the bound over alpha`; 1 with no regrets.
    pub calibration: f64,
    /// The category's e-process value against H0: rate <= alpha.
    pub e_value: f64,
    /// Whether the category's deletions are suspended right now.
    pub suspended: bool,
}

/// Regret rates per category with the pooled prior, bounds, calibration
/// factors and suspensions.
#[derive(Debug, Clone)]
pub struct RegretCalibrator {
    config: RegretConfig,
    categories: BTreeMap<String, CategoryStats>,
}

impl RegretCalibrator {
    /// A calibrator with no evidence.
    #[must_use]
    pub fn new(config: RegretConfig) -> Self {
        Self {
            config,
            categories: BTreeMap::new(),
        }
    }

    /// The tunables in force.
    #[must_use]
    pub fn config(&self) -> &RegretConfig {
        &self.config
    }

    /// Record an outcome. `Unknown` outcomes are not evidence.
    pub fn record(
        &mut self,
        category: &str,
        certainty: ArtifactCertainty,
        outcome: Outcome,
        now: Instant,
    ) {
        if outcome == Outcome::Unknown {
            return;
        }
        let alpha = self.alpha_for(category, certainty);
        let stats = self.categories.entry(category.to_string()).or_default();
        stats.decisions += 1;
        if certainty == ArtifactCertainty::Definite {
            stats.definite_decisions += 1;
        }
        // E-process for H0: rate <= alpha against p1 = min(0.5, 4 alpha).
        let p1 = (4.0 * alpha).min(0.5);
        let step = if outcome == Outcome::Regret {
            stats.regrets += 1;
            (p1 / alpha).ln()
        } else {
            ((1.0 - p1) / (1.0 - alpha)).ln()
        };
        stats.e_log = (stats.e_log + step).clamp(-5.0, 6.0);
        if stats.e_log.exp() >= self.config.e_threshold {
            stats.suspended_until = Some(now + self.config.suspend);
            stats.e_log = 0.0;
        }
    }

    /// Rebuild from stored outcomes (daemon start).
    pub fn replay(
        &mut self,
        outcomes: impl IntoIterator<Item = (String, ArtifactCertainty, Outcome)>,
        now: Instant,
    ) {
        for (category, certainty, outcome) in outcomes {
            self.record(&category, certainty, outcome, now);
        }
        // Suspensions are not replayed: an alarm from history has served.
        for stats in self.categories.values_mut() {
            stats.suspended_until = None;
        }
    }

    fn alpha_for(&self, category: &str, certainty: ArtifactCertainty) -> f64 {
        match self.categories.get(category) {
            Some(stats) if stats.decisions > 0 => {
                if stats.definite_decisions * 2 >= stats.decisions {
                    self.config.alpha_definite
                } else {
                    self.config.alpha_likely
                }
            }
            _ if certainty == ArtifactCertainty::Definite => self.config.alpha_definite,
            _ => self.config.alpha_likely,
        }
    }

    /// Pooled prior across categories: mean regret rate with
    /// `prior_strength` pseudo-observations (a half regret keeps it off 0).
    fn prior(&self) -> (f64, f64) {
        let (regrets, decisions) = self
            .categories
            .values()
            .fold((0.0f64, 0.0f64), |(r, n), s| {
                (r + s.regrets as f64, n + s.decisions as f64)
            });
        let mean = ((regrets + 0.5) / (decisions + 1.0)).clamp(1e-4, 0.5);
        let strength = self.config.prior_strength.max(1.0);
        (mean * strength, (1.0 - mean) * strength)
    }

    /// The calibration factor for `category` (1 when unknown).
    #[must_use]
    pub fn calibration(&self, category: &str) -> f64 {
        self.summary(category).map_or(1.0, |c| c.calibration)
    }

    /// Whether `category` is suspended (its e-process alarmed within the
    /// suspension window).
    #[must_use]
    pub fn suspended(&self, category: &str, now: Instant) -> bool {
        self.categories
            .get(category)
            .and_then(|s| s.suspended_until)
            .is_some_and(|until| now < until)
    }

    /// The category's picture, if it has evidence.
    #[must_use]
    pub fn summary(&self, category: &str) -> Option<CategoryCalibration> {
        let stats = self.categories.get(category)?;
        if stats.decisions == 0 {
            return None;
        }
        let alpha = self.alpha_for(category, ArtifactCertainty::Likely);
        let (a0, b0) = self.prior();
        let posterior_mean = (a0 + stats.regrets as f64) / (a0 + b0 + stats.decisions as f64);
        let upper_bound = clopper_pearson_upper(stats.regrets, stats.decisions, self.config.delta);
        let calibration = if stats.regrets == 0 {
            1.0
        } else {
            1.0 - ((upper_bound - alpha).max(0.0) / (1.0 - alpha)).clamp(0.0, 1.0)
        };
        Some(CategoryCalibration {
            category: category.to_string(),
            decisions: stats.decisions,
            regrets: stats.regrets,
            alpha,
            posterior_mean,
            upper_bound,
            calibration,
            e_value: stats.e_log.exp(),
            suspended: stats
                .suspended_until
                .is_some_and(|until| Instant::now() < until),
        })
    }

    /// Every category with evidence.
    #[must_use]
    pub fn summaries(&self) -> Vec<CategoryCalibration> {
        self.categories
            .keys()
            .filter_map(|c| self.summary(c))
            .collect()
    }

    /// The calibration factors by category, for the scoring engine.
    #[must_use]
    pub fn calibrations(&self) -> HashMap<String, f64> {
        self.summaries()
            .into_iter()
            .map(|c| (c.category, c.calibration))
            .collect()
    }
}

/// Clopper-Pearson upper bound on a binomial proportion with `regrets`
/// successes in `decisions` trials at confidence `1 - delta`.
#[must_use]
pub fn clopper_pearson_upper(regrets: u64, decisions: u64, delta: f64) -> f64 {
    if decisions == 0 {
        return 1.0;
    }
    if regrets >= decisions {
        return 1.0;
    }
    let delta = delta.clamp(1e-9, 0.5);
    if regrets == 0 {
        // Closed form: 1 - delta^(1/n).
        return 1.0 - delta.powf(1.0 / decisions as f64);
    }
    let a = regrets as f64 + 1.0;
    let b = (decisions - regrets) as f64;
    beta_quantile(1.0 - delta, a, b)
}

/// The `p` quantile of Beta(a, b) by bisection on the regularized
/// incomplete beta function.
fn beta_quantile(p: f64, a: f64, b: f64) -> f64 {
    let (mut lo, mut hi) = (0.0f64, 1.0f64);
    for _ in 0..80 {
        let mid = f64::midpoint(lo, hi);
        if regularized_incomplete_beta(mid, a, b) < p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    f64::midpoint(lo, hi)
}

/// `I_x(a, b)` by Lentz's continued fraction (Numerical Recipes `betai`).
fn regularized_incomplete_beta(x: f64, a: f64, b: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_front = a.mul_add(
        x.ln(),
        b.mul_add((1.0 - x).ln(), ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b)),
    );
    if x < (a + 1.0) / (a + b + 2.0) {
        ln_front.exp() * beta_continued_fraction(x, a, b) / a
    } else {
        1.0 - ln_front.exp() * beta_continued_fraction(1.0 - x, b, a) / b
    }
}

#[allow(clippy::many_single_char_names)]
fn beta_continued_fraction(x: f64, a: f64, b: f64) -> f64 {
    const TINY: f64 = 1e-300;
    const EPS: f64 = 1e-14;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < TINY {
        d = TINY;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=300 {
        let m = f64::from(m);
        let m2 = 2.0 * m;
        let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = aa.mul_add(d, 1.0);
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        h *= d * c;
        let aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = aa.mul_add(d, 1.0);
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// Lanczos approximation of `ln Γ(x)` for `x > 0`.
fn ln_gamma(x: f64) -> f64 {
    const COEFFICIENTS: [f64; 6] = [
        76.180_091_729_471_46,
        -86.505_320_329_416_77,
        24.014_098_240_830_91,
        -1.231_739_572_450_155,
        0.120_865_097_386_617_9e-2,
        -0.539_523_938_495_3e-5,
    ];
    let mut y = x;
    let tmp = x + 5.5;
    let tmp = (x + 0.5).mul_add(-tmp.ln(), tmp);
    let mut ser = 1.000_000_000_190_015;
    for coefficient in COEFFICIENTS {
        y += 1.0;
        ser += coefficient / y;
    }
    -tmp + (2.506_628_274_631_000_5 * ser / x).ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(id: &str, path: &Path, category: &str, at: Instant) -> Watch {
        Watch {
            decision_id: id.to_string(),
            path: path.to_path_buf(),
            identity: EntryIdentity {
                parent_device: 1,
                parent_inode: 2,
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
            },
            category: category.to_string(),
            certainty: ArtifactCertainty::Definite,
            deleted_at: at,
        }
    }

    #[test]
    fn incomplete_beta_matches_known_values() {
        assert!((regularized_incomplete_beta(0.5, 1.0, 1.0) - 0.5).abs() < 1e-12);
        // I_x(1, b) = 1 - (1 - x)^b.
        assert!(
            (regularized_incomplete_beta(0.3, 1.0, 4.0) - (1.0 - 0.7f64.powi(4))).abs() < 1e-10
        );
        // I_x(a, 1) = x^a.
        assert!((regularized_incomplete_beta(0.6, 3.0, 1.0) - 0.6f64.powi(3)).abs() < 1e-10);
        // Symmetry: I_x(a, b) = 1 - I_{1-x}(b, a).
        let lhs = regularized_incomplete_beta(0.35, 2.5, 4.5);
        let rhs = 1.0 - regularized_incomplete_beta(0.65, 4.5, 2.5);
        assert!((lhs - rhs).abs() < 1e-10, "{lhs} vs {rhs}");
        assert!((ln_gamma(5.0) - 24f64.ln()).abs() < 1e-9);
    }

    #[test]
    fn clopper_pearson_bound_is_monotone_in_count_and_matches_the_closed_forms() {
        assert_eq!(clopper_pearson_upper(0, 0, 0.05), 1.0);
        assert!(
            (clopper_pearson_upper(0, 20, 0.05) - (1.0 - 0.05f64.powf(1.0 / 20.0))).abs() < 1e-12
        );
        assert_eq!(clopper_pearson_upper(5, 5, 0.05), 1.0);
        // One regret in ten: the textbook 95% one-sided upper bound is 0.394.
        let one_in_ten = clopper_pearson_upper(1, 10, 0.05);
        assert!((one_in_ten - 0.3942).abs() < 2e-3, "{one_in_ten}");
        // More trials with the same regrets lower the bound; more regrets raise it.
        let mut previous = 1.0;
        for n in [2u64, 5, 10, 50, 200, 1000] {
            let bound = clopper_pearson_upper(1, n, 0.05);
            assert!(bound < previous, "n={n}: {bound} >= {previous}");
            previous = bound;
        }
        let mut previous = 0.0;
        for k in 0..50u64 {
            let bound = clopper_pearson_upper(k, 50, 0.05);
            assert!(bound > previous, "k={k}: {bound} <= {previous}");
            previous = bound;
        }
    }

    #[test]
    fn zero_regrets_never_tighten_and_ten_percent_tightens_only_its_category() {
        let now = Instant::now();
        let mut calibrator = RegretCalibrator::new(RegretConfig::default());
        for _ in 0..200 {
            calibrator.record(
                "rust_target",
                ArtifactCertainty::Definite,
                Outcome::Clean,
                now,
            );
        }
        assert_eq!(calibrator.calibration("rust_target"), 1.0);
        assert!(!calibrator.suspended("rust_target", now));
        let summary = calibrator.summary("rust_target").unwrap();
        assert!(summary.upper_bound < 0.02, "{summary:?}");

        for i in 0..100 {
            let outcome = if i % 10 == 0 {
                Outcome::Regret
            } else {
                Outcome::Clean
            };
            calibrator.record("node_modules", ArtifactCertainty::Likely, outcome, now);
        }
        let node = calibrator.summary("node_modules").unwrap();
        assert_eq!(node.regrets, 10);
        assert!(node.upper_bound > 0.1 && node.upper_bound < 0.2, "{node:?}");
        assert!(node.calibration < 0.9, "{node:?}");
        assert_eq!(
            calibrator.calibration("rust_target"),
            1.0,
            "another category is untouched"
        );
        assert!((calibrator.calibration("never_seen") - 1.0).abs() < f64::EPSILON);
        let factors = calibrator.calibrations();
        assert_eq!(factors.len(), 2);
        // Unknown outcomes are not evidence.
        calibrator.record(
            "node_modules",
            ArtifactCertainty::Likely,
            Outcome::Unknown,
            now,
        );
        assert_eq!(calibrator.summary("node_modules").unwrap().decisions, 100);
    }

    #[test]
    fn a_run_of_regrets_suspends_only_that_category_for_the_configured_time() {
        let now = Instant::now();
        let config = RegretConfig {
            suspend: Duration::from_mins(10),
            ..RegretConfig::default()
        };
        let mut calibrator = RegretCalibrator::new(config);
        calibrator.record(
            "rust_target",
            ArtifactCertainty::Definite,
            Outcome::Clean,
            now,
        );
        for _ in 0..3 {
            calibrator.record("pip_cache", ArtifactCertainty::Likely, Outcome::Regret, now);
        }
        assert!(
            calibrator.suspended("pip_cache", now),
            "{:?}",
            calibrator.summary("pip_cache")
        );
        assert!(!calibrator.suspended("rust_target", now));
        assert!(!calibrator.suspended("pip_cache", now + Duration::from_secs(601)));
        // Replay from the ledger rebuilds the counts but not the suspension.
        let mut rebuilt = RegretCalibrator::new(RegretConfig::default());
        rebuilt.replay(
            (0..3).map(|_| {
                (
                    "pip_cache".to_string(),
                    ArtifactCertainty::Likely,
                    Outcome::Regret,
                )
            }),
            now,
        );
        assert_eq!(rebuilt.summary("pip_cache").unwrap().regrets, 3);
        assert!(!rebuilt.suspended("pip_cache", now));
    }

    #[test]
    fn detector_labels_recreation_in_use_as_regret_and_expiry_as_clean() {
        let t0 = Instant::now();
        let mut detector = RegretDetector::new(Duration::from_mins(30));
        let a = PathBuf::from("/p/a/target");
        let b = PathBuf::from("/p/b/target");
        let c = PathBuf::from("/p/c/target");
        detector.watch(watch("d-a", &a, "rust_target", t0));
        detector.watch(watch("d-b", &b, "rust_target", t0));
        detector.watch(watch("d-c", &c, "rust_target", t0));
        assert_eq!(detector.pending(), 3);
        // Ten minutes in: a is back with a live user, b is back unused,
        // c is still gone.
        let outcomes = detector.check(t0 + Duration::from_secs(600), |w| Sighting {
            recreated: w.path == a || w.path == b,
            parent_in_use: w.path == a,
        });
        assert_eq!(outcomes.len(), 2);
        let by_id: HashMap<_, _> = outcomes
            .iter()
            .map(|o| (o.decision_id.as_str(), o))
            .collect();
        assert_eq!(by_id["d-a"].outcome, Outcome::Regret);
        assert_eq!(by_id["d-b"].outcome, Outcome::Unknown);
        assert_eq!(by_id["d-a"].after_secs, 600);
        assert_eq!(detector.pending(), 1);
        // The window passes for c.
        let outcomes = detector.check(t0 + Duration::from_mins(30), |_| Sighting {
            recreated: false,
            parent_in_use: true,
        });
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, Outcome::Clean);
        assert_eq!(detector.pending(), 0);
    }

    #[test]
    fn entry_identity_survives_recreation_of_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let before = EntryIdentity::of(&target).unwrap();
        std::fs::remove_dir(&target).unwrap();
        std::fs::create_dir(&target).unwrap();
        let after = EntryIdentity::of(&target).unwrap();
        assert_eq!(before, after);
        assert_eq!(before.name, "target");
        assert!(EntryIdentity::of(Path::new("/")).is_none());
    }
}
