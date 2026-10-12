//! Regret labels and regret-calibrated delete thresholds (Q4).
//!
//! A deletion was a mistake when the same directory entry (parent device
//! and inode, name) is recreated within `window` of the deletion while a
//! process with its working directory or an open file under the parent is
//! alive: something was still using it. That is a `regret` outcome; a
//! window that passes with verified absence is `clean`; a recreation with no
//! live user, a late sighting, or an unresolved filesystem observation is
//! `unknown` (not evidence either way).
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
    /// The observation cannot establish either regret or a clean deletion.
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
        if !meta.is_dir() {
            return None;
        }
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

impl Watch {
    /// Observe the original directory entry, asking about live users only
    /// after a successful lookup. A missing entry is evidence only when its
    /// original parent can still be verified.
    #[must_use]
    pub fn observe(&self, parent_in_use: impl FnOnce(&Path) -> bool) -> Sighting {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            let (Some(parent), Some(name)) = (self.path.parent(), self.path.file_name()) else {
                return Sighting::Indeterminate;
            };
            // Anchor the lookup to the opened parent. A pathname swap cannot
            // redirect the entry lookup into a replacement directory.
            let Ok(directory) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent)
            else {
                return Sighting::Indeterminate;
            };
            let Ok(meta) = directory.metadata() else {
                return Sighting::Indeterminate;
            };
            if EntryIdentity::from_parent_meta(&meta, name.to_string_lossy().into_owned())
                != self.identity
            {
                return Sighting::Indeterminate;
            }
            let lookup =
                rustix::fs::statat(&directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map(|_| ())
                    .map_err(std::io::Error::from);
            let sighting = Sighting::from_entry_lookup(lookup, || parent_in_use(parent));
            // The original directory must still occupy the watched path,
            // including after any slower process-table observation.
            if EntryIdentity::of(&self.path).as_ref() != Some(&self.identity) {
                return Sighting::Indeterminate;
            }
            sighting
        }
        #[cfg(not(unix))]
        {
            // EntryIdentity has no stable device/inode implementation here.
            // Do not manufacture evidence from a pathname-only observation.
            let _ = parent_in_use;
            Sighting::Indeterminate
        }
    }
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
pub enum Sighting {
    /// The entry is absent from its verified original parent.
    Absent,
    /// The entry exists again in its verified original parent.
    Recreated {
        /// A process has its cwd or an open file under the parent.
        parent_in_use: bool,
    },
    /// The entry or its original parent could not be observed reliably.
    Indeterminate,
}

impl Sighting {
    #[cfg(unix)]
    fn from_entry_lookup(
        lookup: std::io::Result<()>,
        parent_in_use: impl FnOnce() -> bool,
    ) -> Self {
        match lookup {
            Ok(()) => Self::Recreated {
                parent_in_use: parent_in_use(),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::Absent,
            Err(_) => Self::Indeterminate,
        }
    }
}

/// Watches deletions and labels them.
#[derive(Debug, Clone)]
pub struct RegretDetector {
    window: Duration,
    watches: Vec<PendingWatch>,
}

/// The window in force when this deletion started being observed. Config
/// reloads change future watches without moving an existing deadline.
#[derive(Debug, Clone)]
struct PendingWatch {
    watch: Watch,
    window: Duration,
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

    /// Change the observation window for future deletions. Watches already
    /// pending retain the window with which they were registered.
    pub fn set_window(&mut self, window: Duration) {
        self.window = window;
    }

    /// Start watching a deletion. The identity must have been captured
    /// before the entry was removed.
    pub fn watch(&mut self, watch: Watch) {
        self.watches
            .retain(|pending| pending.watch.decision_id != watch.decision_id);
        self.watches.push(PendingWatch {
            watch,
            window: self.window,
        });
    }

    /// Resolve watches: `look` reports what is at each watched path now.
    /// Recreated entries resolve immediately. A recreation first observed at or
    /// after the deadline is `unknown`: the sighting cannot establish whether
    /// it happened inside the window. Verified absent entries resolve `clean`
    /// when their window passes; indeterminate observations remain pending
    /// until then and expire as `unknown`. Call with the current monotonic time.
    pub fn check(
        &mut self,
        now: Instant,
        mut look: impl FnMut(&Watch) -> Sighting,
    ) -> Vec<DecisionOutcome> {
        let mut outcomes = Vec::new();
        let mut keep = Vec::with_capacity(self.watches.len());
        for PendingWatch { watch, window } in self.watches.drain(..) {
            let age = now.saturating_duration_since(watch.deleted_at);
            let sighting = look(&watch);
            let outcome = match sighting {
                Sighting::Recreated { .. } if age >= window => Some((
                    Outcome::Unknown,
                    "recreation first observed at or after regret window expiry",
                )),
                Sighting::Recreated {
                    parent_in_use: true,
                } => Some((Outcome::Regret, "recreated while a process used the parent")),
                Sighting::Recreated {
                    parent_in_use: false,
                } => Some((
                    Outcome::Unknown,
                    "recreated with no live user under the parent",
                )),
                Sighting::Absent if age >= window => {
                    Some((Outcome::Clean, "window passed without a recreation"))
                }
                Sighting::Indeterminate if age >= window => Some((
                    Outcome::Unknown,
                    "regret window expired without a reliable filesystem observation",
                )),
                Sighting::Absent | Sighting::Indeterminate => None,
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
                None => keep.push(PendingWatch { watch, window }),
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

    /// Apply live settings without losing observed outcomes or shortening
    /// an existing suspension. A changed tolerated rate starts that
    /// category's sequential test afresh: its likelihood was accumulated
    /// against a different null hypothesis.
    pub fn update_config(&mut self, config: RegretConfig) {
        let definite_changed =
            self.config.alpha_definite.to_bits() != config.alpha_definite.to_bits();
        let likely_changed = self.config.alpha_likely.to_bits() != config.alpha_likely.to_bits();
        for stats in self.categories.values_mut() {
            let alpha_changed = if stats.definite_decisions * 2 >= stats.decisions {
                definite_changed
            } else {
                likely_changed
            };
            if alpha_changed {
                stats.e_log = 0.0;
            }
        }
        self.config = config;
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
            // A new alarm may extend an active suspension, but a shorter
            // duration loaded since the previous alarm must not reduce it.
            stats.suspended_until = stats.suspended_until.max(Some(now + self.config.suspend));
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
    fn reconfiguration_preserves_evidence_and_resets_only_changed_nulls() {
        let now = Instant::now();
        let mut calibrator = RegretCalibrator::new(RegretConfig::default());
        for (category, certainty, clean, regrets) in [
            ("rust_target", ArtifactCertainty::Definite, 20, 1),
            ("node_modules", ArtifactCertainty::Likely, 3, 1),
            ("suspended", ArtifactCertainty::Definite, 0, 4),
        ] {
            for _ in 0..clean {
                calibrator.record(category, certainty, Outcome::Clean, now);
            }
            for _ in 0..regrets {
                calibrator.record(category, certainty, Outcome::Regret, now);
            }
        }
        let before = calibrator.categories.clone();
        let rust_before = calibrator.summary("rust_target").unwrap();
        assert!(calibrator.suspended("suspended", now));
        assert_ne!(before["rust_target"].e_log, 0.0);
        assert_ne!(before["node_modules"].e_log, 0.0);

        let mut updated = calibrator.config().clone();
        updated.alpha_definite = 0.04;
        updated.suspend = Duration::from_secs(1);
        calibrator.update_config(updated.clone());
        assert_eq!(calibrator.config(), &updated);
        for (category, original) in &before {
            let current = &calibrator.categories[category];
            assert_eq!(current.decisions, original.decisions);
            assert_eq!(current.regrets, original.regrets);
            assert_eq!(current.definite_decisions, original.definite_decisions);
            assert_eq!(current.suspended_until, original.suspended_until);
        }
        assert_eq!(calibrator.categories["rust_target"].e_log, 0.0);
        assert_eq!(calibrator.categories["suspended"].e_log, 0.0);
        assert_eq!(
            calibrator.categories["node_modules"].e_log,
            before["node_modules"].e_log
        );
        let rust_after = calibrator.summary("rust_target").unwrap();
        assert_eq!(rust_after.alpha, 0.04);
        assert_eq!(rust_after.posterior_mean, rust_before.posterior_mean);
        assert_eq!(rust_after.upper_bound, rust_before.upper_bound);
        assert!(rust_after.calibration > rust_before.calibration);
        assert!(calibrator.suspended("suspended", now + Duration::from_secs(2)));

        calibrator.record(
            "rust_target",
            ArtifactCertainty::Definite,
            Outcome::Clean,
            now,
        );
        // The next likelihood step uses the new alpha: (1 - 4 * .04) /
        // (1 - .04), starting from the reset e-value of one.
        assert!((calibrator.summary("rust_target").unwrap().e_value - 0.875).abs() < 1e-12);

        // Identical rates keep the accumulated likelihood, including a
        // category whose rate was unchanged by the preceding reload.
        let unchanged = calibrator.summaries();
        calibrator.update_config(updated.clone());
        assert_eq!(calibrator.summaries(), unchanged);

        updated.alpha_likely = 0.01;
        calibrator.update_config(updated);
        assert_eq!(calibrator.categories["node_modules"].e_log, 0.0);
        assert_eq!(calibrator.summary("node_modules").unwrap().alpha, 0.01);
    }

    #[test]
    fn reconfiguration_changes_future_suspensions_without_truncating_existing_ones() {
        let now = Instant::now();
        let mut config = RegretConfig {
            suspend: Duration::from_secs(600),
            ..RegretConfig::default()
        };
        let mut calibrator = RegretCalibrator::new(config.clone());
        for _ in 0..3 {
            calibrator.record("old", ArtifactCertainty::Definite, Outcome::Regret, now);
        }
        for _ in 0..2 {
            calibrator.record("future", ArtifactCertainty::Definite, Outcome::Regret, now);
        }
        let future_likelihood = calibrator.summary("future").unwrap().e_value;
        config.suspend = Duration::from_secs(30);
        calibrator.update_config(config);
        assert_eq!(
            calibrator.summary("future").unwrap().e_value,
            future_likelihood
        );
        calibrator.record("future", ArtifactCertainty::Definite, Outcome::Regret, now);
        assert!(calibrator.suspended("future", now + Duration::from_secs(29)));
        assert!(!calibrator.suspended("future", now + Duration::from_secs(30)));
        assert!(calibrator.suspended("old", now + Duration::from_secs(599)));
        assert!(!calibrator.suspended("old", now + Duration::from_secs(600)));
    }

    #[test]
    fn a_shorter_reloaded_suspension_cannot_shorten_an_active_alarm() {
        let now = Instant::now();
        let mut config = RegretConfig {
            suspend: Duration::from_secs(600),
            ..RegretConfig::default()
        };
        let mut calibrator = RegretCalibrator::new(config.clone());
        for _ in 0..3 {
            calibrator.record("active", ArtifactCertainty::Definite, Outcome::Regret, now);
        }
        config.suspend = Duration::from_secs(30);
        calibrator.update_config(config);
        let next_alarm = now + Duration::from_secs(5);
        for category in ["active", "fresh"] {
            for _ in 0..3 {
                calibrator.record(
                    category,
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    next_alarm,
                );
            }
        }
        assert!(calibrator.suspended("fresh", now + Duration::from_secs(34)));
        assert!(!calibrator.suspended("fresh", now + Duration::from_secs(35)));
        assert!(calibrator.suspended("active", now + Duration::from_secs(599)));
        assert!(!calibrator.suspended("active", now + Duration::from_secs(600)));

        // An alarm near the existing deadline must still extend it by the
        // newly configured duration; preserving a deadline cannot freeze it.
        for _ in 0..3 {
            calibrator.record(
                "active",
                ArtifactCertainty::Definite,
                Outcome::Regret,
                now + Duration::from_secs(590),
            );
        }
        assert!(calibrator.suspended("active", now + Duration::from_secs(619)));
        assert!(!calibrator.suspended("active", now + Duration::from_secs(620)));
    }

    #[test]
    fn changed_windows_apply_only_to_new_watches_in_both_directions() {
        let t0 = Instant::now();
        for (old_secs, new_secs, first, last) in [(60, 120, "old", "new"), (120, 60, "new", "old")]
        {
            let old_window = Duration::from_secs(old_secs);
            let new_window = Duration::from_secs(new_secs);
            let mut detector = RegretDetector::new(old_window);
            detector.watch(watch("old", Path::new("/p/old"), "rust_target", t0));
            detector.set_window(new_window);
            detector.watch(watch("new", Path::new("/p/new"), "rust_target", t0));
            let first_deadline = t0 + old_window.min(new_window);
            let mut recreated = detector.clone();
            let before = detector.check(first_deadline - Duration::from_nanos(1), |_| {
                Sighting::Absent
            });
            assert!(before.is_empty());
            let expired = detector.check(first_deadline, |_| Sighting::Absent);
            assert_eq!(expired.len(), 1);
            assert_eq!(expired[0].decision_id, first);
            assert_eq!(expired[0].outcome, Outcome::Clean);
            assert_eq!(detector.pending(), 1);
            let remaining = detector.check(t0 + old_window.max(new_window), |_| Sighting::Absent);
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].decision_id, last);
            assert_eq!(detector.pending(), 0);

            // The same captured windows also govern recreation: extending
            // the config cannot turn an expired old watch into regret, and
            // shortening it cannot expire an old watch early.
            let outcomes = recreated.check(first_deadline, |_| Sighting::Recreated {
                parent_in_use: true,
            });
            assert_eq!(outcomes.len(), 2);
            for outcome in outcomes {
                let expected = if outcome.decision_id == first {
                    Outcome::Unknown
                } else {
                    Outcome::Regret
                };
                assert_eq!(outcome.outcome, expected);
            }
        }
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
        let outcomes = detector.check(t0 + Duration::from_secs(600), |w| {
            if w.path == a || w.path == b {
                Sighting::Recreated {
                    parent_in_use: w.path == a,
                }
            } else {
                Sighting::Absent
            }
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
        let outcomes = detector.check(t0 + Duration::from_mins(30), |_| Sighting::Absent);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, Outcome::Clean);
        assert_eq!(detector.pending(), 0);
    }

    #[test]
    fn detector_recreation_deadline_is_exclusive() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        for (age, active_outcome) in [
            (window - Duration::from_nanos(1), Outcome::Regret),
            (window, Outcome::Unknown),
            (window + Duration::from_nanos(1), Outcome::Unknown),
            (Duration::from_hours(2), Outcome::Unknown),
        ] {
            for parent_in_use in [false, true] {
                let mut detector = RegretDetector::new(window);
                detector.watch(watch("delayed", Path::new("/p/target"), "rust_target", t0));
                let outcomes = detector.check(t0 + age, |_| Sighting::Recreated { parent_in_use });
                assert_eq!(outcomes.len(), 1);
                let expected = if parent_in_use {
                    active_outcome
                } else {
                    Outcome::Unknown
                };
                assert_eq!(
                    outcomes[0].outcome, expected,
                    "age={age:?}, parent_in_use={parent_in_use}"
                );
                assert_eq!(detector.pending(), 0);
            }
        }
    }

    #[test]
    fn detector_absence_remains_pending_before_expiry_and_clean_afterwards() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        let mut detector = RegretDetector::new(window);
        for id in ["at-deadline", "after-deadline"] {
            detector.watch(watch(id, Path::new("/p/target"), "rust_target", t0));
        }
        let before = detector.check(t0 + window - Duration::from_nanos(1), |_| Sighting::Absent);
        assert!(before.is_empty());
        assert_eq!(detector.pending(), 2);

        let at = detector.check(t0 + window, |w| {
            if w.decision_id == "after-deadline" {
                Sighting::Recreated {
                    parent_in_use: false,
                }
            } else {
                Sighting::Absent
            }
        });
        assert_eq!(at.len(), 2);
        let clean = at.iter().find(|o| o.decision_id == "at-deadline").unwrap();
        assert_eq!(clean.outcome, Outcome::Clean);
        assert_eq!(detector.pending(), 0);

        detector.watch(watch(
            "late-absence",
            Path::new("/p/target"),
            "rust_target",
            t0,
        ));
        let after = detector.check(t0 + window + Duration::from_secs(1), |_| Sighting::Absent);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].outcome, Outcome::Clean);
    }

    #[test]
    fn late_recreations_do_not_change_calibration_or_suspension() {
        let t0 = Instant::now();
        for prior_regrets in [0, 3] {
            let mut detector = RegretDetector::new(Duration::from_secs(60));
            let mut calibrator = RegretCalibrator::new(RegretConfig::default());
            calibrator.record(
                "rust_target",
                ArtifactCertainty::Definite,
                Outcome::Clean,
                t0,
            );
            for _ in 0..prior_regrets {
                calibrator.record(
                    "rust_target",
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    t0,
                );
            }
            let before = calibrator.summary("rust_target").unwrap();
            for id in ["late-a", "late-b", "late-c"] {
                detector.watch(watch(id, Path::new("/p/target"), "rust_target", t0));
            }
            let now = t0 + Duration::from_secs(60);
            let outcomes = detector.check(now, |_| Sighting::Recreated {
                parent_in_use: true,
            });
            assert_eq!(outcomes.len(), 3);
            for outcome in outcomes {
                assert_eq!(outcome.outcome, Outcome::Unknown);
                calibrator.record(
                    &outcome.category,
                    certainty_from_name(&outcome.certainty),
                    outcome.outcome,
                    now,
                );
            }
            assert_eq!(calibrator.summary("rust_target").unwrap(), before);
            assert_eq!(calibrator.suspended("rust_target", now), prior_regrets > 0);
        }
    }

    #[test]
    fn indeterminate_observations_expire_unknown_without_changing_calibration() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        for prior_regrets in [0, 3] {
            let mut detector = RegretDetector::new(window);
            let mut calibrator = RegretCalibrator::new(RegretConfig::default());
            calibrator.record(
                "rust_target",
                ArtifactCertainty::Definite,
                Outcome::Clean,
                t0,
            );
            for _ in 0..prior_regrets {
                calibrator.record(
                    "rust_target",
                    ArtifactCertainty::Definite,
                    Outcome::Regret,
                    t0,
                );
            }
            let before = calibrator.summary("rust_target").unwrap();
            detector.watch(watch(
                "unreadable",
                Path::new("/p/target"),
                "rust_target",
                t0,
            ));
            for age in [Duration::ZERO, window - Duration::from_nanos(1)] {
                assert!(
                    detector
                        .check(t0 + age, |_| Sighting::Indeterminate)
                        .is_empty()
                );
                assert_eq!(detector.pending(), 1);
            }
            let now = t0 + window;
            let outcomes = detector.check(now, |_| Sighting::Indeterminate);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome, Outcome::Unknown);
            calibrator.record(
                &outcomes[0].category,
                certainty_from_name(&outcomes[0].certainty),
                outcomes[0].outcome,
                now,
            );
            assert_eq!(calibrator.summary("rust_target").unwrap(), before);
            assert_eq!(calibrator.suspended("rust_target", now), prior_regrets > 0);
            assert_eq!(detector.pending(), 0);
        }
    }

    #[test]
    fn a_reliable_observation_can_resolve_a_previously_indeterminate_watch() {
        let t0 = Instant::now();
        let window = Duration::from_secs(60);
        for (sighting, at, expected) in [
            (Sighting::Absent, t0 + window, Outcome::Clean),
            (
                Sighting::Recreated {
                    parent_in_use: true,
                },
                t0 + Duration::from_secs(30),
                Outcome::Regret,
            ),
        ] {
            let mut detector = RegretDetector::new(window);
            detector.watch(watch("retry", Path::new("/p/target"), "rust_target", t0));
            assert!(detector.check(t0, |_| Sighting::Indeterminate).is_empty());
            let outcomes = detector.check(at, |_| sighting);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome, expected);
            assert_eq!(detector.pending(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_entry_lookups_do_not_become_absence_or_query_processes() {
        use std::io::ErrorKind;

        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::NotADirectory,
            ErrorKind::Interrupted,
            ErrorKind::Other,
        ] {
            let sighting = Sighting::from_entry_lookup(Err(kind.into()), || {
                panic!("failed lookup must not query processes")
            });
            assert_eq!(sighting, Sighting::Indeterminate, "{kind:?}");
        }
        let absent = Sighting::from_entry_lookup(Err(ErrorKind::NotFound.into()), || {
            panic!("absent entry must not query processes")
        });
        assert_eq!(absent, Sighting::Absent);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_observation_verifies_absence_recreation_and_parent_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("project");
        let target = parent.join("target");
        std::fs::create_dir(&parent).unwrap();
        let mut watched = watch("deleted", &target, "rust_target", Instant::now());
        watched.identity = EntryIdentity::of(&target).unwrap();
        assert_eq!(
            watched.observe(|_| panic!("absent entry must not query processes")),
            Sighting::Absent
        );

        std::fs::create_dir(&target).unwrap();
        for parent_in_use in [false, true] {
            assert_eq!(
                watched.observe(|observed_parent| {
                    assert_eq!(observed_parent, parent);
                    parent_in_use
                }),
                Sighting::Recreated { parent_in_use }
            );
        }

        std::fs::rename(&parent, dir.path().join("original-project")).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
        std::fs::create_dir(&parent).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
        std::fs::create_dir(&target).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_observation_rechecks_parent_after_process_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("project");
        let target = parent.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let mut watched = watch("deleted", &target, "rust_target", Instant::now());
        watched.identity = EntryIdentity::of(&target).unwrap();
        let observation = watched.observe(|_| {
            std::fs::rename(&parent, dir.path().join("original-project")).unwrap();
            std::fs::create_dir_all(&target).unwrap();
            true
        });
        assert_eq!(observation, Sighting::Indeterminate);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_observation_accepts_stable_parent_aliases_but_not_retargeting() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let replacement = dir.path().join("replacement");
        let alias = dir.path().join("alias");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        let target = alias.join("target");
        let mut watched = watch("deleted", &target, "rust_target", Instant::now());
        watched.identity = EntryIdentity::of(&target).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Absent);
        std::fs::create_dir(&target).unwrap();
        assert_eq!(
            watched.observe(|_| true),
            Sighting::Recreated {
                parent_in_use: true
            }
        );

        std::fs::rename(&alias, dir.path().join("previous-alias")).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
        std::fs::create_dir(&target).unwrap();
        assert_eq!(watched.observe(|_| true), Sighting::Indeterminate);
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
