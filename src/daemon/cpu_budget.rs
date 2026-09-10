//! Q7: the daemon's CPU budget as one invariant across threads.
//!
//! One token bucket holds CPU-seconds. It refills from wall time at
//! `pct/100` of one core and drains by the process's own CPU time (rusage
//! deltas), so it charges everything the daemon does: scanner passes, the
//! priority pre-scan, maintenance passes, index work and the monitor tick.
//! When the bucket is in deficit the monitor loop stretches its sleep; the
//! scanner starts a discretionary pass only with at least
//! [`PASS_MIN_TOKENS`] in the bucket and may then spend only as much CPU as
//! the bucket holds ([`CpuBudget::pass_cpu_allowance`]), *measured* while the
//! pass runs by [`PassCpuGuard`]. Documented bound: over any window of `w`
//! seconds the daemon's CPU time is at most `pct/100 * w + burst`, plus
//! what the protected operations and the executor cost.
//!
//! # Why the allowance is measured and not modelled
//!
//! Until 0.6.1 the allowance was converted to a *wall-clock* deadline as
//! `available_cpu_secs / scanner.parallelism`, i.e. assuming every walker
//! thread pegs a core for the whole pass. Two things made that catastrophic
//! in practice:
//!
//! * the bucket is clamped to `burst` (5 CPU-seconds by default), so the
//!   converted wall deadline had a hard ceiling of `burst / parallelism` —
//!   **0.6-0.7 s on a 14-16 core host** — that no amount of idling could
//!   raise; and
//! * a directory walk is I/O- and syscall-bound, and the priority pre-scan
//!   that the deadline actually killed is *single-threaded*, so dividing by
//!   the thread count was wrong twice over.
//!
//! The observable result was a daemon that logged
//! `scan complete: 0 entries, 0 candidates, 0.7s (timed out)` on every pass
//! for months while the disk filled. Charging the pass its *real* rusage
//! delta keeps the same documented CPU bound, exactly rather than
//! pessimistically, and lets an I/O-bound walk run to
//! `scanner.scan_time_budget_secs`.
//!
//! Protected operations never wait on the budget: ballast release, the
//! state write, the service-manager heartbeat and signal handling keep
//! their cadence because the per-tick yield is capped below the shortest
//! of those cadences, and Critical pressure disables yielding entirely
//! (disk safety wins). Operator and config-reload scans bypass it too.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::monitor::pid::PressureLevel;

/// Default CPU-seconds the bucket can hold.
///
/// Short bursts (a pre-scan, an index load) run at full speed; sustained
/// work is paced at the budget rate. Overridable per host with
/// `telemetry.cpu_budget_burst_secs`.
pub const BURST_SECS: f64 = 5.0;

/// Floor for a configured burst. Below a CPU-second the bucket could never
/// satisfy [`PASS_MIN_TOKENS`] and no discretionary pass would ever start.
pub const MIN_BURST_SECS: f64 = PASS_MIN_TOKENS;

/// Ceiling for a configured burst, so a typo cannot hand the scanner an
/// effectively unbounded CPU allowance.
pub const MAX_BURST_SECS: f64 = 600.0;

/// Longest a single monitor tick stretches its sleep for the budget.
///
/// Kept well under the state-write interval (30 s) and the default watchdog
/// heartbeat so the protected operations never miss their cadence.
pub const MAX_TICK_YIELD: Duration = Duration::from_secs(10);

/// Deepest deficit the bucket records. Bounds how long a single very
/// expensive pass can hold the daemon back afterwards.
pub const MAX_DEFICIT_SECS: f64 = 60.0;

/// CPU-seconds a discretionary scan pass needs in the bucket before it may
/// start; below this the scanner waits for the refill instead of running a
/// pass that would be cut short at once.
pub const PASS_MIN_TOKENS: f64 = 1.0;

/// The "budget exceeded" line is logged at most this often.
pub const EXCEEDED_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Consecutive over-budget minutes before a Warning notification, and the
/// spacing of repeats while the condition persists.
pub const WARNING_AFTER_MINUTES: u32 = 5;

const WINDOW: Duration = Duration::from_secs(60);

/// What `sbh status` and `state.json` show about the budget.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CpuBudgetState {
    /// Budget as percent of one core (0 = disabled).
    pub pct: u8,
    /// CPU used over the last minute as percent of one core.
    pub used_pct_1m: f64,
    /// CPU-seconds the daemon is over budget right now (0 when within it).
    pub deficit_secs: f64,
    /// Consecutive whole minutes the daemon has been over budget.
    pub over_budget_minutes: u32,
}

/// What one observation asks the caller to do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetTick {
    /// Log the once-per-minute "cpu budget exceeded" line now.
    pub log_exceeded: bool,
    /// Raise the Warning notification: the number of consecutive minutes
    /// over budget.
    pub warn_after_minutes: Option<u32>,
}

/// The token bucket. One instance per daemon, observed by the monitor loop
/// and read by the scanner.
#[derive(Debug, Clone)]
pub struct CpuBudget {
    pct: u8,
    burst_secs: f64,
    tokens: f64,
    last_wall: Instant,
    last_cpu_secs: f64,
    created: Instant,
    samples: VecDeque<(Instant, f64)>,
    last_exceeded_log: Option<Instant>,
    minute_started: Instant,
    minute_over: bool,
    over_budget_minutes: u32,
    warned_at_minutes: u32,
}

impl CpuBudget {
    /// A full bucket at `pct` percent of one core, calibrated to the
    /// process's current CPU time so earlier startup work is not charged.
    #[must_use]
    pub fn new(pct: u8, now: Instant, cpu_secs: f64) -> Self {
        Self {
            pct: pct.min(100),
            burst_secs: BURST_SECS,
            tokens: BURST_SECS,
            last_wall: now,
            last_cpu_secs: cpu_secs,
            created: now,
            samples: VecDeque::new(),
            last_exceeded_log: None,
            minute_started: now,
            minute_over: false,
            over_budget_minutes: 0,
            warned_at_minutes: 0,
        }
    }

    /// Budget percent of one core; 0 disables pacing (accounting continues).
    #[must_use]
    pub const fn pct(&self) -> u8 {
        self.pct
    }

    /// Change the budget (config reload) without losing the accounting.
    pub fn set_pct(&mut self, pct: u8) {
        self.pct = pct.min(100);
    }

    /// A bucket at `pct` percent of one core holding `burst` CPU-seconds.
    ///
    /// `burst` is clamped to `[MIN_BURST_SECS, MAX_BURST_SECS]`: a burst
    /// under [`PASS_MIN_TOKENS`] would stop every discretionary pass from
    /// ever starting.
    #[must_use]
    pub fn with_burst_secs(mut self, burst_secs: f64) -> Self {
        self.set_burst_secs(burst_secs);
        self.tokens = self.burst_secs;
        self
    }

    /// Change the burst depth (config reload), keeping the current balance
    /// but never above the new depth.
    pub fn set_burst_secs(&mut self, burst_secs: f64) {
        let burst = if burst_secs.is_finite() {
            burst_secs.clamp(MIN_BURST_SECS, MAX_BURST_SECS)
        } else {
            BURST_SECS
        };
        self.burst_secs = burst;
        self.tokens = self.tokens.min(burst);
    }

    /// CPU-seconds the bucket can hold.
    #[must_use]
    pub const fn burst_secs(&self) -> f64 {
        self.burst_secs
    }

    /// Whether pacing is on (a zero budget only keeps the accounting).
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.pct > 0
    }

    /// Refill rate in CPU-seconds per wall-second.
    #[must_use]
    pub fn rate(&self) -> f64 {
        f64::from(self.pct) / 100.0
    }

    /// CPU-seconds currently over budget (0 while within it).
    #[must_use]
    pub fn deficit_secs(&self) -> f64 {
        (-self.tokens).max(0.0)
    }

    /// CPU-seconds the bucket still holds (0 while in deficit): what a pass
    /// starting now may spend before the budget cuts it short.
    #[must_use]
    pub fn available_secs(&self) -> f64 {
        self.tokens.max(0.0)
    }

    /// What a discretionary scan pass may spend right now, in **CPU**-seconds:
    /// `None` means no limit (budget disabled, or Critical pressure),
    /// `Some(0.0)` means do not start (fewer than [`PASS_MIN_TOKENS`]
    /// CPU-seconds in the bucket), otherwise the CPU-seconds in the bucket.
    ///
    /// The caller charges the pass its measured rusage delta through
    /// [`PassCpuGuard`] rather than converting this to a wall deadline; see
    /// the module docs for why the conversion was the bug that kept the
    /// scanner to 0.7 s passes.
    #[must_use]
    pub fn pass_cpu_allowance(&self, level: PressureLevel) -> Option<f64> {
        if !self.enabled() || level >= PressureLevel::Critical {
            return None;
        }
        let available = self.available_secs();
        if available < PASS_MIN_TOKENS {
            return Some(0.0);
        }
        Some(available)
    }

    /// Account for the wall time since the last observation and the CPU the
    /// process spent in it. `cpu_secs` is the process's cumulative user +
    /// system time.
    pub fn observe(&mut self, now: Instant, cpu_secs: f64) -> BudgetTick {
        let wall = now.saturating_duration_since(self.last_wall).as_secs_f64();
        let used = (cpu_secs - self.last_cpu_secs).max(0.0);
        self.last_wall = now;
        self.last_cpu_secs = cpu_secs;

        self.tokens = (wall.mul_add(self.rate(), self.tokens) - used)
            .clamp(-MAX_DEFICIT_SECS, self.burst_secs);

        self.samples.push_back((now, used));
        while self
            .samples
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > WINDOW)
        {
            self.samples.pop_front();
        }

        let mut tick = BudgetTick::default();
        if !self.enabled() {
            self.minute_over = false;
            self.over_budget_minutes = 0;
            self.warned_at_minutes = 0;
            return tick;
        }
        if self.tokens < 0.0 {
            self.minute_over = true;
            if self
                .last_exceeded_log
                .is_none_or(|at| now.saturating_duration_since(at) >= EXCEEDED_LOG_INTERVAL)
            {
                self.last_exceeded_log = Some(now);
                tick.log_exceeded = true;
            }
        }
        if now.saturating_duration_since(self.minute_started) >= WINDOW {
            self.minute_started = now;
            if self.minute_over {
                self.over_budget_minutes = self.over_budget_minutes.saturating_add(1);
            } else {
                self.over_budget_minutes = 0;
                self.warned_at_minutes = 0;
            }
            self.minute_over = false;
            if self.over_budget_minutes >= WARNING_AFTER_MINUTES
                && self
                    .over_budget_minutes
                    .saturating_sub(self.warned_at_minutes)
                    >= WARNING_AFTER_MINUTES
            {
                self.warned_at_minutes = self.over_budget_minutes;
                tick.warn_after_minutes = Some(self.over_budget_minutes);
            }
        }
        tick
    }

    /// How long discretionary work should wait: the time the bucket needs
    /// to refill out of its deficit, capped at `cap`. Zero while within
    /// budget, when the budget is disabled, and at Critical pressure.
    #[must_use]
    pub fn yield_for(&self, level: PressureLevel, cap: Duration) -> Duration {
        if !self.enabled() || level >= PressureLevel::Critical || self.tokens >= 0.0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64(self.deficit_secs() / self.rate()).min(cap)
    }

    /// CPU used over the last minute as percent of one core.
    #[must_use]
    pub fn used_pct_1m(&self, now: Instant) -> f64 {
        let used: f64 = self.samples.iter().map(|(_, cpu)| cpu).sum();
        let window = now
            .saturating_duration_since(self.created)
            .min(WINDOW)
            .as_secs_f64();
        if window <= 0.0 {
            return 0.0;
        }
        used / window * 100.0
    }

    /// The budget as `state.json` and `sbh status` show it.
    #[must_use]
    pub fn snapshot(&self, now: Instant) -> CpuBudgetState {
        CpuBudgetState {
            pct: self.pct,
            used_pct_1m: self.used_pct_1m(now),
            deficit_secs: self.deficit_secs(),
            over_budget_minutes: self.over_budget_minutes,
        }
    }
}

/// How often [`PassCpuGuard`] re-reads the process's CPU time.
///
/// Reading it costs a `/proc` open (Linux) or a Mach call (macOS), and the
/// scanner asks the guard on every directory entry, so the answer is cached
/// for this long. The overshoot that permits is bounded by the CPU the
/// daemon can burn in one interval, far under the burst.
pub const CPU_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Charges a single scan pass its **measured** CPU time against the
/// allowance [`CpuBudget::pass_cpu_allowance`] handed out when the pass
/// started.
///
/// The guard latches: once the allowance is spent it keeps reporting
/// exhausted without re-sampling, so the pass unwinds through its nested
/// loops with one verdict rather than flapping.
pub struct PassCpuGuard {
    allowance_secs: Option<f64>,
    baseline_secs: Option<f64>,
    spent_secs: f64,
    last_sample: Instant,
    sample_interval: Duration,
    exhausted: bool,
    sampler: Box<dyn FnMut() -> Option<f64> + Send>,
}

impl std::fmt::Debug for PassCpuGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassCpuGuard")
            .field("allowance_secs", &self.allowance_secs)
            .field("spent_secs", &self.spent_secs)
            .field("exhausted", &self.exhausted)
            .finish_non_exhaustive()
    }
}

impl PassCpuGuard {
    /// A guard over `allowance_secs` CPU-seconds (`None` = unlimited),
    /// reading the process's cumulative user+system CPU seconds from
    /// `sampler`. A sampler that returns `None` (the platform cannot report
    /// CPU time) makes the guard inert: the pass is then bounded by its wall
    /// budget alone, which is the safe direction — the old code's failure was
    /// stopping too early, not too late.
    pub fn new(
        allowance_secs: Option<f64>,
        now: Instant,
        mut sampler: impl FnMut() -> Option<f64> + Send + 'static,
    ) -> Self {
        let baseline_secs = sampler();
        Self {
            allowance_secs,
            baseline_secs,
            spent_secs: 0.0,
            last_sample: now,
            sample_interval: CPU_SAMPLE_INTERVAL,
            exhausted: false,
            sampler: Box::new(sampler),
        }
    }

    /// An inert guard: no allowance, nothing to sample. Used for operator
    /// and config-reload scans, which bypass the budget by contract.
    #[must_use]
    pub fn unlimited(now: Instant) -> Self {
        Self::new(None, now, || None)
    }

    /// Override the sampling interval (tests drive the clock directly).
    #[must_use]
    pub const fn with_sample_interval(mut self, interval: Duration) -> Self {
        self.sample_interval = interval;
        self
    }

    /// CPU-seconds this pass may spend in total, if it is limited at all.
    #[must_use]
    pub const fn allowance_secs(&self) -> Option<f64> {
        self.allowance_secs
    }

    /// CPU-seconds charged to this pass so far (as of the last sample).
    #[must_use]
    pub const fn spent_secs(&self) -> f64 {
        self.spent_secs
    }

    /// Whether the pass has spent its CPU allowance, re-sampling at most
    /// once per [`CPU_SAMPLE_INTERVAL`].
    pub fn exhausted(&mut self, now: Instant) -> bool {
        if self.exhausted {
            return true;
        }
        let Some(allowance) = self.allowance_secs else {
            return false;
        };
        if self.baseline_secs.is_none() {
            return false;
        }
        if now.saturating_duration_since(self.last_sample) < self.sample_interval {
            return false;
        }
        self.last_sample = now;
        self.sample();
        self.exhausted = self.spent_secs >= allowance;
        self.exhausted
    }

    /// Read the sampler once and update `spent_secs` (no latching).
    fn sample(&mut self) {
        let (Some(baseline), Some(current)) = (self.baseline_secs, (self.sampler)()) else {
            return;
        };
        self.spent_secs = (current - baseline).max(0.0);
    }

    /// Final accounting for the pass, ignoring the sampling interval. Call
    /// once when the pass ends so the reported figure is the whole pass.
    pub fn finish(&mut self) -> f64 {
        self.sample();
        self.spent_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(pct: u8) -> (CpuBudget, Instant) {
        let now = Instant::now();
        (CpuBudget::new(pct, now, 100.0), now)
    }

    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    #[test]
    fn refills_from_wall_time_and_drains_by_cpu_deltas() {
        let (mut b, t0) = budget(25);
        // 5 s burst, 4 s of wall refill 1 s, 2 s of CPU used: 5 + 1 - 2 = 4.
        b.observe(t0 + secs(4.0), 102.0);
        assert!((b.tokens - 4.0).abs() < 1e-9, "{}", b.tokens);
        assert_eq!(b.deficit_secs(), 0.0);
        // The bucket never holds more than the burst.
        b.observe(t0 + secs(100.0), 102.0);
        assert!((b.tokens - BURST_SECS).abs() < 1e-9);
        // A 20 s CPU burn over 4 s of wall: 5 + 1 - 20 = -14 deficit.
        b.observe(t0 + secs(104.0), 122.0);
        assert!(
            (b.deficit_secs() - 14.0).abs() < 1e-9,
            "{}",
            b.deficit_secs()
        );
        // The deficit is bounded.
        b.observe(t0 + secs(105.0), 400.0);
        assert!((b.deficit_secs() - MAX_DEFICIT_SECS).abs() < 1e-9);
    }

    #[test]
    fn yield_is_the_refill_time_capped_and_zero_within_budget() {
        let (mut b, t0) = budget(25);
        assert_eq!(
            b.yield_for(PressureLevel::Green, MAX_TICK_YIELD),
            Duration::ZERO
        );
        b.observe(t0 + secs(1.0), 110.0); // 5 + 0.25 - 10 = -4.75
        let want = 4.75 / 0.25;
        let got = b.yield_for(PressureLevel::Orange, secs(60.0)).as_secs_f64();
        assert!((got - want).abs() < 1e-6, "{got} vs {want}");
        assert_eq!(
            b.yield_for(PressureLevel::Orange, MAX_TICK_YIELD),
            MAX_TICK_YIELD
        );
    }

    #[test]
    fn pass_cpu_allowance_is_the_bucket_balance_not_a_wall_deadline() {
        let (mut b, t0) = budget(25);
        // A full bucket is 5 CPU-seconds, whatever the walker's thread count.
        let full = b.pass_cpu_allowance(PressureLevel::Green).unwrap();
        assert!((full - BURST_SECS).abs() < 1e-9, "{full}");
        // Nearly empty: the pass must not start until a CPU-second is back.
        b.observe(t0 + secs(1.0), 104.5); // 5 + 0.25 - 4.5 = 0.75
        assert!(b.available_secs() < PASS_MIN_TOKENS);
        assert_eq!(b.pass_cpu_allowance(PressureLevel::Orange), Some(0.0));
        b.observe(t0 + secs(3.0), 104.5); // +0.5 refill -> 1.25
        let short = b.pass_cpu_allowance(PressureLevel::Orange).unwrap();
        assert!((short - 1.25).abs() < 1e-9, "{short}");
        // Critical and a disabled budget never limit a pass.
        assert_eq!(b.pass_cpu_allowance(PressureLevel::Critical), None);
        let (off, _) = budget(0);
        assert_eq!(off.pass_cpu_allowance(PressureLevel::Green), None);
    }

    /// The regression this whole change exists for: the old allowance was
    /// `available_cpu_secs / parallelism` **as wall time**, and because the
    /// bucket is clamped to the burst that gave a hard ceiling of
    /// `burst / parallelism` seconds — 0.625 s on a 16-core host at the
    /// default `parallelism = cores / 2`. A pass can now spend the whole
    /// bucket regardless of how many walker threads there are.
    #[test]
    fn allowance_no_longer_shrinks_with_the_thread_count() {
        let (b, _) = budget(25);
        let allowance = b.pass_cpu_allowance(PressureLevel::Orange).unwrap();
        // The value the fleet observed as a 0.7 s wall deadline.
        let legacy_wall_ceiling = BURST_SECS / 8.0;
        assert!(
            legacy_wall_ceiling < 1.0,
            "the legacy conversion really did produce a sub-second budget: {legacy_wall_ceiling}"
        );
        assert!(
            allowance >= PASS_MIN_TOKENS,
            "a full bucket must fund a real pass, got {allowance}"
        );
        assert!((allowance - BURST_SECS).abs() < 1e-9, "{allowance}");
    }

    #[test]
    fn burst_is_configurable_and_clamped() {
        let now = Instant::now();
        let wide = CpuBudget::new(25, now, 0.0).with_burst_secs(120.0);
        assert!((wide.burst_secs() - 120.0).abs() < 1e-9);
        assert!(
            (wide.pass_cpu_allowance(PressureLevel::Green).unwrap() - 120.0).abs() < 1e-9,
            "a wider bucket funds a longer pass"
        );
        // Below PASS_MIN_TOKENS no pass could ever start, so it is clamped up.
        let tiny = CpuBudget::new(25, now, 0.0).with_burst_secs(0.05);
        assert!((tiny.burst_secs() - MIN_BURST_SECS).abs() < 1e-9);
        let huge = CpuBudget::new(25, now, 0.0).with_burst_secs(1.0e9);
        assert!((huge.burst_secs() - MAX_BURST_SECS).abs() < 1e-9);
        let nan = CpuBudget::new(25, now, 0.0).with_burst_secs(f64::NAN);
        assert!((nan.burst_secs() - BURST_SECS).abs() < 1e-9);
        // A reload that narrows the bucket also caps the balance.
        let mut narrowed = wide;
        narrowed.set_burst_secs(2.0);
        assert!(narrowed.available_secs() <= 2.0 + 1e-9);
    }

    #[test]
    fn pass_guard_charges_measured_cpu_and_latches() {
        let t0 = Instant::now();
        let cpu = std::sync::Arc::new(std::sync::Mutex::new(10.0_f64));
        let handle = std::sync::Arc::clone(&cpu);
        let mut guard = PassCpuGuard::new(Some(2.0), t0, move || Some(*handle.lock().unwrap()))
            .with_sample_interval(Duration::from_millis(100));
        // Within the sample interval the guard does not even look.
        *cpu.lock().unwrap() = 99.0;
        assert!(!guard.exhausted(t0 + Duration::from_millis(50)));
        // Half the allowance spent: keep going.
        *cpu.lock().unwrap() = 11.0;
        assert!(!guard.exhausted(t0 + Duration::from_millis(200)));
        assert!((guard.spent_secs() - 1.0).abs() < 1e-9);
        // Over the allowance: exhausted, and it stays exhausted even if the
        // sampler goes backwards.
        *cpu.lock().unwrap() = 12.5;
        assert!(guard.exhausted(t0 + Duration::from_millis(400)));
        *cpu.lock().unwrap() = 10.0;
        assert!(guard.exhausted(t0 + Duration::from_millis(4000)));
    }

    /// An I/O-bound walk burns almost no CPU, so the guard must let it run.
    /// This is exactly the fleet case: enumerating a 100 GB `/data/projects`
    /// is syscall- and disk-bound, and the old model charged it as though
    /// every walker thread pegged a core.
    #[test]
    fn pass_guard_lets_an_io_bound_pass_run_long() {
        let t0 = Instant::now();
        let cpu = std::sync::Arc::new(std::sync::Mutex::new(0.0_f64));
        let handle = std::sync::Arc::clone(&cpu);
        let mut guard = PassCpuGuard::new(Some(5.0), t0, move || Some(*handle.lock().unwrap()))
            .with_sample_interval(Duration::from_millis(100));
        // 120 seconds of wall time at 2% of a core.
        for tick in 1_u64..=120 {
            #[allow(clippy::cast_precision_loss)]
            let cpu_secs = tick as f64 * 0.02;
            *cpu.lock().unwrap() = cpu_secs;
            assert!(
                !guard.exhausted(t0 + Duration::from_secs(tick)),
                "an I/O-bound pass must not be cut at t={tick}s"
            );
        }
        assert!(guard.finish() < 5.0);
    }

    #[test]
    fn pass_guard_is_inert_without_an_allowance_or_a_sampler() {
        let t0 = Instant::now();
        let mut unlimited = PassCpuGuard::unlimited(t0);
        assert!(!unlimited.exhausted(t0 + Duration::from_secs(3600)));
        assert_eq!(unlimited.allowance_secs(), None);
        // A platform that cannot report CPU time must not stop the pass.
        let mut blind = PassCpuGuard::new(Some(0.001), t0, || None)
            .with_sample_interval(Duration::from_millis(1));
        assert!(!blind.exhausted(t0 + Duration::from_secs(60)));
    }

    #[test]
    fn critical_pressure_and_a_disabled_budget_never_yield() {
        let (mut b, t0) = budget(25);
        b.observe(t0 + secs(1.0), 150.0);
        assert!(b.deficit_secs() > 0.0);
        assert_eq!(
            b.yield_for(PressureLevel::Critical, MAX_TICK_YIELD),
            Duration::ZERO
        );
        assert_ne!(
            b.yield_for(PressureLevel::Red, MAX_TICK_YIELD),
            Duration::ZERO
        );

        let (mut off, t0) = budget(0);
        let tick = off.observe(t0 + secs(1.0), 150.0);
        assert_eq!(
            off.yield_for(PressureLevel::Green, MAX_TICK_YIELD),
            Duration::ZERO
        );
        assert!(!tick.log_exceeded);
        assert!(!off.enabled());
    }

    #[test]
    fn exceeded_line_is_logged_at_most_once_a_minute() {
        let (mut b, t0) = budget(10);
        assert!(b.observe(t0 + secs(1.0), 120.0).log_exceeded);
        assert!(!b.observe(t0 + secs(2.0), 121.0).log_exceeded);
        assert!(!b.observe(t0 + secs(59.0), 122.0).log_exceeded);
        assert!(b.observe(t0 + secs(61.0), 123.0).log_exceeded);
    }

    #[test]
    fn warning_after_five_consecutive_over_budget_minutes_then_every_five() {
        let (mut b, t0) = budget(10);
        let mut cpu = 100.0;
        let mut warnings = Vec::new();
        // One observation per second, burning 0.5 s CPU each (5x the budget).
        for s in 1..=(60 * 12) {
            cpu += 0.5;
            let tick = b.observe(t0 + secs(f64::from(s)), cpu);
            if let Some(minutes) = tick.warn_after_minutes {
                warnings.push((s, minutes));
            }
        }
        assert_eq!(
            warnings.iter().map(|(_, m)| *m).collect::<Vec<_>>(),
            vec![5, 10],
            "{warnings:?}"
        );
        assert_eq!(b.snapshot(t0 + secs(720.0)).over_budget_minutes, 12);
        // A minute within budget resets the streak. The deficit is capped at
        // MAX_DEFICIT_SECS, so 700 s at 10% is enough to refill it.
        let quiet = t0 + secs(720.0 + 700.0);
        b.observe(quiet, cpu);
        assert_eq!(b.snapshot(quiet).over_budget_minutes, 0);
    }

    #[test]
    fn used_pct_covers_the_last_minute_only() {
        let (mut b, t0) = budget(25);
        b.observe(t0 + secs(30.0), 106.0); // 6 s in 30 s
        let pct = b.used_pct_1m(t0 + secs(30.0));
        assert!((pct - 20.0).abs() < 1e-6, "{pct}");
        b.observe(t0 + secs(120.0), 106.0); // the old sample ages out
        assert_eq!(b.used_pct_1m(t0 + secs(120.0)), 0.0);
        assert_eq!(b.snapshot(t0 + secs(120.0)).pct, 25);
    }

    #[test]
    fn reload_changes_the_rate_without_losing_the_deficit() {
        let (mut b, t0) = budget(25);
        b.observe(t0 + secs(1.0), 120.0);
        let before = b.deficit_secs();
        b.set_pct(50);
        assert_eq!(b.pct(), 50);
        assert!((b.deficit_secs() - before).abs() < 1e-9);
        assert!(b.yield_for(PressureLevel::Green, secs(1000.0)) < secs(before / 0.25));
    }

    proptest::proptest! {
        /// For any sequence of pressure levels, wall steps and CPU deltas the
        /// per-tick yield never exceeds its cap (so the protected operations
        /// keep their cadence), is zero at Critical, and the bucket never
        /// holds more than the burst or owes more than the deficit cap.
        #[test]
        fn yield_is_always_capped_and_critical_never_waits(
            pct in 0u8..=100,
            steps in proptest::collection::vec((0u8..5, 0.0f64..30.0, 0.0f64..20.0), 1..200),
        ) {
            let t0 = Instant::now();
            let mut b = CpuBudget::new(pct, t0, 0.0);
            let mut wall = 0.0;
            let mut cpu = 0.0;
            for (level, dt, used) in steps {
                wall += dt;
                cpu += used;
                b.observe(t0 + secs(wall), cpu);
                let level = match level {
                    0 => PressureLevel::Green,
                    1 => PressureLevel::Yellow,
                    2 => PressureLevel::Orange,
                    3 => PressureLevel::Red,
                    _ => PressureLevel::Critical,
                };
                let wait = b.yield_for(level, MAX_TICK_YIELD);
                proptest::prop_assert!(wait <= MAX_TICK_YIELD);
                if level == PressureLevel::Critical || pct == 0 {
                    proptest::prop_assert_eq!(wait, Duration::ZERO);
                }
                proptest::prop_assert!(b.tokens <= BURST_SECS + 1e-9);
                proptest::prop_assert!(b.deficit_secs() <= MAX_DEFICIT_SECS + 1e-9);
            }
        }
    }
}
