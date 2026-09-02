//! Q7: the daemon's CPU budget as one invariant across threads.
//!
//! One token bucket holds CPU-seconds. It refills from wall time at
//! `pct/100` of one core and drains by the process's own CPU time (rusage
//! deltas), so it charges everything the daemon does: scanner passes, the
//! priority pre-scan, maintenance passes, index work and the monitor tick.
//! When the bucket is in deficit the monitor loop stretches its sleep; the
//! scanner starts a discretionary pass only with at least
//! [`PASS_MIN_TOKENS`] in the bucket and may then walk only as long as the
//! bucket has tokens (its wall deadline is capped by
//! [`CpuBudget::pass_allowance`]). Documented bound: over any window of `w`
//! seconds the daemon's CPU time is at most `pct/100 * w + BURST_SECS`, plus
//! what the protected operations and the executor cost.
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

/// CPU-seconds the bucket can hold: short bursts (a pre-scan, an index
/// load) run at full speed; sustained work is paced at the budget rate.
pub const BURST_SECS: f64 = 5.0;

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

    /// What a discretionary scan pass may do right now: `None` means no
    /// limit (budget disabled, or Critical pressure), `Some(ZERO)` means do
    /// not start (fewer than [`PASS_MIN_TOKENS`] CPU-seconds in the bucket),
    /// otherwise the wall time the pass may walk: the available CPU-seconds
    /// spread over `threads` workers, so the pass ends about when the bucket
    /// does instead of overshooting by a whole pass.
    #[must_use]
    pub fn pass_allowance(&self, level: PressureLevel, threads: usize) -> Option<Duration> {
        if !self.enabled() || level >= PressureLevel::Critical {
            return None;
        }
        let available = self.available_secs();
        if available < PASS_MIN_TOKENS {
            return Some(Duration::ZERO);
        }
        #[allow(clippy::cast_precision_loss)]
        let wall = available / threads.max(1) as f64;
        Some(Duration::from_secs_f64(wall))
    }

    /// Account for the wall time since the last observation and the CPU the
    /// process spent in it. `cpu_secs` is the process's cumulative user +
    /// system time.
    pub fn observe(&mut self, now: Instant, cpu_secs: f64) -> BudgetTick {
        let wall = now.saturating_duration_since(self.last_wall).as_secs_f64();
        let used = (cpu_secs - self.last_cpu_secs).max(0.0);
        self.last_wall = now;
        self.last_cpu_secs = cpu_secs;

        self.tokens =
            (wall.mul_add(self.rate(), self.tokens) - used).clamp(-MAX_DEFICIT_SECS, BURST_SECS);

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
    fn pass_allowance_spreads_the_tokens_over_the_walker_threads() {
        let (mut b, t0) = budget(25);
        // A full bucket (5 s) over two threads: 2.5 s of wall.
        let full = b.pass_allowance(PressureLevel::Green, 2).unwrap();
        assert!((full.as_secs_f64() - 2.5).abs() < 1e-9, "{full:?}");
        // Nearly empty: the pass must not start until a CPU-second is back.
        b.observe(t0 + secs(1.0), 104.5); // 5 + 0.25 - 4.5 = 0.75
        assert!(b.available_secs() < PASS_MIN_TOKENS);
        assert_eq!(
            b.pass_allowance(PressureLevel::Orange, 2),
            Some(Duration::ZERO)
        );
        b.observe(t0 + secs(3.0), 104.5); // +0.5 refill -> 1.25
        let short = b.pass_allowance(PressureLevel::Orange, 2).unwrap();
        assert!((short.as_secs_f64() - 0.625).abs() < 1e-9, "{short:?}");
        // Critical and a disabled budget never limit a pass.
        assert_eq!(b.pass_allowance(PressureLevel::Critical, 2), None);
        let (off, _) = budget(0);
        assert_eq!(off.pass_allowance(PressureLevel::Green, 2), None);
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
