//! Prometheus textfile export (bd-rc-master-ajg1.7.3).
//!
//! The daemon renders `metrics.prom` beside `state.json` from the same
//! [`DaemonState`] it just wrote, so node_exporter's textfile collector can
//! scrape it with no network surface and no new dependency. The file is
//! written atomically (temp + rename) and world-readable; `sbh metrics`
//! prints it for hosts without a collector.
//!
//! The renderer is a pure function of the state document plus the build's
//! git sha, and [`validate_exposition`] checks the text against the
//! exposition-format rules the tests hold it to: metric names, one `HELP`
//! and one `TYPE` line per family, samples grouped under their family,
//! label values escaped.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::ballast::coordinator::{
    BallastRefillBlocker, BallastReserveSnapshot, BallastReserveState,
};
use crate::core::errors::{Result, SbhError};
use crate::daemon::self_monitor::{BallastPoolState, DaemonState};
use crate::scanner::deletion::FreedBasis;

/// File name of the export, a sibling of `state.json`.
pub const METRICS_FILE_NAME: &str = "metrics.prom";

/// The git sha this binary was built from, as `build.rs` exposes it.
///
/// Git's answer in a checkout, the packager's `SBH_BUILD_GIT_SHA`
/// elsewhere, `unknown` when neither existed at build time
/// (bd-rc-master-ajg1.5.4). The older `VERGEN_GIT_SHA`/`GIT_SHA` names are
/// still honored.
#[must_use]
pub fn build_git_sha() -> &'static str {
    option_env!("SBH_BUILD_GIT_SHA")
        .or(option_env!("VERGEN_GIT_SHA"))
        .or(option_env!("GIT_SHA"))
        .unwrap_or("unknown")
}

/// The metrics file path for a given `state.json` path.
#[must_use]
pub fn metrics_file_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name(METRICS_FILE_NAME)
}

/// Pressure levels rendered one-hot per mount.
const PRESSURE_LEVELS: [&str; 5] = ["green", "yellow", "orange", "red", "critical"];
/// Policy modes rendered one-hot.
const POLICY_MODES: [&str; 4] = ["observe", "canary", "enforce", "fallback_safe"];

/// One metric family: name, help, type and its samples.
struct Family {
    name: &'static str,
    help: &'static str,
    kind: &'static str,
    samples: Vec<String>,
}

impl Family {
    fn new(name: &'static str, help: &'static str, kind: &'static str) -> Self {
        Self {
            name,
            help,
            kind,
            samples: Vec::new(),
        }
    }

    fn sample(&mut self, labels: &[(&str, &str)], value: impl std::fmt::Display) {
        let mut line = String::from(self.name);
        if !labels.is_empty() {
            line.push('{');
            for (index, (key, value)) in labels.iter().enumerate() {
                if index > 0 {
                    line.push(',');
                }
                let _ = write!(line, "{key}=\"{}\"", escape_label(value));
            }
            line.push('}');
        }
        let _ = write!(line, " {value}");
        self.samples.push(line);
    }

    fn render(&self, out: &mut String) {
        if self.samples.is_empty() {
            return;
        }
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} {}", self.name, self.kind);
        for sample in &self.samples {
            out.push_str(sample);
            out.push('\n');
        }
    }
}

/// Escape a label value per the exposition format: backslash, double quote
/// and newline.
fn escape_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// A finite float, or `0` when the state carries NaN/inf (the exposition
/// format allows `NaN` but a dashboard does not want it).
fn finite(value: f64) -> f64 {
    if value.is_finite() { value } else { 0.0 }
}

/// Render the whole family set from a state document.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render(state: &DaemonState, git_sha: &str) -> String {
    let mut families = Vec::new();

    let mut up = Family::new(
        "sbh_up",
        "1 while the daemon is running and writing state.",
        "gauge",
    );
    up.sample(&[], u8::from(state.stopped_at.is_none()));
    families.push(up);

    let mut info = Family::new("sbh_info", "Build and run identity of the daemon.", "gauge");
    info.sample(
        &[
            ("version", &state.version),
            ("git_sha", git_sha),
            ("policy_mode", &state.policy_mode),
            ("run_id", &state.run_id),
        ],
        1,
    );
    families.push(info);

    let mut uptime = Family::new(
        "sbh_daemon_uptime_seconds",
        "Seconds since the daemon started.",
        "gauge",
    );
    uptime.sample(&[], state.uptime_seconds);
    families.push(uptime);

    let mut cpu = Family::new(
        "sbh_daemon_cpu_seconds_total",
        "CPU seconds the daemon process has used (user plus system).",
        "counter",
    );
    cpu.sample(&[], finite(state.cpu_secs_total));
    families.push(cpu);

    let mut rss = Family::new(
        "sbh_daemon_rss_bytes",
        "Resident set size of the daemon process.",
        "gauge",
    );
    rss.sample(&[], state.memory_rss_bytes);
    families.push(rss);

    let mut budget_used = Family::new(
        "sbh_daemon_cpu_budget_used_ratio",
        "CPU used over the last minute as a fraction of one core.",
        "gauge",
    );
    budget_used.sample(&[], finite(state.cpu_budget.used_pct_1m / 100.0));
    families.push(budget_used);

    let mut budget_deficit = Family::new(
        "sbh_daemon_cpu_budget_deficit_seconds",
        "Idle time the scanner still owes the CPU budget.",
        "gauge",
    );
    budget_deficit.sample(&[], finite(state.cpu_budget.deficit_secs));
    families.push(budget_deficit);

    let mut free_ratio = Family::new(
        "sbh_mount_free_ratio",
        "Free space on a watched mount as a fraction of its size.",
        "gauge",
    );
    let mut level = Family::new(
        "sbh_mount_pressure_level",
        "1 for the mount's current pressure level, 0 for the others.",
        "gauge",
    );
    let mut fill_rate = Family::new(
        "sbh_mount_fill_rate_bytes_per_second",
        "Estimated rate at which the mount is filling (negative while it drains).",
        "gauge",
    );
    let mut tte = Family::new(
        "sbh_mount_seconds_to_red",
        "Forecast seconds until the mount reaches the red threshold; absent without a forecast.",
        "gauge",
    );
    for mount in &state.pressure.mounts {
        free_ratio.sample(&[("mount", &mount.path)], finite(mount.free_pct / 100.0));
        for name in PRESSURE_LEVELS {
            level.sample(
                &[("mount", &mount.path), ("level", name)],
                u8::from(mount.level.eq_ignore_ascii_case(name)),
            );
        }
        if let Some(rate) = state.rates.get(&mount.path) {
            fill_rate.sample(&[("mount", &mount.path)], finite(rate.bytes_per_sec));
            if let Some(seconds) = rate.seconds_to_red {
                tte.sample(&[("mount", &mount.path)], finite(seconds));
            }
        } else if let Some(rate) = mount.rate_bps {
            fill_rate.sample(&[("mount", &mount.path)], finite(rate));
        }
    }
    families.push(free_ratio);
    families.push(level);
    families.push(fill_rate);
    families.push(tte);

    let mut capability = Family::new(
        "sbh_mount_reclaim_capability",
        "1 for the mount's reclaim capability, 0 for the others.",
        "gauge",
    );
    let mut controller_state = Family::new(
        "sbh_mount_controller_state",
        "1 for the mount controller's current state, 0 for the others.",
        "gauge",
    );
    let mut quarantined = Family::new(
        "sbh_quarantine_bytes",
        "Bytes held in quarantine on the mount.",
        "gauge",
    );
    let mut reserve_recommended = Family::new(
        "sbh_reserve_recommended_bytes",
        "Reserve the mount's observed write bursts call for (0.99 quantile per reaction window, floored at two ballast files).",
        "gauge",
    );
    let mut burst_q99 = Family::new(
        "sbh_burst_q99_bytes",
        "0.99 quantile of used-bytes growth per reaction window on the mount.",
        "gauge",
    );
    let mut inode_known = Family::new(
        "sbh_mount_inode_accounting_known",
        "1 when finite inode pressure accounting is available and enabled, 0 when unknown or disabled.",
        "gauge",
    );
    let mut inode_total = Family::new(
        "sbh_mount_inodes_total",
        "Finite inode capacity; absent when inode accounting is unknown or disabled.",
        "gauge",
    );
    let mut inode_available = Family::new(
        "sbh_mount_inodes_available",
        "Inodes available to an ordinary caller; absent when accounting is unknown or disabled.",
        "gauge",
    );
    let mut inode_ratio = Family::new(
        "sbh_mount_inode_free_ratio",
        "Available inodes as a fraction of finite inode capacity, independent of byte capacity.",
        "gauge",
    );
    let mut inode_level = Family::new(
        "sbh_mount_inode_pressure_level",
        "1 for the independent inode pressure level, 0 for the others; absent without accounting.",
        "gauge",
    );
    for record in &state.mount_controllers {
        inode_known.sample(
            &[("mount", &record.mount)],
            u8::from(record.inode_pressure.is_some()),
        );
        if let Some(inodes) = &record.inode_pressure {
            inode_total.sample(&[("mount", &record.mount)], inodes.total);
            inode_available.sample(&[("mount", &record.mount)], inodes.available);
            inode_ratio.sample(&[("mount", &record.mount)], finite(inodes.free_pct / 100.0));
            for name in PRESSURE_LEVELS {
                inode_level.sample(
                    &[("mount", &record.mount), ("level", name)],
                    u8::from(inodes.level.eq_ignore_ascii_case(name)),
                );
            }
        }
        let capability_name = serde_plain_name(&record.reclaim_capability);
        for name in [
            "configured",
            "catalog",
            "cross_device",
            "ballast_only",
            "none",
        ] {
            capability.sample(
                &[("mount", &record.mount), ("capability", name)],
                u8::from(capability_name == name),
            );
        }
        let state_name = record.state.as_str();
        for name in ["observe_only", "maintain", "reclaim", "idle", "recovering"] {
            controller_state.sample(
                &[("mount", &record.mount), ("state", name)],
                u8::from(state_name == name),
            );
        }
        if let Some(reserve) = &record.reserve_state {
            quarantined.sample(&[("mount", &record.mount)], reserve.quarantined_bytes);
            if let Some(burst) = &reserve.burst {
                reserve_recommended.sample(&[("mount", &record.mount)], burst.recommended_bytes);
                burst_q99.sample(&[("mount", &record.mount)], burst.q99_bytes);
            }
        }
    }
    families.push(capability);
    families.push(controller_state);
    families.push(quarantined);
    families.push(reserve_recommended);
    families.push(burst_q99);
    families.push(inode_known);
    families.push(inode_total);
    families.push(inode_available);
    families.push(inode_ratio);
    families.push(inode_level);

    families.extend(reserve_families(state));

    let mut releases = Family::new(
        "sbh_ballast_releases_total",
        "Ballast files released since the daemon started.",
        "counter",
    );
    releases.sample(&[], state.ballast.released);
    families.push(releases);

    let mut scans = Family::new(
        "sbh_scans_total",
        "Scan passes completed since the daemon started.",
        "counter",
    );
    scans.sample(&[], state.counters.scans);
    families.push(scans);

    let mut deletions = Family::new(
        "sbh_deletions_total",
        "Artifacts removed (or quarantined) since the daemon started.",
        "counter",
    );
    deletions.sample(&[], state.counters.deletions);
    families.push(deletions);

    let mut freed = Family::new(
        "sbh_bytes_freed_total",
        "Bytes reclaimed since the daemon started.",
        "counter",
    );
    freed.sample(&[], state.counters.bytes_freed);
    families.push(freed);

    let mut freed_basis = Family::new(
        "sbh_bytes_freed_basis",
        "1 for how sbh_bytes_freed_total is known, 0 for the others: observed, or \
         the allocated-size estimate where the filesystem frees blocks at commit.",
        "gauge",
    );
    for basis in [
        FreedBasis::Observed,
        FreedBasis::Estimated,
        FreedBasis::EstimatedUpperBound,
    ] {
        freed_basis.sample(
            &[("basis", basis.label())],
            u8::from(state.counters.freed_basis == basis),
        );
    }
    families.push(freed_basis);

    let mut errors = Family::new(
        "sbh_errors_total",
        "Errors the daemon logged since it started.",
        "counter",
    );
    errors.sample(&[], state.counters.errors);
    families.push(errors);

    let mut dropped = Family::new(
        "sbh_log_events_dropped_total",
        "Activity-log events dropped because the logger channel was full.",
        "counter",
    );
    dropped.sample(&[], state.counters.dropped_log_events);
    families.push(dropped);

    let mut last_scan = Family::new(
        "sbh_last_scan_candidates",
        "Candidates found by the most recent scan pass.",
        "gauge",
    );
    last_scan.sample(&[], state.last_scan.candidates);
    families.push(last_scan);

    let mut policy = Family::new(
        "sbh_policy_mode",
        "1 for the policy engine's active mode, 0 for the others.",
        "gauge",
    );
    for name in POLICY_MODES {
        policy.sample(&[("mode", name)], u8::from(state.policy.mode == name));
    }
    families.push(policy);

    let mut policy_since = Family::new(
        "sbh_policy_mode_seconds",
        "Seconds the policy engine has been in its current mode.",
        "gauge",
    );
    policy_since.sample(&[], state.policy.since_secs);
    families.push(policy_since);

    let mut threads = Family::new(
        "sbh_thread_up",
        "1 while the worker thread is running (heartbeat fresh), 0 when stalled or dead.",
        "gauge",
    );
    for (name, thread) in [
        ("monitor", &state.threads.monitor),
        ("scanner", &state.threads.scanner),
        ("executor", &state.threads.executor),
        ("logger", &state.threads.logger),
    ] {
        threads.sample(
            &[("thread", name)],
            u8::from(thread.status == "running" || thread.status == "ok"),
        );
    }
    families.push(threads);

    let mut out = String::with_capacity(4096);
    for family in &families {
        family.render(&mut out);
    }
    out
}

/// Reserve gauges are observations, not the allocator's cached bookkeeping.
///
/// Rendering is deterministic at the state document's publication time. A
/// textfile collector can keep serving that document after the daemon stops,
/// so consumers must also bound `time() - sbh_state_last_updated_timestamp_seconds`
/// and the per-pool observation age before treating a positive quantity as
/// current protection. Unknown quantities are absent; an observed zero remains
/// an explicit zero and has the `exhausted` condition.
#[allow(clippy::too_many_lines)]
fn reserve_families(state: &DaemonState) -> Vec<Family> {
    let updated_at = chrono::DateTime::parse_from_rfc3339(&state.last_updated)
        .ok()
        .map(|time| time.with_timezone(&chrono::Utc));
    let current_run = state.stopped_at.is_none() && updated_at.is_some();
    let discovery_pending = state
        .discovery
        .as_ref()
        .is_some_and(|discovery| discovery.pending || discovery.reload_pending);
    let mut published = Family::new(
        "sbh_state_last_updated_timestamp_seconds",
        "Unix time of this state publication; bound its age when evaluating textfile gauges.",
        "gauge",
    );
    if let Some(updated) = updated_at {
        published.sample(&[], updated.timestamp());
    }
    let mut condition = Family::new(
        "sbh_ballast_reserve_state",
        "1 for the pool's reserve condition at state publication, 0 for the others; independent of disk pressure.",
        "gauge",
    );
    let mut authoritative = Family::new(
        "sbh_ballast_inventory_authoritative",
        "1 when this pool's current observation confirms releasable availability; 0 when unknown.",
        "gauge",
    );
    let mut complete = Family::new(
        "sbh_ballast_inventory_complete",
        "1 when current authoritative observations cover all managed pools; 0 while discovery is pending, without pool observations, or with any unknown pool.",
        "gauge",
    );
    let mut present = Family::new(
        "sbh_ballast_present_bytes",
        "Observed releasable ballast bytes per physical pool; absent when availability is unknown.",
        "gauge",
    );
    let mut target = Family::new(
        "sbh_ballast_target_bytes",
        "Ballast target per physical pool, independent of observed availability.",
        "gauge",
    );
    let mut files = Family::new(
        "sbh_ballast_files",
        "Configured and available files across managed pools; totals are absent during pending discovery, and available is absent if any pool is unknown.",
        "gauge",
    );
    let mut blocked = Family::new(
        "sbh_ballast_refill_blocked",
        "1 when the named reason prevents automatic refill of this pool, 0 otherwise; observation only, never allocation authority.",
        "gauge",
    );
    let mut refilling = Family::new(
        "sbh_ballast_refill_in_progress",
        "1 while an authorized replenishment worker is reported for the pool, 0 otherwise.",
        "gauge",
    );
    let mut observed = Family::new(
        "sbh_ballast_reserve_observed_timestamp_seconds",
        "Unix time of the pool's last valid inventory observation; absent without a valid timestamp.",
        "gauge",
    );

    let mut available_files = Some(0_usize);
    let mut configured_files = Some(0_usize);
    let mut pool_count = 0;
    for pool in state.ballast_pools.iter().filter(|pool| !pool.skipped) {
        pool_count += 1;
        // Even without a usable state timestamp, validate pool identity so
        // byte-native paths remain distinct in Unknown metric labels.
        let checked = pool.reserve_status_at(updated_at.unwrap_or(chrono::DateTime::UNIX_EPOCH));
        let snapshot = checked.as_ref().filter(|_| current_run);
        let label_values = reserve_labels(pool, checked.as_ref());
        let mut labels: Vec<_> = label_values
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let known = snapshot.is_some_and(|reserve| reserve.inventory_authoritative);
        let band = snapshot.map_or_else(
            || BallastReserveState::classify(u64::from(pool.total != 0), 0, false),
            |reserve| reserve.state,
        );
        for value in [
            BallastReserveState::Unconfigured,
            BallastReserveState::Healthy,
            BallastReserveState::Depleted,
            BallastReserveState::Critical,
            BallastReserveState::Exhausted,
            BallastReserveState::Unknown,
        ] {
            labels.push(("state", value.as_str()));
            condition.sample(&labels, u8::from(band == value));
            labels.pop();
        }
        authoritative.sample(&labels, u8::from(known));
        configured_files = configured_files.and_then(|total| total.checked_add(pool.total));
        if let Some(reserve) = snapshot.filter(|reserve| reserve.inventory_authoritative) {
            present.sample(&labels, reserve.releasable_bytes);
            available_files =
                available_files.and_then(|total| total.checked_add(reserve.files_available));
        } else {
            available_files = None;
        }
        // A target is configuration, not inventory evidence. Older state
        // documents may carry it only in the controller's reserve record.
        let configured_bytes = checked
            .as_ref()
            .map(|reserve| reserve.configured_bytes)
            .or_else(|| {
                state
                    .mount_controllers
                    .iter()
                    .find(|record| record.mount == pool.mount)
                    .and_then(|record| record.reserve_state.as_ref())
                    .map(|reserve| reserve.target_bytes)
            });
        if let Some(bytes) = configured_bytes {
            target.sample(&labels, bytes);
        }
        refilling.sample(
            &labels,
            u8::from(snapshot.is_some_and(|reserve| reserve.refill_in_progress)),
        );
        for reason in [
            BallastRefillBlocker::NotEvaluated,
            BallastRefillBlocker::PressurePolicy,
            BallastRefillBlocker::Forecast,
            BallastRefillBlocker::RamPressure,
            BallastRefillBlocker::InodePressure,
            BallastRefillBlocker::MountRecovery,
            BallastRefillBlocker::MountInactive,
            BallastRefillBlocker::DryRun,
            BallastRefillBlocker::KillSwitch,
            BallastRefillBlocker::Shutdown,
            BallastRefillBlocker::Cooldown,
            BallastRefillBlocker::WorkerBusy,
            BallastRefillBlocker::InventoryUnreadable,
            BallastRefillBlocker::FilesystemStatsUnavailable,
            BallastRefillBlocker::ReadOnlyFilesystem,
            BallastRefillBlocker::ObservationStale,
            BallastRefillBlocker::SafetyFloor,
        ] {
            let applies = snapshot
                .map_or(reason == BallastRefillBlocker::NotEvaluated, |reserve| {
                    reserve.refill_blockers.contains(&reason)
                });
            labels.push(("reason", reason.as_str()));
            blocked.sample(&labels, u8::from(applies));
            labels.pop();
        }
        if let Some(reserve) = snapshot
            && let Ok(at) = chrono::DateTime::parse_from_rfc3339(&reserve.observed_at)
            && updated_at.is_some_and(|updated| at <= updated)
        {
            observed.sample(&labels, at.timestamp());
        }
    }
    let all_known =
        current_run && !discovery_pending && pool_count > 0 && available_files.is_some();
    complete.sample(&[], u8::from(all_known));
    if all_known && let Some(count) = available_files {
        files.sample(&[("state", "available")], count);
    }
    if !discovery_pending && state.ballast_pools.is_empty() {
        // Legacy aggregate totals describe configuration only. They cannot
        // recover a missing per-pool inventory observation.
        files.sample(&[("state", "total")], state.ballast.total);
    } else if !discovery_pending && let Some(count) = configured_files {
        files.sample(&[("state", "total")], count);
    }
    vec![
        published,
        condition,
        authoritative,
        complete,
        present,
        target,
        files,
        blocked,
        refilling,
        observed,
    ]
}

/// Display labels remain familiar while native-byte labels prevent different
/// non-UTF-8 pool identities from collapsing to the same replacement text.
fn reserve_labels(
    pool: &BallastPoolState,
    snapshot: Option<&BallastReserveSnapshot>,
) -> Vec<(&'static str, String)> {
    let mut labels = vec![
        ("mount", pool.mount.clone()),
        ("ballast_dir", pool.ballast_dir.clone()),
    ];
    if let Some(snapshot) = snapshot {
        for (name, path) in [
            ("mount_native_hex", &snapshot.mount_point),
            ("ballast_dir_native_hex", &snapshot.ballast_dir),
        ] {
            if path.to_str().is_none() {
                let mut hex = String::new();
                for byte in path.as_os_str().as_encoded_bytes() {
                    let _ = write!(hex, "{byte:02x}");
                }
                labels.push((name, hex));
            }
        }
    }
    labels
}

/// The snake_case name serde gives a unit enum, without a serde dependency
/// on the enum here: `Debug` for these enums is the variant name, which is
/// what the label carries in lower snake case.
fn serde_plain_name<T: std::fmt::Debug>(value: &T) -> String {
    let debug = format!("{value:?}");
    let mut name = String::with_capacity(debug.len() + 2);
    for (index, ch) in debug.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                name.push('_');
            }
            name.push(ch.to_ascii_lowercase());
        } else {
            name.push(ch);
        }
    }
    name
}

/// Write the export atomically (temp file plus rename), world-readable so
/// a collector running as another user can scrape it.
pub fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let io = |source: std::io::Error| SbhError::Io {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    let temp = path.with_extension("prom.tmp");
    std::fs::write(&temp, text).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o644)).map_err(io)?;
    }
    std::fs::rename(&temp, path).map_err(io)
}

/// Check `text` against the exposition-format rules.
///
/// Every non-comment line is `name{labels} value` with a legal name, every
/// family has exactly one `HELP` and one `TYPE` line that precede its
/// samples, samples of a family are contiguous, and the file ends with a
/// newline.
pub fn validate_exposition(text: &str) -> std::result::Result<(), String> {
    if !text.is_empty() && !text.ends_with('\n') {
        return Err("missing trailing newline".to_string());
    }
    let mut current: Option<String> = None;
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut has_help = false;
    let mut has_type = false;
    for (number, line) in text.lines().enumerate() {
        let number = number + 1;
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let name = rest.split(' ').next().unwrap_or_default();
            check_name(name, number)?;
            if current.as_deref() != Some(name) {
                if !seen.insert(name.to_string()) {
                    return Err(format!("line {number}: family {name} appears twice"));
                }
                current = Some(name.to_string());
                has_help = false;
                has_type = false;
            }
            if has_help {
                return Err(format!("line {number}: second HELP for {name}"));
            }
            has_help = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split(' ');
            let name = parts.next().unwrap_or_default();
            let kind = parts.next().unwrap_or_default();
            check_name(name, number)?;
            if current.as_deref() != Some(name) {
                return Err(format!("line {number}: TYPE for {name} without its HELP"));
            }
            if has_type {
                return Err(format!("line {number}: second TYPE for {name}"));
            }
            if !matches!(
                kind,
                "gauge" | "counter" | "histogram" | "summary" | "untyped"
            ) {
                return Err(format!("line {number}: unknown type {kind:?}"));
            }
            has_type = true;
            continue;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (name, rest) =
            split_sample(line).ok_or_else(|| format!("line {number}: not a sample: {line}"))?;
        check_name(name, number)?;
        let Some(family) = current.as_deref() else {
            return Err(format!("line {number}: sample before any HELP"));
        };
        if name != family && !name.starts_with(&format!("{family}_")) {
            return Err(format!(
                "line {number}: sample {name} outside its family block ({family})"
            ));
        }
        if !(has_help && has_type) {
            return Err(format!(
                "line {number}: sample before HELP and TYPE of {family}"
            ));
        }
        let value = rest.trim();
        if value.is_empty() || value.parse::<f64>().is_err() && value != "NaN" {
            return Err(format!("line {number}: bad value {value:?}"));
        }
    }
    Ok(())
}

fn check_name(name: &str, line: usize) -> std::result::Result<(), String> {
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':');
    if valid {
        Ok(())
    } else {
        Err(format!("line {line}: illegal metric name {name:?}"))
    }
}

/// Split `name{labels} value` (or `name value`) into the name and the value
/// text, validating that a label block closes and every label value is a
/// quoted string. Commas, braces and escaped quotes inside a quoted value
/// are data, not separators (a fuzz finding: `policy_mode="enforce,"`).
fn split_sample(line: &str) -> Option<(&str, &str)> {
    let Some(open) = line.find('{') else {
        return line.split_once(' ');
    };
    let bytes = line.as_bytes();
    let mut at = open + 1;
    while bytes.get(at) != Some(&b'}') {
        let eq = line[at..].find('=')? + at;
        if eq == at || line[at..eq].contains(',') {
            return None;
        }
        if bytes.get(eq + 1) != Some(&b'"') {
            return None;
        }
        let mut end = eq + 2;
        loop {
            match bytes.get(end)? {
                b'\\' => end += 2,
                b'"' => break,
                _ => end += 1,
            }
        }
        at = end + 1;
        match bytes.get(at)? {
            b',' => at += 1,
            b'}' => {}
            _ => return None,
        }
    }
    Some((&line[..open], line.get(at + 1..)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::cpu_budget::CpuBudgetState;
    use crate::daemon::mount_controller::{
        MountState, MountStateRecord, ReclaimCapability, ReserveBurst, ReserveState, SurfaceKind,
    };
    use crate::daemon::self_monitor::{
        BallastState, Counters, LastScanState, MountPressure, MountRateState, PolicyStateRecord,
        PressureState, ThreadState, ThreadsState,
    };

    fn observed_pool(
        mount: &str,
        available: usize,
        total: usize,
        bytes: u64,
        configured_bytes: u64,
    ) -> BallastPoolState {
        let directory = Path::new(mount).join(".sbh/ballast");
        BallastPoolState {
            mount: mount.into(),
            ballast_dir: directory.to_string_lossy().into_owned(),
            available,
            total,
            releasable_bytes: bytes,
            reserve: Some(BallastReserveSnapshot {
                observed_at: "2026-09-02T00:01:30Z".into(),
                mount_point: PathBuf::from(mount),
                ballast_dir: directory,
                files_available: available,
                files_total: total,
                releasable_bytes: bytes,
                configured_bytes,
                state: BallastReserveState::classify(configured_bytes, bytes, true),
                inventory_authoritative: true,
                unreadable_count: 0,
                headroom: None,
                headroom_error: None,
                refill_blockers: Vec::new(),
                refill_in_progress: false,
            }),
            ..Default::default()
        }
    }

    #[allow(clippy::too_many_lines)]
    fn sample_state() -> DaemonState {
        let mut rates = std::collections::BTreeMap::new();
        rates.insert(
            "/data".to_string(),
            MountRateState {
                bytes_per_sec: 2048.5,
                accel: 0.0,
                confidence: 0.9,
                seconds_to_red: Some(3600.0),
                seconds_to_full: None,
                forecast: None,
            },
        );
        DaemonState {
            version: "0.5.1".to_string(),
            pid: 4242,
            started_at: "2026-09-02T00:00:00Z".to_string(),
            uptime_seconds: 91,
            last_updated: "2026-09-02T00:01:31Z".to_string(),
            pressure: PressureState {
                overall: "orange".to_string(),
                mounts: vec![
                    MountPressure {
                        path: "/data".to_string(),
                        free_pct: 12.5,
                        level: "orange".to_string(),
                        rate_bps: Some(2048.5),
                    },
                    MountPressure {
                        path: "/weird\"mount\\name".to_string(),
                        free_pct: 55.0,
                        level: "green".to_string(),
                        rate_bps: None,
                    },
                ],
            },
            ballast: BallastState {
                available: 3,
                total: 4,
                released: 1,
            },
            ballast_pools: vec![observed_pool("/data", 3, 4, 4096, 1 << 30)],
            last_scan: LastScanState {
                at: None,
                candidates: 7,
                deleted: 2,
            },
            counters: Counters {
                scans: 12,
                deletions: 2,
                bytes_freed: 5_032_071_168,
                errors: 0,
                dropped_log_events: 0,
                freed_basis: crate::scanner::deletion::FreedBasis::Observed,
                bytes_freed_observed: None,
            },
            memory_rss_bytes: 61 * 1024 * 1024,
            policy_mode: "enforce".to_string(),
            mount_controllers: vec![MountStateRecord {
                mount: "/data".to_string(),
                state: MountState::Reclaim,
                idle_reason: None,
                surface: SurfaceKind::Configured,
                level: "orange".to_string(),
                urgency: 0.87,
                backing_pressure: None,
                inode_pressure: None,
                rescan_in_secs: Some(20),
                reclaim_capability: ReclaimCapability::Configured,
                reserve_state: Some(ReserveState {
                    present_bytes: 4096,
                    target_bytes: 1 << 30,
                    horizon_minutes: Some(30.0),
                    floor_limited: false,
                    quarantined_bytes: 0,
                    burst: Some(ReserveBurst {
                        recommended_bytes: 2 << 30,
                        q99_bytes: 1_500_000_000,
                        windows: 72,
                        reaction_window_secs: 240.0,
                        method: crate::monitor::burst::ReserveMethod::Quantile,
                        horizon_minutes: Some(0.001),
                    }),
                    release_efficiency: None,
                }),
            }],
            schema_version: 2,
            run_id: "e9ef7-1a0644409f8".to_string(),
            rates,
            threads: ThreadsState {
                monitor: ThreadState {
                    status: "running".to_string(),
                    seconds_since_heartbeat: Some(0),
                },
                scanner: ThreadState {
                    status: "running".to_string(),
                    seconds_since_heartbeat: Some(1),
                },
                executor: ThreadState {
                    status: "stalled".to_string(),
                    seconds_since_heartbeat: Some(75),
                },
                logger: ThreadState {
                    status: "running".to_string(),
                    seconds_since_heartbeat: Some(0),
                },
            },
            cpu_secs_total: 8.26,
            cpu_budget: CpuBudgetState {
                pct: 25,
                used_pct_1m: 1.4,
                deficit_secs: 0.0,
                over_budget_minutes: 0,
            },
            idle_reason: None,
            policy: PolicyStateRecord {
                mode: "enforce".to_string(),
                since_secs: 91,
                last_fallback_reason: None,
                auto_recover_to: "enforce".to_string(),
                serialization_failures: 0,
            },
            stopped_at: None,
            exit_reason: None,
            ..Default::default()
        }
    }

    #[test]
    fn render_validates_and_carries_the_core_families() {
        let text = render(&sample_state(), "abc123");
        validate_exposition(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        for needle in [
            "sbh_up 1\n",
            "sbh_info{version=\"0.5.1\",git_sha=\"abc123\",policy_mode=\"enforce\",run_id=\"e9ef7-1a0644409f8\"} 1\n",
            "sbh_daemon_uptime_seconds 91\n",
            "sbh_daemon_cpu_seconds_total 8.26\n",
            "sbh_daemon_rss_bytes 63963136\n",
            "sbh_mount_free_ratio{mount=\"/data\"} 0.125\n",
            "sbh_mount_pressure_level{mount=\"/data\",level=\"orange\"} 1\n",
            "sbh_mount_pressure_level{mount=\"/data\",level=\"green\"} 0\n",
            "sbh_mount_fill_rate_bytes_per_second{mount=\"/data\"} 2048.5\n",
            "sbh_mount_seconds_to_red{mount=\"/data\"} 3600\n",
            "sbh_mount_reclaim_capability{mount=\"/data\",capability=\"configured\"} 1\n",
            "sbh_mount_controller_state{mount=\"/data\",state=\"reclaim\"} 1\n",
            "sbh_ballast_present_bytes{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"} 4096\n",
            "sbh_ballast_target_bytes{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"} 1073741824\n",
            "sbh_ballast_files{state=\"available\"} 3\n",
            "sbh_ballast_releases_total 1\n",
            "sbh_scans_total 12\n",
            "sbh_deletions_total 2\n",
            "sbh_bytes_freed_total 5032071168\n",
            "sbh_bytes_freed_basis{basis=\"observed\"} 1\n",
            "sbh_bytes_freed_basis{basis=\"estimated_allocated\"} 0\n",
            "sbh_policy_mode{mode=\"enforce\"} 1\n",
            "sbh_policy_mode{mode=\"observe\"} 0\n",
            "sbh_thread_up{thread=\"executor\"} 0\n",
            "sbh_thread_up{thread=\"scanner\"} 1\n",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in\n{text}");
        }
    }

    #[test]
    fn reserve_metrics_distinguish_exhaustion_unknown_and_healthy_siblings() {
        let mut state = sample_state();
        let mut exhausted = observed_pool("/data", 0, 4, 0, 16_384);
        // The allocator's old full-pool bookkeeping must not win over the
        // observer's confirmed exhaustion or a missing observation.
        exhausted.available = 4;
        exhausted.releasable_bytes = 16_384;
        exhausted.reserve.as_mut().unwrap().refill_blockers = vec![
            BallastRefillBlocker::PressurePolicy,
            BallastRefillBlocker::SafetyFloor,
        ];
        let healthy = observed_pool("/healthy", 4, 4, 16_384, 16_384);
        let mut unknown = observed_pool("/unreadable", 4, 4, 16_384, 16_384);
        {
            let reserve = unknown.reserve.as_mut().unwrap();
            reserve.inventory_authoritative = false;
            reserve.unreadable_count = 1;
            reserve.refill_blockers = vec![BallastRefillBlocker::InventoryUnreadable];
        }
        let mut alias = observed_pool("/alias", 100, 100, 409_600, 409_600);
        alias.skipped = true;
        state.ballast_pools = vec![exhausted, healthy, unknown, alias];
        let text = render(&state, "fixture");
        validate_exposition(&text).unwrap();
        for expected in [
            "sbh_ballast_reserve_state{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",state=\"exhausted\"} 1\n",
            "sbh_ballast_present_bytes{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"} 0\n",
            "sbh_ballast_inventory_authoritative{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"} 1\n",
            "sbh_ballast_refill_blocked{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",reason=\"pressure_policy\"} 1\n",
            "sbh_ballast_refill_blocked{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",reason=\"safety_floor\"} 1\n",
            "sbh_ballast_reserve_state{mount=\"/unreadable\",ballast_dir=\"/unreadable/.sbh/ballast\",state=\"unknown\"} 1\n",
            "sbh_ballast_inventory_authoritative{mount=\"/unreadable\",ballast_dir=\"/unreadable/.sbh/ballast\"} 0\n",
            "sbh_ballast_present_bytes{mount=\"/healthy\",ballast_dir=\"/healthy/.sbh/ballast\"} 16384\n",
            "sbh_ballast_reserve_state{mount=\"/healthy\",ballast_dir=\"/healthy/.sbh/ballast\",state=\"healthy\"} 1\n",
            "sbh_ballast_inventory_complete 0\n",
            "sbh_ballast_files{state=\"total\"} 12\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?}\n{text}");
        }
        assert!(!text.contains("sbh_ballast_present_bytes{mount=\"/unreadable\""));
        assert!(!text.contains("sbh_ballast_files{state=\"available\"}"));
        assert!(!text.contains("mount=\"/alias\""));

        state.ballast_pools.remove(2);
        let recovered = render(&state, "fixture");
        assert!(recovered.contains("sbh_ballast_inventory_complete 1\n"));
        assert!(recovered.contains("sbh_ballast_files{state=\"available\"} 4\n"));
        assert!(recovered.contains("sbh_ballast_files{state=\"total\"} 8\n"));
    }

    #[test]
    fn reserve_metrics_follow_observed_partial_release_and_recovery() {
        let mut state = sample_state();
        let published = chrono::DateTime::parse_from_rfc3339(&state.last_updated)
            .unwrap()
            .timestamp();
        let observation_time = chrono::DateTime::parse_from_rfc3339("2026-09-02T00:01:30Z")
            .unwrap()
            .timestamp();
        for (available, bytes, band) in [
            (0, 0, "exhausted"),
            (1, 4096, "critical"),
            (2, 8192, "depleted"),
            (4, 16_384, "healthy"),
        ] {
            state.ballast_pools = vec![observed_pool("/data", available, 4, bytes, 16_384)];
            // Legacy counts deliberately disagree throughout the sequence.
            state.ballast.available = 99;
            state.ballast_pools[0].available = 99;
            state.ballast_pools[0].releasable_bytes = 99;
            let reserve = state.ballast_pools[0].reserve.as_mut().unwrap();
            reserve.refill_in_progress = band != "healthy";
            let text = render(&state, "fixture");
            validate_exposition(&text).unwrap();
            assert!(text.contains(&format!(
                "sbh_ballast_reserve_state{{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",state=\"{band}\"}} 1\n"
            )));
            assert!(text.contains(&format!(
                "sbh_ballast_present_bytes{{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"}} {bytes}\n"
            )));
            assert!(text.contains(&format!(
                "sbh_ballast_files{{state=\"available\"}} {available}\n"
            )));
            assert!(text.contains(&format!(
                "sbh_state_last_updated_timestamp_seconds {published}\n"
            )));
            assert!(text.contains(&format!(
                "sbh_ballast_reserve_observed_timestamp_seconds{{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"}} {observation_time}\n"
            )));
            assert!(text.contains(&format!(
                "sbh_ballast_refill_in_progress{{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"}} {}\n",
                u8::from(band != "healthy")
            )));
            assert_eq!(
                text,
                render(&state, "fixture"),
                "no reader wall clock enters rendering"
            );
        }
    }

    #[test]
    fn reserve_metrics_expire_stale_future_invalid_and_pending_evidence() {
        for (observed_at, authoritative, blocker, has_timestamp) in [
            ("2026-09-02T00:00:01Z", true, "observation_stale", true),
            ("2026-09-02T00:01:32Z", true, "observation_stale", false),
            ("invalid", true, "observation_stale", false),
            ("", false, "not_evaluated", false),
        ] {
            let mut state = sample_state();
            let reserve = state.ballast_pools[0].reserve.as_mut().unwrap();
            reserve.observed_at = observed_at.into();
            reserve.inventory_authoritative = authoritative;
            reserve.refill_in_progress = true;
            reserve.refill_blockers = vec![
                BallastRefillBlocker::PressurePolicy,
                BallastRefillBlocker::SafetyFloor,
            ];
            let text = render(&state, "fixture");
            validate_exposition(&text).unwrap();
            assert!(text.contains("sbh_ballast_reserve_state{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",state=\"unknown\"} 1\n"));
            assert!(text.contains("sbh_ballast_inventory_complete 0\n"));
            assert!(text.contains("sbh_ballast_refill_in_progress{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"} 0\n"));
            assert!(text.contains("sbh_ballast_refill_blocked{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",reason=\"pressure_policy\"} 1\n"));
            assert!(text.contains("sbh_ballast_refill_blocked{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",reason=\"safety_floor\"} 0\n"));
            assert!(text.contains(&format!(
                "sbh_ballast_refill_blocked{{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",reason=\"{blocker}\"}} 1\n"
            )));
            assert_eq!(
                text.contains("sbh_ballast_reserve_observed_timestamp_seconds{mount=\"/data\""),
                has_timestamp,
                "{observed_at}"
            );
            assert!(!text.contains("sbh_ballast_present_bytes{"));
            assert!(!text.contains("sbh_ballast_files{state=\"available\"}"));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reserve_metrics_never_restore_legacy_or_stopped_inventory_as_current() {
        let mut stopped = sample_state();
        stopped.stopped_at = Some(stopped.last_updated.clone());
        let mut invalid_publication = sample_state();
        invalid_publication.last_updated = "invalid".into();
        let mut restarted = sample_state();
        restarted.run_id = "new-daemon-run".into();
        restarted.ballast_pools[0].reserve = None;
        let mut replaced = sample_state();
        replaced.ballast_pools[0].ballast_dir = "/data/replacement".into();
        let mut legacy = sample_state();
        legacy.ballast_pools.clear();

        for state in [stopped, invalid_publication, restarted, replaced, legacy] {
            let text = render(&state, "fixture");
            validate_exposition(&text).unwrap();
            assert!(text.contains("sbh_ballast_inventory_complete 0\n"));
            assert!(!text.contains("sbh_ballast_present_bytes{"));
            assert!(!text.contains("sbh_ballast_files{state=\"available\"}"));
            assert!(!text.contains("state=\"healthy\"} 1"));
            assert!(!text.contains("state=\"exhausted\"} 1"));
            if state.last_updated == "invalid" {
                assert!(!text.contains("sbh_state_last_updated_timestamp_seconds"));
            }
        }

        for (pending, reload_pending) in [(true, false), (false, true)] {
            let mut state = sample_state();
            state.discovery = Some(crate::daemon::self_monitor::DiscoveryState {
                pending,
                reload_pending,
                ..Default::default()
            });
            state.ballast_pools.clear();
            state.ballast.total = 0;
            let text = render(&state, "fixture");
            validate_exposition(&text).unwrap();
            assert!(text.contains("sbh_ballast_inventory_complete 0\n"));
            assert!(!text.contains("sbh_ballast_files{"));

            // Pending rediscovery does not erase independently observed
            // existing pools, but they cannot establish whole-plan totals.
            state.ballast_pools = vec![
                observed_pool("/data", 4, 4, 16_384, 16_384),
                observed_pool("/empty", 0, 4, 0, 16_384),
            ];
            let text = render(&state, "fixture");
            validate_exposition(&text).unwrap();
            assert!(text.contains("sbh_ballast_inventory_complete 0\n"));
            assert!(!text.contains("sbh_ballast_files{"));
            assert!(text.contains("sbh_ballast_present_bytes{mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\"} 16384\n"));
            assert!(text.contains("sbh_ballast_present_bytes{mount=\"/empty\",ballast_dir=\"/empty/.sbh/ballast\"} 0\n"));
            assert!(text.contains(
                "mount=\"/data\",ballast_dir=\"/data/.sbh/ballast\",state=\"healthy\"} 1\n"
            ));
            assert!(text.contains(
                "mount=\"/empty\",ballast_dir=\"/empty/.sbh/ballast\",state=\"exhausted\"} 1\n"
            ));

            state.discovery = None;
            let text = render(&state, "fixture");
            assert!(text.contains("sbh_ballast_inventory_complete 1\n"));
            assert!(text.contains("sbh_ballast_files{state=\"available\"} 4\n"));
            assert!(text.contains("sbh_ballast_files{state=\"total\"} 8\n"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn reserve_metrics_keep_native_paths_distinct_and_escape_display_labels() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut state = sample_state();
        state.ballast_pools.clear();
        for suffix in [0xfe, 0xff] {
            let mut pool = observed_pool("/native", 1, 4, 4096, 16_384);
            let mut bytes = b"/native-".to_vec();
            bytes.push(suffix);
            let mount = PathBuf::from(OsString::from_vec(bytes));
            let directory = mount.join("pool-\"\\\n");
            pool.mount = mount.to_string_lossy().into_owned();
            pool.ballast_dir = directory.to_string_lossy().into_owned();
            let reserve = pool.reserve.as_mut().unwrap();
            reserve.mount_point = mount;
            reserve.ballast_dir = directory;
            state.ballast_pools.push(pool);
        }
        assert_eq!(state.ballast_pools[0].mount, state.ballast_pools[1].mount);
        let text = render(&state, "fixture");
        validate_exposition(&text).unwrap();
        let present: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("sbh_ballast_present_bytes{"))
            .collect();
        assert_eq!(present.len(), 2);
        assert_ne!(present[0], present[1]);
        assert!(present[0].contains("mount_native_hex=\"2f6e61746976652dfe\""));
        assert!(present[1].contains("mount_native_hex=\"2f6e61746976652dff\""));
        assert!(
            present
                .iter()
                .all(|line| line.contains("ballast_dir_native_hex="))
        );
        assert!(text.contains("sbh_ballast_files{state=\"available\"} 2\n"));
    }

    #[test]
    fn inode_metrics_preserve_byte_metrics_and_distinguish_unknown_from_zero() {
        use crate::core::config::InodePressureConfig;
        use crate::monitor::inode_pressure::classify_inode_pressure;
        use crate::monitor::pid::PressureLevel;
        use crate::platform::pal::InodeStats;

        let mut state = sample_state();
        let unknown = render(&state, "fixture");
        assert!(unknown.contains("sbh_mount_inode_accounting_known{mount=\"/data\"} 0\n"));
        assert!(!unknown.contains("sbh_mount_inodes_available{mount=\"/data\"}"));
        state.mount_controllers[0].inode_pressure = classify_inode_pressure(
            InodeStats::new(1000, 0, 0).unwrap(),
            &InodePressureConfig::default(),
            PressureLevel::Green,
        );
        let text = render(&state, "fixture");
        validate_exposition(&text).unwrap();
        for expected in [
            "sbh_mount_inode_accounting_known{mount=\"/data\"} 1\n",
            "sbh_mount_inodes_total{mount=\"/data\"} 1000\n",
            "sbh_mount_inodes_available{mount=\"/data\"} 0\n",
            "sbh_mount_inode_free_ratio{mount=\"/data\"} 0\n",
            "sbh_mount_inode_pressure_level{mount=\"/data\",level=\"critical\"} 1\n",
            "sbh_mount_inode_pressure_level{mount=\"/data\",level=\"green\"} 0\n",
            "sbh_mount_free_ratio{mount=\"/data\"} 0.125\n",
            "sbh_mount_fill_rate_bytes_per_second{mount=\"/data\"} 2048.5\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?}");
        }
    }

    #[test]
    fn split_sample_treats_quoted_commas_braces_and_escapes_as_data() {
        let cases = [
            (r#"sbh_info{policy_mode="enforce,",run_id=""} 1"#, "1"),
            (r#"a{x="a\"b\\c",y="{}"} 2.5"#, "2.5"),
            ("a{} 3", "3"),
            ("a 4", "4"),
        ];
        for (line, value) in cases {
            let (name, rest) = split_sample(line).unwrap_or_else(|| panic!("{line}"));
            assert!(name == "sbh_info" || name == "a", "{line}");
            assert_eq!(rest.trim(), value, "{line}");
        }
        for bad in [
            r#"a{x="unterminated} 1"#,
            "a{x=bare} 1",
            r#"a{x="1"y="2"} 1"#,
            r#"a{="1"} 1"#,
            "a{x=\"1\"",
        ] {
            assert!(split_sample(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn label_values_are_escaped_and_the_stopped_daemon_reports_down() {
        let text = render(&sample_state(), "abc123");
        assert!(
            text.contains("sbh_mount_free_ratio{mount=\"/weird\\\"mount\\\\name\"} 0.55\n"),
            "{text}"
        );
        let mut stopped = sample_state();
        stopped.stopped_at = Some("2026-09-02T00:02:00Z".to_string());
        let text = render(&stopped, "abc123");
        assert!(text.contains("sbh_up 0\n"), "{text}");
        validate_exposition(&text).unwrap();
    }

    #[test]
    fn validator_rejects_the_mistakes_it_is_there_for() {
        assert!(
            validate_exposition("sbh_up 1\n").is_err(),
            "sample before HELP"
        );
        assert!(
            validate_exposition("# HELP sbh_up x\n# TYPE sbh_up gauge\nsbh_up 1")
                .unwrap_err()
                .contains("newline")
        );
        assert!(
            validate_exposition("# HELP sbh_up x\n# TYPE sbh_up gauge\nsbh_up 1\n# HELP sbh_up y\n# TYPE sbh_up gauge\n")
                .unwrap_err()
                .contains("second HELP"),
            "a family carries one HELP line"
        );
        assert!(
            validate_exposition("# HELP a x\n# TYPE a gauge\na 1\n# HELP b x\n# TYPE b gauge\nb 1\n# HELP a y\n# TYPE a gauge\na 2\n")
                .unwrap_err()
                .contains("twice")
        );
        assert!(
            validate_exposition("# HELP 1bad x\n# TYPE 1bad gauge\n1bad 1\n")
                .unwrap_err()
                .contains("illegal")
        );
        assert!(
            validate_exposition("# HELP a x\n# TYPE a gauge\na{mount=/data} 1\n")
                .unwrap_err()
                .contains("not a sample")
        );
        assert!(
            validate_exposition("# HELP a x\n# TYPE a gauge\na abc\n")
                .unwrap_err()
                .contains("bad value")
        );
    }

    #[test]
    fn write_atomic_leaves_no_temp_file_and_a_readable_export() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested").join("metrics.prom");
        write_atomic(&path, "# HELP sbh_up x\n# TYPE sbh_up gauge\nsbh_up 1\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# HELP sbh_up x\n# TYPE sbh_up gauge\nsbh_up 1\n"
        );
        assert!(!path.with_extension("prom.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }
}
