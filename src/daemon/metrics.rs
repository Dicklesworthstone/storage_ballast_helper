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

use crate::core::errors::{Result, SbhError};
use crate::daemon::self_monitor::DaemonState;

/// File name of the export, a sibling of `state.json`.
pub const METRICS_FILE_NAME: &str = "metrics.prom";

/// The git sha this binary was built from, as the build script exposes it
/// (`unknown` outside a git checkout).
#[must_use]
pub fn build_git_sha() -> &'static str {
    option_env!("VERGEN_GIT_SHA")
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
    let mut ballast_present = Family::new(
        "sbh_ballast_present_bytes",
        "Ballast bytes currently held on the mount.",
        "gauge",
    );
    let mut ballast_target = Family::new(
        "sbh_ballast_target_bytes",
        "Ballast bytes the reserve controller wants on the mount.",
        "gauge",
    );
    let mut quarantined = Family::new(
        "sbh_quarantine_bytes",
        "Bytes held in quarantine on the mount.",
        "gauge",
    );
    for record in &state.mount_controllers {
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
            ballast_present.sample(&[("mount", &record.mount)], reserve.present_bytes);
            ballast_target.sample(&[("mount", &record.mount)], reserve.target_bytes);
            quarantined.sample(&[("mount", &record.mount)], reserve.quarantined_bytes);
        }
    }
    families.push(capability);
    families.push(controller_state);
    families.push(ballast_present);
    families.push(ballast_target);
    families.push(quarantined);

    let mut ballast_files = Family::new(
        "sbh_ballast_files",
        "Ballast files available and provisioned across every pool.",
        "gauge",
    );
    ballast_files.sample(&[("state", "available")], state.ballast.available);
    ballast_files.sample(&[("state", "total")], state.ballast.total);
    families.push(ballast_files);

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
/// text, validating that a label block closes and its values are quoted.
fn split_sample(line: &str) -> Option<(&str, &str)> {
    if let Some(open) = line.find('{') {
        let close = line[open..].find('}')? + open;
        let labels = &line[open + 1..close];
        for pair in labels.split(',') {
            let (_, value) = pair.split_once('=')?;
            if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
                return None;
            }
        }
        Some((&line[..open], &line[close + 1..]))
    } else {
        let (name, value) = line.split_once(' ')?;
        Some((name, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::cpu_budget::CpuBudgetState;
    use crate::daemon::mount_controller::{
        MountState, MountStateRecord, ReclaimCapability, ReserveState, SurfaceKind,
    };
    use crate::daemon::self_monitor::{
        BallastState, Counters, LastScanState, MountPressure, MountRateState, PolicyStateRecord,
        PressureState, ThreadState, ThreadsState,
    };

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
                rescan_in_secs: Some(20),
                reclaim_capability: ReclaimCapability::Configured,
                reserve_state: Some(ReserveState {
                    present_bytes: 4096,
                    target_bytes: 1 << 30,
                    horizon_minutes: Some(30.0),
                    floor_limited: false,
                    quarantined_bytes: 0,
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
            "sbh_ballast_present_bytes{mount=\"/data\"} 4096\n",
            "sbh_ballast_target_bytes{mount=\"/data\"} 1073741824\n",
            "sbh_ballast_files{state=\"available\"} 3\n",
            "sbh_ballast_releases_total 1\n",
            "sbh_scans_total 12\n",
            "sbh_deletions_total 2\n",
            "sbh_bytes_freed_total 5032071168\n",
            "sbh_policy_mode{mode=\"enforce\"} 1\n",
            "sbh_policy_mode{mode=\"observe\"} 0\n",
            "sbh_thread_up{thread=\"executor\"} 0\n",
            "sbh_thread_up{thread=\"scanner\"} 1\n",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in\n{text}");
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
