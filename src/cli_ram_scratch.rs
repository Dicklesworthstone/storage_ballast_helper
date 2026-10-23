//! Read-only RAM and agent-session scratch diagnostics through `sbh check`.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use serde::Serialize;
use storage_ballast_helper::monitor::ram_scratch::attribution::{
    self, AttributionLimits, MountAttribution,
};
use storage_ballast_helper::monitor::ram_scratch::{self, ScratchLimits, ScratchReport};
use storage_ballast_helper::platform::pal::Platform;

/// Extend the existing check command without changing ordinary disk checks.
pub fn augment(command: Command) -> Command {
    command
        .arg(Arg::new("ram_scratch").long("ram-scratch").action(ArgAction::SetTrue)
            .conflicts_with_all(["path", "target_free", "need", "predict", "allow_unprotected"])
            .help("Report occupied tmpfs against host RAM/swap, including runtime mounts; never clean"))
        .arg(Arg::new("ram_scratch_timeout_secs").long("ram-scratch-timeout-secs")
            .requires("ram_scratch").value_parser(value_parser!(u64).range(1..=60))
            .help("Shared cooperative collection/attribution deadline, default 10 seconds"))
        .arg(Arg::new("ram_scratch_top").long("ram-scratch-top")
            .requires("ram_scratch").value_parser(value_parser!(usize))
            .help("Largest observed top-level entries per occupied mount on warning, default 10 (1..50)"))
        .arg(Arg::new("ram_scratch_max_entries").long("ram-scratch-max-entries")
            .requires("ram_scratch").value_parser(value_parser!(usize))
            .help("Total metadata-attribution entry budget, default 2000000 (1..5000000)"))
        .arg(Arg::new("ram_scratch_depth").long("ram-scratch-depth")
            .requires("ram_scratch").value_parser(value_parser!(usize))
            .help("Attribution directory depth below each top-level child, default 8 (0..32)"))
        .arg(Arg::new("agent_scratch").long("agent-scratch").action(ArgAction::SetTrue)
            .conflicts_with_all(["ram_scratch", "target_free", "need", "predict", "allow_unprotected"])
            .help("Report Claude session scratch and its inactivity evidence; PATH is a temp or claude-UID root; never clean"))
        .arg(Arg::new("agent_scratch_min_idle_days").long("min-idle-days")
            .requires("agent_scratch").value_parser(value_parser!(u32).range(1..=3650))
            .help("Required inactivity of both session tree and transcript, default 7 days"))
        .arg(Arg::new("agent_scratch_transcripts").long("transcript-root")
            .requires("agent_scratch").value_parser(value_parser!(std::path::PathBuf))
            .help("Explicit .claude/projects directory; otherwise resolve each session owner's home"))
        .arg(Arg::new("agent_scratch_timeout_secs").long("agent-scratch-timeout-secs")
            .requires("agent_scratch").value_parser(value_parser!(u64).range(1..=120))
            .help("Shared session inventory deadline, default 30 seconds"))
        .arg(Arg::new("agent_scratch_top").long("agent-scratch-top")
            .requires("agent_scratch").value_parser(value_parser!(usize))
            .help("Largest observed sessions to show, default 25 (1..2048)"))
        .arg(Arg::new("agent_scratch_max_entries").long("agent-scratch-max-entries")
            .requires("agent_scratch").value_parser(value_parser!(usize))
            .help("Total discovery and traversal entry budget, default 2000000 (1..5000000)"))
}

#[derive(Debug, Serialize)]
struct Report {
    #[serde(flatten)]
    host: ScratchReport,
    attribution_requested: bool,
    attribution: Vec<MountAttribution>,
}

/// Dispatch only the explicit read-only scratch-report modes.
pub fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
    let Some(("check", command)) = matches.subcommand() else {
        return Ok(None);
    };
    if command.get_flag("agent_scratch") {
        return run_agent_scratch(matches, command).map(Some);
    }
    if !command.get_flag("ram_scratch") {
        return Ok(None);
    }
    let limits = ScratchLimits {
        timeout_secs: command
            .get_one::<u64>("ram_scratch_timeout_secs")
            .copied()
            .unwrap_or(10),
        ..Default::default()
    };
    let defaults = AttributionLimits::default();
    let attribution = AttributionLimits {
        top: command
            .get_one::<usize>("ram_scratch_top")
            .copied()
            .unwrap_or(defaults.top),
        max_entries: command
            .get_one::<usize>("ram_scratch_max_entries")
            .copied()
            .unwrap_or(defaults.max_entries),
        max_depth: command
            .get_one::<usize>("ram_scratch_depth")
            .copied()
            .unwrap_or(defaults.max_depth),
    };
    // Do not load config or initialize log/state backends for a host diagnostic.
    let result = execute(
        &storage_ballast_helper::platform::current(),
        limits,
        attribution,
    );
    let mut out = io::stdout().lock();
    let code = match result {
        Ok(report) => {
            if matches.get_flag("json") {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)?;
            } else if !matches.get_flag("quiet") {
                write_human(&mut out, &report)?;
            }
            report.host.exit_code
        }
        Err(error) => {
            let code = if error.kind() == io::ErrorKind::InvalidInput {
                1
            } else {
                2
            };
            if matches.get_flag("json") {
                serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({
                        "schema": "sbh.ram_scratch.v1", "read_only": true, "complete": false,
                        "error": error.to_string(), "exit_code": code,
                    }),
                )?;
                writeln!(out)?;
            } else {
                eprintln!("sbh: RAM scratch inspection failed: {error}");
            }
            code
        }
    };
    out.flush()?;
    Ok(Some(code))
}

#[cfg(unix)]
fn run_agent_scratch(matches: &ArgMatches, command: &ArgMatches) -> io::Result<i32> {
    use std::path::PathBuf;
    use storage_ballast_helper::core::config::Config;
    use storage_ballast_helper::monitor::agent_scratch::{self, Limits};

    let result = (|| {
        let config = Config::load(matches.get_one::<PathBuf>("config").map(PathBuf::as_path))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let platform = storage_ballast_helper::platform::pal::detect_platform()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let roots = if let Some(path) = command.get_one::<PathBuf>("path") {
            vec![path.clone()]
        } else {
            let mut roots = config.scanner.root_paths.clone();
            roots.extend(platform.temp_dirs());
            for path in ["/tmp", "/data/tmp"] {
                roots.push(PathBuf::from(path));
            }
            // Missing default scanner roots are common on other platforms;
            // inaccessible roots must remain visible as incomplete evidence.
            // Explicit PATH is always inspected and diagnosed.
            roots.retain(|path| include_default_agent_root(path));
            roots.sort();
            roots.dedup();
            roots
        };
        let defaults = Limits::default();
        let limits = Limits {
            min_idle_days: command
                .get_one::<u32>("agent_scratch_min_idle_days")
                .copied()
                .unwrap_or(defaults.min_idle_days),
            timeout: Duration::from_secs(
                command
                    .get_one::<u64>("agent_scratch_timeout_secs")
                    .copied()
                    .unwrap_or(30),
            ),
            top: command
                .get_one::<usize>("agent_scratch_top")
                .copied()
                .unwrap_or(defaults.top),
            max_entries: command
                .get_one::<usize>("agent_scratch_max_entries")
                .copied()
                .unwrap_or(defaults.max_entries),
            ..defaults
        };
        agent_scratch::inspect(
            platform,
            &roots,
            command
                .get_one::<PathBuf>("agent_scratch_transcripts")
                .map(PathBuf::as_path),
            &config.scanner.protected_paths,
            limits,
        )
    })();
    let mut out = io::stdout().lock();
    let code = match result {
        Ok(report) => {
            if matches.get_flag("json") {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)?;
            } else if !matches.get_flag("quiet") {
                write_agent_scratch(&mut out, &report)?;
            }
            report.exit_code
        }
        Err(error) => {
            let code = if error.kind() == io::ErrorKind::InvalidInput {
                1
            } else {
                2
            };
            if matches.get_flag("json") {
                serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({
                        "schema": "sbh.agent_scratch.v1", "read_only": true,
                        "complete": false, "error": error.to_string(), "exit_code": code,
                    }),
                )?;
                writeln!(out)?;
            } else {
                eprintln!("sbh: agent scratch inspection failed: {error}");
            }
            code
        }
    };
    out.flush()?;
    Ok(code)
}

#[cfg(unix)]
fn include_default_agent_root(path: &std::path::Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_dir(),
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

#[cfg(not(unix))]
fn run_agent_scratch(_matches: &ArgMatches, _command: &ArgMatches) -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "agent scratch inspection requires Unix",
    ))
}

#[cfg(unix)]
fn write_agent_scratch(
    out: &mut impl Write,
    report: &storage_ballast_helper::monitor::agent_scratch::Report,
) -> io::Result<()> {
    writeln!(
        out,
        "Agent scratch: {} sessions, {} idle for at least {} days; {} entries examined{}",
        report.sessions_found,
        report.idle_sessions,
        report.min_idle_days,
        report.entries_examined,
        if report.complete {
            ""
        } else {
            " (partial observations)"
        }
    )?;
    for session in &report.sessions {
        writeln!(
            out,
            "  {:?} {:?}: logical={} bytes, allocated={} bytes; tree={} h, transcript={} h",
            session.state,
            session.path.as_os_str(),
            session.observed_logical_bytes,
            session.observed_allocated_bytes,
            session
                .tree_idle_hours
                .map_or_else(|| "unknown".into(), |age| age.to_string()),
            session
                .transcript_idle_hours
                .map_or_else(|| "unknown".into(), |age| age.to_string())
        )?;
        for reason in session.reasons.iter().chain(&session.protections) {
            writeln!(out, "    {reason}")?;
        }
    }
    for issue in &report.issues {
        writeln!(out, "  Incomplete: {issue}")?;
    }
    if report.omitted_sessions > 0 {
        writeln!(
            out,
            "  {} smaller sessions omitted by --agent-scratch-top",
            report.omitted_sessions
        )?;
    }
    writeln!(
        out,
        "Report only: idle sessions need manual review. Shared/reflinked blocks are included in allocation; reclaimable bytes are unknown. No files are changed."
    )
}

fn execute(
    platform: &dyn Platform,
    limits: ScratchLimits,
    attribution_limits: AttributionLimits,
) -> io::Result<Report> {
    limits.validate()?;
    attribution_limits.validate()?;
    let deadline = Instant::now() + Duration::from_secs(limits.timeout_secs);
    let mut host = ram_scratch::inspect(platform, limits)?;
    let attribution_requested = host
        .assessment
        .as_ref()
        .is_some_and(ram_scratch::ScratchAssessment::warning);
    let attribution = if attribution_requested {
        let mounts = host
            .assessment
            .as_ref()
            .map(|report| {
                report
                    .mounts
                    .iter()
                    .filter(|mount| mount.used_bytes > 0)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // Unused mounts require no expensive child walk. Every occupied mount
        // gets a report, including explicit unknowns after the shared deadline.
        attribution::inspect(&mounts, attribution_limits, deadline)?
    } else {
        Vec::new()
    };
    if attribution.iter().any(|report| !report.complete) {
        host.complete = false;
        host.exit_code = 4;
        host.issues.push("top-entry attribution is incomplete; sampled sizes are not full totals and missing ages are unknown".into());
    }
    Ok(Report {
        host,
        attribution_requested,
        attribution,
    })
}

fn write_human(out: &mut impl Write, report: &Report) -> io::Result<()> {
    if let Some(assessment) = &report.host.assessment {
        let label = if assessment.warning() {
            "WARNING"
        } else {
            "RAM-SCRATCH"
        };
        writeln!(out, "[{label}] {}", assessment.summary())?;
    } else {
        writeln!(
            out,
            "RAM scratch collector unsupported: {}",
            report.host.scope
        )?;
    }
    for mount in &report.attribution {
        writeln!(
            out,
            "  {:?}: complete={}, examined={}, omitted mount boundaries={}, symlinks={}",
            mount.mount_path,
            mount.complete,
            mount.entries_examined,
            mount.mount_boundaries_skipped,
            mount.symlinks_skipped
        )?;
        for entry in &mount.entries {
            let age = entry
                .idle_hours
                .map_or_else(|| "unknown".to_owned(), |hours| format!("{hours} h"));
            writeln!(
                out,
                "    {:?}: uid={}, observed allocated={} bytes, newest-change age={}, complete={}",
                entry.path, entry.owner_uid, entry.observed_allocated_bytes, age, entry.complete
            )?;
        }
        for issue in &mount.issues {
            writeln!(out, "    Incomplete: {issue}")?;
        }
    }
    for issue in &report.host.issues {
        writeln!(out, "  Incomplete: {issue}")?;
    }
    writeln!(
        out,
        "Read-only diagnostic. RAM + swap is nominal capacity, not a safe allocation allowance. File ages and sampled blocks are not deletion approval. Scope: {}.",
        report.host.scope
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage_ballast_helper::monitor::ram_scratch::{ProcessSwap, ScratchMount, assess};
    use storage_ballast_helper::platform::pal::MemoryInfo;

    #[cfg(unix)]
    #[test]
    fn default_agent_roots_keep_metadata_errors_for_partial_reporting() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("ordinary-file");
        let looped = directory.path().join("looped-root");
        std::fs::write(&file, b"not a scratch directory").unwrap();
        symlink(&looped, &looped).unwrap();

        assert!(include_default_agent_root(directory.path()));
        assert!(!include_default_agent_root(&file));
        assert!(!include_default_agent_root(
            &directory.path().join("missing")
        ));
        assert!(std::fs::metadata(&looped).is_err());
        assert!(
            include_default_agent_root(&looped),
            "metadata failures must reach inspection, not look like absent storage"
        );
    }

    #[test]
    fn agent_session_check_accepts_explicit_roots_and_rejects_mixed_check_modes() {
        let matches = crate::cli_command()
            .try_get_matches_from([
                "sbh",
                "check",
                "--agent-scratch",
                "/data/tmp",
                "--min-idle-days",
                "9",
                "--transcript-root",
                "/home/agent/.claude/projects",
                "--json",
            ])
            .unwrap();
        let check = matches.subcommand().unwrap().1;
        assert!(check.get_flag("agent_scratch"));
        assert_eq!(
            check.get_one::<std::path::PathBuf>("path"),
            Some(&std::path::PathBuf::from("/data/tmp"))
        );
        assert_eq!(
            check.get_one::<u32>("agent_scratch_min_idle_days"),
            Some(&9)
        );
        assert!(matches.get_flag("json"));
        let automatic = crate::cli_command()
            .try_get_matches_from(["sbh", "check", "--agent-scratch"])
            .unwrap();
        assert!(
            automatic
                .subcommand()
                .unwrap()
                .1
                .get_one::<std::path::PathBuf>("path")
                .is_none()
        );
        for extra in [
            vec!["--ram-scratch"],
            vec!["--need", "1G"],
            vec!["--predict", "5"],
            vec!["--min-idle-days", "0"],
        ] {
            assert!(
                crate::cli_command()
                    .try_get_matches_from([vec!["sbh", "check", "--agent-scratch"], extra].concat())
                    .is_err()
            );
        }
        assert!(
            crate::cli_command()
                .try_get_matches_from(["sbh", "check", "--min-idle-days", "7"])
                .is_err()
        );
    }

    #[test]
    fn ordinary_checks_and_other_commands_fall_through_without_io() {
        for arguments in [
            vec!["sbh", "check", "/tmp"],
            vec!["sbh", "status"],
            vec!["sbh", "check", "--need", "5G"],
        ] {
            let matches = crate::cli_command()
                .try_get_matches_from(arguments)
                .unwrap();
            assert_eq!(run(&matches).unwrap(), None);
        }
    }

    #[test]
    fn host_scope_cannot_silently_override_a_disk_scope() {
        for tail in [
            vec!["/tmp"],
            vec!["--need", "5G"],
            vec!["--predict", "10"],
            vec!["--target-free", "20"],
            vec!["--allow-unprotected"],
        ] {
            let arguments = [vec!["sbh", "check", "--ram-scratch"], tail].concat();
            assert!(
                crate::cli_command()
                    .try_get_matches_from(arguments)
                    .is_err()
            );
        }
        assert!(
            crate::cli_command()
                .try_get_matches_from(["sbh", "check", "--ram-scratch-top", "5"])
                .is_err()
        );
        assert!(
            crate::cli_command()
                .try_get_matches_from([
                    "sbh",
                    "check",
                    "--ram-scratch",
                    "--ram-scratch-timeout-secs",
                    "0"
                ])
                .is_err()
        );
    }

    #[test]
    fn global_json_and_config_are_preserved_but_config_is_not_used_by_host_check() {
        let matches = crate::cli_command()
            .try_get_matches_from([
                "sbh",
                "check",
                "--ram-scratch",
                "--json",
                "--config",
                "/missing/config.toml",
            ])
            .unwrap();
        assert!(matches.get_flag("json"));
        assert!(matches.subcommand().unwrap().1.get_flag("ram_scratch"));
        assert!(!crate::update_mutates_binary(&matches));
    }

    #[test]
    fn one_warning_retains_runtime_names_and_partial_evidence() {
        let memory = MemoryInfo {
            total_bytes: 62 << 30,
            available_bytes: 10 << 30,
            swap_total_bytes: 64 << 30,
            swap_free_bytes: 0,
        };
        let mounts = ["/tmp", "/dev/shm", "/run", "/run/user/1000"]
            .iter()
            .enumerate()
            .map(|(id, path)| ScratchMount {
                path: (*path).into(),
                filesystem_id: u64::try_from(id).unwrap(),
                total_bytes: 32 << 30,
                used_bytes: 16 << 30,
                available_bytes: 16 << 30,
            })
            .collect();
        let assessment = assess(
            memory,
            mounts,
            ProcessSwap {
                bytes: 4 << 30,
                inspected: 10,
                unreadable: 0,
                complete: true,
            },
        )
        .unwrap();
        let report = Report {
            host: ScratchReport {
                schema: "sbh.ram_scratch.v1",
                read_only: true,
                supported: true,
                complete: false,
                scope: "fixture",
                assessment: Some(assessment),
                issues: vec!["bounded attribution".into()],
                exit_code: 4,
            },
            attribution_requested: true,
            attribution: Vec::new(),
        };
        let mut output = Vec::new();
        write_human(&mut output, &report).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.matches("[WARNING]").count(), 1);
        for path in ["/tmp", "/dev/shm", "/run", "/run/user/1000"] {
            assert!(text.contains(path));
        }
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["complete"], false);
        assert_eq!(json["exit_code"], 4);
        assert_eq!(json["read_only"], true);
    }
}
