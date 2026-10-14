//! Report-only host RAM-scratch checks through `sbh check --ram-scratch`.

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
            .help("Total metadata-attribution entry budget, default 20000 (1..100000)"))
        .arg(Arg::new("ram_scratch_depth").long("ram-scratch-depth")
            .requires("ram_scratch").value_parser(value_parser!(usize))
            .help("Attribution directory depth below each top-level child, default 8 (0..32)"))
}

#[derive(Debug, Serialize)]
struct Report {
    #[serde(flatten)]
    host: ScratchReport,
    attribution_requested: bool,
    attribution: Vec<MountAttribution>,
}

/// Dispatch only the explicit report-only RAM-scratch mode.
pub fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
    let Some(("check", command)) = matches.subcommand() else {
        return Ok(None);
    };
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
    let attribution = AttributionLimits {
        top: command
            .get_one::<usize>("ram_scratch_top")
            .copied()
            .unwrap_or(10),
        max_entries: command
            .get_one::<usize>("ram_scratch_max_entries")
            .copied()
            .unwrap_or(20_000),
        max_depth: command
            .get_one::<usize>("ram_scratch_depth")
            .copied()
            .unwrap_or(8),
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
