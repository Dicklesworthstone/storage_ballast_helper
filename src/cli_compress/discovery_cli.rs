//! Read-only cold-file discovery exposed through the existing compress command.

use std::io::{self, Write};

use clap::{ArgMatches, Args, Command, FromArgMatches};
use serde::Serialize;
use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::scanner::compression::CompressionPolicy;
use storage_ballast_helper::scanner::compression::discovery::{
    self, DiscoveryLimits, DiscoveryReport,
};

#[derive(Debug, Args)]
struct DiscoveryOptions {
    /// Discover cold metadata candidates beneath explicit directories; never rewrite files.
    #[arg(long, conflicts_with_all = ["apply", "recover_journal", "allow_zstd_feature", "quiescent"])]
    discover: bool,
    /// Maximum directory depth below each root (0 examines root-level files only).
    #[arg(long, requires = "discover")]
    max_depth: Option<usize>,
    /// Maximum directory entries examined, including excluded entries.
    #[arg(long, requires = "discover")]
    max_entries: Option<usize>,
    /// Maximum directories enumerated.
    #[arg(long, requires = "discover")]
    max_directories: Option<usize>,
    /// Separate cooperative discovery deadline, from 1 to 60 seconds.
    #[arg(long, requires = "discover")]
    discovery_timeout_secs: Option<u64>,
    /// Resume after the native pathname encoded by a previous discovery's token.
    #[arg(long, requires = "discover", value_name = "HEX")]
    after_hex: Option<String>,
}

pub(super) fn augment(command: Command) -> Command {
    DiscoveryOptions::augment_args(command)
}

#[derive(Debug, Serialize)]
struct CandidatePath {
    /// Display only; execution must not reconstruct a path from lossy UTF-8.
    path: String,
    native_path_hex: String,
}

#[derive(Debug, Serialize)]
struct Output {
    schema: &'static str,
    read_only: bool,
    mutation_attempted: bool,
    discovery: DiscoveryReport,
    candidates: Vec<CandidatePath>,
    exit_code: i32,
}

pub(super) fn run(
    matches: &ArgMatches,
    subcommand: &ArgMatches,
    options: &super::Options,
) -> io::Result<Option<i32>> {
    let flags = DiscoveryOptions::from_arg_matches(subcommand)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    if !flags.discover {
        return Ok(None);
    }
    // Defense in depth for any future caller constructing matches directly.
    // This route contains no call to compression::run or any mutation backend.
    if options.apply || options.recover_journal.is_some()
        || options.allow_zstd_feature || options.quiescent
    {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "directory discovery is read-only and cannot be combined with apply or recovery"));
    }
    let result = execute(matches, options, &flags);
    let mut out = io::stdout().lock();
    let code = match result {
        Ok(report) => {
            if matches.get_flag("json") {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)?;
            } else if !matches.get_flag("quiet") {
                write_human(&mut out, &report)?;
            }
            report.exit_code
        }
        Err((code, error)) => {
            if matches.get_flag("json") {
                serde_json::to_writer(&mut out, &serde_json::json!({
                    "schema": "sbh.compression.discovery.v1",
                    "read_only": true, "mutation_attempted": false,
                    "error": error, "exit_code": code,
                }))?;
                writeln!(out)?;
            } else {
                eprintln!("sbh: compression discovery failed: {error}");
            }
            code
        }
    };
    out.flush()?;
    Ok(Some(code))
}

fn execute(
    matches: &ArgMatches,
    options: &super::Options,
    flags: &DiscoveryOptions,
) -> Result<Output, (i32, String)> {
    let defaults = DiscoveryLimits::default();
    let after = flags.after_hex.as_deref()
        .map(discovery::continuation_path).transpose()
        .map_err(|error| (super::io_exit_code(&error), error.to_string()))?;
    let limits = DiscoveryLimits {
        max_depth: flags.max_depth.unwrap_or(defaults.max_depth),
        max_entries: flags.max_entries.unwrap_or(defaults.max_entries),
        max_directories: flags.max_directories.unwrap_or(defaults.max_directories),
        timeout_secs: flags.discovery_timeout_secs.unwrap_or(defaults.timeout_secs),
        after,
    };
    let policy = CompressionPolicy {
        min_size_bytes: options.min_size_bytes,
        min_age_secs: options.min_age_secs,
        max_files: options.max_files,
        max_bytes: options.max_bytes,
        timeout_secs: options.timeout_secs,
        min_free_bytes: options.min_free_bytes,
    };
    let explicit = matches.get_one::<std::path::PathBuf>("config");
    let config = Config::load(explicit.map(std::path::PathBuf::as_path))
        .map_err(|error| (1, error.to_string()))?;
    let selection = discovery::discover(
        &options.paths, &policy, &limits, &config,
        &storage_ballast_helper::platform::current(),
    ).map_err(|error| (super::io_exit_code(&error), error.to_string()))?;
    let candidates = selection.paths().into_iter().map(|path| CandidatePath {
        path: path.to_string_lossy().into_owned(),
        native_path_hex: storage_ballast_helper::core::hex_lower(path.as_os_str().as_encoded_bytes()),
    }).collect();
    Ok(Output {
        schema: "sbh.compression.discovery.v1",
        read_only: true,
        mutation_attempted: false,
        exit_code: if selection.report().complete { 0 } else { 4 },
        discovery: selection.report().clone(),
        candidates,
    })
}

fn write_human(out: &mut impl Write, report: &Output) -> io::Result<()> {
    writeln!(out, "Cold-file discovery: {} candidate(s), {} logical bytes.",
        report.discovery.selected_files, report.discovery.selected_bytes)?;
    writeln!(out, "Read-only metadata selection; filesystem compression and live-use eligibility are not yet established.")?;
    for candidate in &report.candidates {
        // Debug formatting escapes control characters rather than permitting
        // an unusual filename to forge another output line.
        writeln!(out, "  {:?}", candidate.path)?;
    }
    for (reason, count) in &report.discovery.skipped {
        writeln!(out, "Skipped {count}: {reason}")?;
    }
    if let Some(reason) = &report.discovery.stop_reason {
        writeln!(out, "Discovery status: {reason}")?;
    }
    if let Some(token) = &report.discovery.resume_after_hex {
        writeln!(out, "Resume discovery of the same roots with --after-hex {token}")?;
    }
    writeln!(out, "No extents rewritten and no compression journal created.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_never_accepts_mutation_flags_or_recovery() {
        for flag in ["--apply", "--allow-zstd-feature", "--quiescent"] {
            assert!(super::super::command().try_get_matches_from([
                "compress", "--discover", flag, "/tmp/input",
            ]).is_err(), "{flag}");
        }
        assert!(super::super::command().try_get_matches_from([
            "compress", "--discover", "--recover-journal", "/tmp/run.jsonl",
        ]).is_err());
    }

    #[test]
    fn traversal_flags_require_discovery_and_global_flags_survive() {
        for (flag, value) in [
            ("--max-depth", "2"), ("--max-entries", "100"),
            ("--max-directories", "10"), ("--discovery-timeout-secs", "5"),
            ("--after-hex", "2f746d702f66696c65"),
        ] {
            assert!(super::super::command().try_get_matches_from([
                "compress", flag, value, "/tmp/input",
            ]).is_err(), "{flag}");
        }
        let matches = crate::cli_command().try_get_matches_from([
            "sbh", "compress", "--discover", "--json", "--max-depth", "0", "/tmp/input",
        ]).unwrap();
        assert!(matches.get_flag("json"));
        let (_, subcommand) = matches.subcommand().unwrap();
        let flags = DiscoveryOptions::from_arg_matches(subcommand).unwrap();
        assert!(flags.discover);
        assert_eq!(flags.max_depth, Some(0));
    }
}
