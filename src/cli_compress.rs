//! Explicit operator entry point for lossless Btrfs compression.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{ArgMatches, Args, Command, FromArgMatches};
use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::scanner::compression::{
    self, CompressionMode, CompressionPolicy, CompressionReport,
};

#[derive(Debug, Args)]
struct Options {
    /// Explicit regular files to inspect. Directories and symlinks are rejected.
    #[arg(required = true, num_args = 1.., value_hint = clap::ValueHint::FilePath)]
    paths: Vec<PathBuf>,
    /// Rewrite eligible extents; the default is a read-only eligibility preview.
    #[arg(long, conflicts_with = "dry_run", requires_all = ["allow_zstd_feature", "quiescent"])]
    apply: bool,
    /// Explicitly request the default read-only preview.
    #[arg(long)]
    dry_run: bool,
    /// Accept that zstd can enable a filesystem feature requiring Linux >= 4.14.
    #[arg(long)]
    allow_zstd_feature: bool,
    /// Confirm writers and snapshot/reflink creation are stopped for this pass.
    #[arg(long)]
    quiescent: bool,
    /// Minimum logical file size in bytes (not estimated reclaim).
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    min_size_bytes: u64,
    /// Minimum modification age in seconds; values below 3600 are refused.
    #[arg(long, default_value_t = 86_400)]
    min_age_secs: u64,
    /// Maximum number of explicit files considered in this pass (1..4096).
    #[arg(long, default_value_t = 128)]
    max_files: usize,
    /// Maximum logical bytes admitted for rewrite and verification work.
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024)]
    max_bytes: u64,
    /// Cooperative deadline; in-flight kernel calls cannot be forcibly stopped.
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,
    /// Available-byte floor retained beyond two bounded rewrite chunks.
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    min_free_bytes: u64,
}

pub(super) fn command() -> Command {
    Options::augment_args(Command::new("compress")
        .about("Preview or apply lossless compression to selected cold, unshared Btrfs files")
        .after_help("Preview is the default. Linux x86-64/AArch64 and openat2 support are required; extent-tree inspection normally requires root.\n\nApply preserves contents and verifies SHA-256, size and mtime. Protected, leased, open, executing, mapped, shared, already-compressed and low-headroom files are refused. There is no force override.\n\nFIEMAP inspection is not a snapshot lock. --quiescent acknowledges that concurrent writers, snapshots and reflinks have been stopped. A deadline stops between bounded calls; postflight verification may take additional time.\n\nExamples:\n  sudo sbh compress --json -- /data/old-debug-binary /data/old-session.jsonl\n  sudo sbh compress --apply --allow-zstd-feature --quiescent --json -- /data/old-debug-binary\n\nThis command does not enable automatic daemon compression or change deletion policy."))
}

pub(super) fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
    let Some(("compress", subcommand)) = matches.subcommand() else { return Ok(None); };
    let options = Options::from_arg_matches(subcommand)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let policy = CompressionPolicy {
        min_size_bytes: options.min_size_bytes,
        min_age_secs: options.min_age_secs,
        max_files: options.max_files,
        max_bytes: options.max_bytes,
        timeout_secs: options.timeout_secs,
        min_free_bytes: options.min_free_bytes,
    };
    let mode = CompressionMode {
        apply: options.apply && !options.dry_run,
        allow_zstd_feature: options.allow_zstd_feature,
        quiescent: options.quiescent,
    };
    let explicit_config = matches.get_one::<PathBuf>("config");
    let result = Config::load(explicit_config.map(PathBuf::as_path))
        .map_err(|error| error.to_string())
        .and_then(|config| compression::run(&options.paths, &policy, mode, &config,
            &storage_ballast_helper::platform::current()).map_err(|error| error.to_string()));
    let mut out = io::stdout().lock();
    match result {
        Ok(report) => {
            if matches.get_flag("json") {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)?;
            } else if !matches.get_flag("quiet") {
                write_human(&mut out, &report)?;
            }
            out.flush()?;
            Ok(Some(report.exit_code))
        }
        Err(error) => {
            if matches.get_flag("json") {
                serde_json::to_writer(&mut out, &serde_json::json!({
                    "schema": "sbh.compression.v1", "dry_run": !mode.apply,
                    "mutation_attempted": false, "error": error, "exit_code": 1,
                }))?;
                writeln!(out)?;
                out.flush()?;
            } else {
                eprintln!("sbh: compression did not start: {error}");
            }
            Ok(Some(1))
        }
    }
}

fn write_human(out: &mut impl Write, report: &CompressionReport) -> io::Result<()> {
    let mode = if report.dry_run { "preview" } else { "apply" };
    writeln!(out, "Btrfs compression {mode}; {} file(s) considered.", report.files.len())?;
    for file in &report.files {
        writeln!(out, "{}: {}\n  {}", file.outcome, file.path.display(), file.detail)?;
        if let Some(before) = file.physical_data_bytes_before {
            writeln!(out, "  Physical data bytes before: {before}")?;
        }
        if let Some(after) = file.physical_data_bytes_after {
            writeln!(out, "  Physical data bytes after:  {after}")?;
        }
        if let Some(evidence) = &file.reclaim {
            writeln!(out,
                "  Referenced savings: {}; growth: {}; old allocations pending: {}; confirmed net data-only reclaim: {} bytes.",
                evidence.referenced_bytes_saved, evidence.referenced_bytes_added,
                evidence.old_data_bytes_pending, evidence.confirmed_data_bytes_reclaimed)?;
        }
        if file.mutation_attempted {
            writeln!(out, "  Content/size/mtime verified: {}", file.content_verified)?;
        }
    }
    if let Some(reason) = &report.stop_reason {
        writeln!(out, "Stopped: {reason}. Unvisited files: {}.", report.unvisited_files)?;
    }
    writeln!(out, "Physical data accounting excludes metadata and is not a claim about immediately available mount space.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, clap::Error> {
        let matches = command().try_get_matches_from(args)?;
        Options::from_arg_matches(&matches)
    }

    #[test]
    fn preview_is_default_and_apply_requires_both_acknowledgements() {
        let preview = parse(&["compress", "/tmp/file"]).unwrap();
        assert!(!preview.apply);
        assert_eq!(preview.min_age_secs, 86_400);
        for args in [
            vec!["compress", "--apply", "/tmp/file"],
            vec!["compress", "--apply", "--allow-zstd-feature", "/tmp/file"],
            vec!["compress", "--apply", "--quiescent", "/tmp/file"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
        assert!(parse(&["compress", "--apply", "--allow-zstd-feature", "--quiescent", "/tmp/file"]).unwrap().apply);
    }

    #[test]
    fn preview_and_apply_conflict_and_there_is_no_force_switch() {
        assert!(parse(&["compress", "--dry-run", "--apply", "--allow-zstd-feature", "--quiescent", "/tmp/file"]).is_err());
        assert!(parse(&["compress", "--force", "/tmp/file"]).is_err());
        assert!(parse(&["compress"]).is_err());
    }

    #[test]
    fn entrypoint_exposes_compression_and_preserves_global_arguments() {
        for args in [
            vec!["sbh", "--json", "compress", "/tmp/file"],
            vec!["sbh", "compress", "--json", "--config", "/tmp/config.toml", "/tmp/file"],
        ] {
            let matches = crate::cli_command().try_get_matches_from(args).unwrap();
            assert!(matches.get_flag("json"));
            assert_eq!(matches.subcommand_name(), Some("compress"));
            assert!(!crate::update_mutates_binary(&matches));
        }
    }
}
