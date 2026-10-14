//! Explicit operator entry point for lossless Btrfs compression.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{ArgMatches, Args, Command, FromArgMatches};
use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::scanner::compression::journal::{self, RecoveryReport};
use storage_ballast_helper::scanner::compression::{
    self, CompressionMode, CompressionPolicy, CompressionReport,
};

mod discovery_cli;

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)] // independent CLI switches
struct Options {
    /// Explicit files, or directory roots with --discover. Symlink roots are rejected.
    #[arg(required_unless_present = "recover_journal", num_args = 1.., value_hint = clap::ValueHint::FilePath)]
    paths: Vec<PathBuf>,
    /// Read a completed/interrupted journal and verify unfinished inputs; never replay mutations.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath,
        conflicts_with_all = ["paths", "apply", "dry_run", "allow_zstd_feature", "quiescent"])]
    recover_journal: Option<PathBuf>,
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
    /// Maximum logical bytes admitted for rewrite or unfinished-input recovery hashing.
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024)]
    max_bytes: u64,
    /// Cooperative deadline for compression or recovery; in-flight I/O may still block.
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,
    /// Available-byte floor retained beyond two bounded rewrite chunks.
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    min_free_bytes: u64,
}

pub fn command() -> Command {
    discovery_cli::augment(Options::augment_args(Command::new("compress")
        .about("Preview or apply lossless compression to selected cold, unshared Btrfs files")
        .after_help("Preview is the default. Linux x86-64/AArch64 and openat2 support are required for apply; extent-tree inspection normally requires root.\n\nApply preserves contents and verifies SHA-256, size and mtime. Protected, leased, open, executing, mapped, shared, already-compressed and low-headroom files are refused. There is no force override.\n\nFIEMAP inspection is not a snapshot lock. --quiescent acknowledges that concurrent writers, snapshots and reflinks have been stopped. A deadline stops between bounded calls; postflight verification may take additional time.\n\nBefore any rewrite, apply records a durable intent under compression-journal beside state.json. The state directory must already exist. Audit failures stop mutation.\n\nExamples:\n  sudo sbh compress --json -- /data/old-debug-binary /data/old-session.jsonl\n  sudo sbh compress --apply --allow-zstd-feature --quiescent --json -- /data/old-debug-binary\n  sudo sbh compress --recover-journal /var/lib/sbh/compression-journal/RUN.jsonl --json\n  sbh compress --discover --json -- /data/cold-archive\n\n--discover recursively selects metadata candidates without applying compression. It rejects all apply consent flags; live-use and physical-extent checks are still required by ordinary file preview/apply.\n\nRecovery is read-only, requires no daemon config, and never replays compression. Verified content after interruption is not evidence of physical reclaim. This command does not enable automatic daemon compression or change deletion policy.")))
}

pub fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
    let Some(("compress", subcommand)) = matches.subcommand() else {
        return Ok(None);
    };
    let options = Options::from_arg_matches(subcommand)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    if let Some(code) = discovery_cli::run(matches, subcommand, &options)? {
        return Ok(Some(code));
    }
    // An invalid or missing current daemon config must not hide a past run's
    // durable evidence. Recovery uses only its explicit journal and read limits.
    if let Some(path) = &options.recover_journal {
        return run_recovery(matches, path, options.max_bytes, options.timeout_secs).map(Some);
    }
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
        .map_err(|error| (1, error.to_string()))
        .and_then(|config| {
            compression::run(
                &options.paths,
                &policy,
                mode,
                &config,
                &storage_ballast_helper::platform::current(),
            )
            .map_err(|error| (io_exit_code(&error), error.to_string()))
        });
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
        Err((exit_code, error)) => {
            if matches.get_flag("json") {
                serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({
                        "schema": "sbh.compression.v1", "dry_run": !mode.apply,
                        "mutation_attempted": false, "error": error, "exit_code": exit_code,
                    }),
                )?;
                writeln!(out)?;
                out.flush()?;
            } else {
                eprintln!("sbh: compression did not start: {error}");
            }
            Ok(Some(exit_code))
        }
    }
}

fn run_recovery(
    matches: &ArgMatches,
    path: &std::path::Path,
    max_bytes: u64,
    timeout_secs: u64,
) -> io::Result<i32> {
    let result = journal::recover(path, max_bytes, timeout_secs);
    let mut out = io::stdout().lock();
    let code = match result {
        Ok(report) => {
            if matches.get_flag("json") {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)?;
            } else if !matches.get_flag("quiet") {
                write_recovery(&mut out, &report)?;
            }
            report.exit_code
        }
        Err(error) => {
            let exit_code = io_exit_code(&error);
            if matches.get_flag("json") {
                serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({
                        "schema": "sbh.compression.recovery.v1", "read_only": true,
                        "journal_path": path.to_string_lossy(), "error": error.to_string(),
                        "exit_code": exit_code,
                    }),
                )?;
                writeln!(out)?;
            } else {
                eprintln!("sbh: compression journal inspection failed: {error}");
            }
            exit_code
        }
    };
    out.flush()?;
    Ok(code)
}

fn io_exit_code(error: &io::Error) -> i32 {
    if error.kind() == io::ErrorKind::InvalidInput {
        1
    } else {
        2
    }
}

fn write_human(out: &mut impl Write, report: &CompressionReport) -> io::Result<()> {
    let mode = if report.dry_run { "preview" } else { "apply" };
    writeln!(
        out,
        "Btrfs compression {mode}; {} file(s) considered.",
        report.files.len()
    )?;
    if let Some(path) = &report.journal_path {
        writeln!(out, "Durable intent/outcome journal: {path}")?;
    }
    for file in &report.files {
        writeln!(
            out,
            "{}: {}\n  {}",
            file.outcome,
            file.path.display(),
            file.detail
        )?;
        if let Some(id) = &file.operation_id {
            writeln!(out, "  Journal operation: {id}")?;
        }
        if let Some(before) = file.physical_data_bytes_before {
            writeln!(out, "  Physical data bytes before: {before}")?;
        }
        if let Some(after) = file.physical_data_bytes_after {
            writeln!(out, "  Physical data bytes after:  {after}")?;
        }
        if let Some(evidence) = &file.reclaim {
            writeln!(
                out,
                "  Referenced savings: {}; growth: {}; old allocations pending: {}; confirmed net data-only reclaim: {} bytes.",
                evidence.referenced_bytes_saved,
                evidence.referenced_bytes_added,
                evidence.old_data_bytes_pending,
                evidence.confirmed_data_bytes_reclaimed
            )?;
        }
        if file.mutation_attempted {
            writeln!(
                out,
                "  Content/size/mtime verified: {}",
                file.content_verified
            )?;
        }
    }
    if let Some(reason) = &report.stop_reason {
        writeln!(
            out,
            "Stopped: {reason}. Unvisited files: {}.",
            report.unvisited_files
        )?;
    }
    writeln!(
        out,
        "Physical data accounting excludes metadata and is not a claim about immediately available mount space."
    )?;
    Ok(())
}

fn write_recovery(out: &mut impl Write, report: &RecoveryReport) -> io::Result<()> {
    writeln!(
        out,
        "Compression journal: {}\nRun: {}",
        report.journal_path, report.run_id
    )?;
    writeln!(
        out,
        "Durable run footer: {}; torn final record: {}.",
        report.run_finished, report.truncated_tail
    )?;
    if let Some(code) = report.recorded_exit_code {
        writeln!(out, "Recorded run exit code: {code}")?;
    }
    for operation in &report.operations {
        writeln!(
            out,
            "{}: {}\n  Operation {}: {}",
            operation.verification, operation.path, operation.operation_id, operation.detail
        )?;
        if let Some(recorded) = &operation.recorded_result {
            writeln!(
                out,
                "  Historical outcome: {}; mutation attempted: {}; content verified then: {}.",
                recorded.outcome, recorded.mutation_attempted, recorded.content_verified
            )?;
        }
    }
    writeln!(
        out,
        "Read-only inspection: no input or journal was rewritten. Content verification after interruption does not establish compression completion or physical reclaim."
    )?;
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
        assert!(
            parse(&[
                "compress",
                "--apply",
                "--allow-zstd-feature",
                "--quiescent",
                "/tmp/file"
            ])
            .unwrap()
            .apply
        );
    }

    #[test]
    fn preview_and_apply_conflict_and_there_is_no_force_switch() {
        assert!(
            parse(&[
                "compress",
                "--dry-run",
                "--apply",
                "--allow-zstd-feature",
                "--quiescent",
                "/tmp/file"
            ])
            .is_err()
        );
        assert!(parse(&["compress", "--force", "/tmp/file"]).is_err());
        assert!(parse(&["compress"]).is_err());
    }

    #[test]
    fn entrypoint_exposes_compression_and_preserves_global_arguments() {
        for args in [
            vec!["sbh", "--json", "compress", "/tmp/file"],
            vec![
                "sbh",
                "compress",
                "--json",
                "--config",
                "/tmp/config.toml",
                "/tmp/file",
            ],
        ] {
            let matches = crate::cli_command().try_get_matches_from(args).unwrap();
            assert!(matches.get_flag("json"));
            assert_eq!(matches.subcommand_name(), Some("compress"));
            assert!(!crate::update_mutates_binary(&matches));
        }
    }

    #[test]
    fn recovery_is_an_exclusive_read_only_mode_without_apply_consent() {
        let options = parse(&["compress", "--recover-journal", "/tmp/run.jsonl"]).unwrap();
        assert!(options.paths.is_empty());
        assert!(!options.apply);
        assert!(!options.allow_zstd_feature);
        assert!(!options.quiescent);
        for flag in [
            "--apply",
            "--dry-run",
            "--allow-zstd-feature",
            "--quiescent",
        ] {
            assert!(parse(&["compress", "--recover-journal", "/tmp/run.jsonl", flag]).is_err());
        }
        assert!(
            parse(&[
                "compress",
                "--recover-journal",
                "/tmp/run.jsonl",
                "/tmp/input"
            ])
            .is_err()
        );
    }

    #[test]
    fn runtime_failures_are_not_mislabeled_as_user_input_errors() {
        assert_eq!(
            io_exit_code(&io::Error::from(io::ErrorKind::InvalidInput)),
            1
        );
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidData,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Other,
        ] {
            assert_eq!(io_exit_code(&io::Error::from(kind)), 2);
        }
    }

    #[cfg(unix)]
    #[test]
    fn recovery_dispatch_does_not_load_the_current_daemon_config() {
        use std::os::unix::fs::OpenOptionsExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recorded-noop.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let header = serde_json::json!({
            "schema": "sbh.compression.journal.v1", "run_id": "fixture", "sequence": 0,
            "at": "2026-10-14T00:00:00Z", "entry": {
                "kind": "run_started", "pid": 42, "input_files": 1,
                "policy": CompressionPolicy::default()
            }
        });
        let footer = serde_json::json!({
            "schema": "sbh.compression.journal.v1", "run_id": "fixture", "sequence": 1,
            "at": "2026-10-14T00:00:00Z", "entry": {
                "kind": "run_finished", "exit_code": 0, "unvisited_files": 0
            }
        });
        writeln!(file, "{header}\n{footer}").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let matches = crate::cli_command()
            .try_get_matches_from([
                "sbh",
                "--json",
                "--config",
                "/nonexistent-sbh-recovery-config.toml",
                "compress",
                "--recover-journal",
                path.to_str().unwrap(),
            ])
            .unwrap();
        assert_eq!(run(&matches).unwrap(), Some(0));
    }
}
