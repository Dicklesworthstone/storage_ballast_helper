//! Compression operation explanations through the existing `explain --id` surface.
//!
//! The explicit `compress:` namespace prevents compression records from being
//! mistaken for deletion decisions. Parsing and journal validation stay in the
//! existing recovery implementation; no second journal grammar is introduced.

use std::io::{self, Write};
use std::path::Path;

use clap::ArgMatches;
use serde::Serialize;
use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::scanner::compression::CompressionPolicy;
use storage_ballast_helper::scanner::compression::journal::{self, RecoveryOperation};

const PREFIX: &str = "compress:";
// Explanation reads historical evidence, not gigabytes of source contents.
// recover() requires a positive budget. At most one byte across the whole run
// can be rehashed here; full input verification remains the recovery command.
const REHASH_BYTES: u64 = 1;
const INSPECTION_SECONDS: u64 = 5;

#[derive(Debug)]
struct Lookup<'a> {
    id: &'a str,
    run: &'a str,
    operation: &'a str,
}

impl<'a> Lookup<'a> {
    fn parse(id: &'a str) -> io::Result<Self> {
        let operation = id.strip_prefix(PREFIX).ok_or_else(invalid_id)?;
        let (run, sequence) = operation.rsplit_once(':').ok_or_else(invalid_id)?;
        // A run ID becomes ONE basename under the configured journal directory.
        // Never accept slashes, traversal, encoded paths, specifiers or NULs.
        if run.is_empty()
            || run.len() > 128
            || !run
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || sequence.is_empty()
            || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid_id());
        }
        let number = sequence.parse::<u64>().map_err(|_| invalid_id())?;
        if number == 0 || number.to_string() != sequence {
            return Err(invalid_id());
        }
        Ok(Self { id, run, operation })
    }
}

fn invalid_id() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "compression IDs use compress:RUN:SEQUENCE, where RUN is the journal basename and SEQUENCE is a positive decimal intent sequence",
    )
}

#[derive(Debug, Serialize)]
struct Explanation {
    schema: &'static str,
    read_only: bool,
    source: &'static str,
    id: String,
    journal_path: String,
    run_id: String,
    run_finished: bool,
    recorded_run_exit_code: Option<i32>,
    truncated_tail: bool,
    run_policy: CompressionPolicy,
    input_rehash_budget_bytes: u64,
    summary: String,
    operation: RecoveryOperation,
    exit_code: i32,
}

pub(super) fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
    let Some(("explain", command)) = matches.subcommand() else {
        return Ok(None);
    };
    let Some(id) = command.try_get_one::<String>("id").ok().flatten() else {
        return Ok(None);
    };
    if !id.starts_with(PREFIX) {
        return Ok(None);
    }
    let result = execute(matches, command, id);
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
                serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({
                        "schema": "sbh.compression.explanation.v1", "read_only": true,
                        "source": "compression_journal", "id": id,
                        "error": error, "exit_code": code,
                    }),
                )?;
                writeln!(out)?;
            } else {
                eprintln!("sbh: compression explanation failed: {error}");
            }
            code
        }
    };
    out.flush()?;
    Ok(Some(code))
}

fn execute(
    matches: &ArgMatches,
    command: &ArgMatches,
    id: &str,
) -> Result<Explanation, (i32, String)> {
    let lookup = Lookup::parse(id).map_err(|error| (1, error.to_string()))?;
    for key in ["why_not", "replay"] {
        if command.ids().any(|id| id.as_str() == key)
            && command.value_source(key) == Some(clap::parser::ValueSource::CommandLine)
        {
            return Err((1, "compression explanations support --id only; deletion replay and why-not modes are separate".into()));
        }
    }
    let explicit = matches.get_one::<std::path::PathBuf>("config");
    let config = Config::load(explicit.map(std::path::PathBuf::as_path))
        .map_err(|error| (1, error.to_string()))?;
    let directory = config
        .paths
        .state_file
        .with_file_name("compression-journal");
    if !directory.is_absolute() {
        return Err((1, "compression journal directory must be absolute".into()));
    }
    let path = directory.join(format!("{}.jsonl", lookup.run));
    explain_journal(&path, &lookup)
        .map_err(|error| (super::io_exit_code(&error), error.to_string()))
}

fn explain_journal(path: &Path, lookup: &Lookup<'_>) -> io::Result<Explanation> {
    // This preserves the shared parser's owner/mode/link/lock/size/sequence
    // checks and its torn-tail and false-success-footer rules.
    let report = journal::recover(path, REHASH_BYTES, INSPECTION_SECONDS)?;
    if report.run_id != lookup.run {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal run identity does not match the requested compression ID",
        ));
    }
    let operation = report
        .operations
        .into_iter()
        .find(|operation| operation.operation_id == lookup.operation)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "compression operation {} is absent from this journal",
                    lookup.operation
                ),
            )
        })?;
    let summary = operation.recorded_result.as_ref().map_or_else(
        || "Only a durable pre-mutation intent exists. Whether compression ran or reclaimed space remains unknown; no replay was attempted.".into(),
        |result| format!("Durable historical {} outcome. Allocation measurements describe the recorded operation, not current filesystem free space.", result.outcome),
    );
    Ok(Explanation {
        schema: "sbh.compression.explanation.v1",
        read_only: true,
        source: "compression_journal",
        id: lookup.id.into(),
        journal_path: report.journal_path,
        run_id: report.run_id,
        run_finished: report.run_finished,
        recorded_run_exit_code: report.recorded_exit_code,
        truncated_tail: report.truncated_tail,
        run_policy: report.policy,
        input_rehash_budget_bytes: REHASH_BYTES,
        summary,
        operation,
        exit_code: report.exit_code,
    })
}

fn write_human(out: &mut impl Write, report: &Explanation) -> io::Result<()> {
    writeln!(
        out,
        "Compression operation {}\n{}",
        report.id, report.summary
    )?;
    writeln!(
        out,
        "Source: {:?}\nFile: {:?}",
        report.journal_path, report.operation.path
    )?;
    writeln!(
        out,
        "Run finished: {}; torn final record: {}.",
        report.run_finished, report.truncated_tail
    )?;
    if let Some(result) = &report.operation.recorded_result {
        writeln!(
            out,
            "Recorded outcome: {}; mutation attempted: {}; contents verified then: {}.",
            result.outcome, result.mutation_attempted, result.content_verified
        )?;
        writeln!(
            out,
            "Physical data allocation before/after: {:?} / {:?} bytes.",
            result.physical_data_bytes_before, result.physical_data_bytes_after
        )?;
        if let Some(reclaim) = &result.reclaim {
            writeln!(
                out,
                "Referenced savings: {}; added: {}; pending old data: {}; confirmed net data-only reclaim: {} bytes.",
                reclaim.referenced_bytes_saved,
                reclaim.referenced_bytes_added,
                reclaim.old_data_bytes_pending,
                reclaim.confirmed_data_bytes_reclaimed
            )?;
        } else {
            writeln!(out, "Physical reclaim evidence: unknown.")?;
        }
    }
    writeln!(
        out,
        "Current-input verification: {}. {}",
        report.operation.verification, report.operation.detail
    )?;
    writeln!(
        out,
        "For full unfinished-input verification, use sbh compress --recover-journal with this journal path. This explanation never rewrites inputs or journal records."
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt as _;

    const RUN: &str = "abc-42-0";
    const ID: &str = "compress:abc-42-0:1";

    fn fixture(finished: bool) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{RUN}.jsonl"));
        let source = dir.path().join("source-not-opened.bin");
        let hash = "0".repeat(64);
        let wrap = |sequence: u64, entry: Value| {
            json!({
                "schema": "sbh.compression.journal.v1", "run_id": RUN,
                "sequence": sequence, "at": "2026-10-14T00:00:00Z", "entry": entry,
            })
        };
        let mut rows = vec![
            wrap(
                0,
                json!({"kind": "run_started", "pid": 42, "input_files": 1,
                "policy": CompressionPolicy::default()}),
            ),
            wrap(
                1,
                json!({"kind": "prepared", "intent": {
                    "operation_id": "abc-42-0:1",
                    "path_hex": storage_ballast_helper::core::hex_lower(source.as_os_str().as_encoded_bytes()),
                    "identity": {"device": 1, "inode": 2, "size": 67_108_864,
                        "mtime": 1, "mtime_nsec": 0, "ctime": 2, "ctime_nsec": 0, "links": 1},
                    "sha256_before": hash, "physical_data_bytes_before": 65536,
                }}),
            ),
        ];
        if finished {
            rows.push(wrap(
                2,
                json!({"kind": "file_finished", "report": {
                    "path": source, "operation_id": "abc-42-0:1", "outcome": "compressed",
                    "detail": "fixture historical outcome", "logical_bytes": 67_108_864,
                    "physical_data_bytes_before": 65536, "physical_data_bytes_after": 8192,
                    "processed_bytes": 67_108_864, "mutation_attempted": true,
                    "sha256_before": hash, "sha256_after": hash, "content_verified": true,
                    "reclaim": {"referenced_bytes_saved": 57344, "referenced_bytes_added": 0,
                        "old_data_bytes_pending": 0, "old_data_bytes_released": 65536,
                        "new_data_bytes_allocated": 8192, "confirmed_data_bytes_reclaimed": 57344},
                    "accounting_error": null,
                }}),
            ));
            rows.push(wrap(
                3,
                json!({"kind": "run_finished", "exit_code": 0, "unvisited_files": 0}),
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        for row in rows {
            writeln!(file, "{row}").unwrap();
        }
        file.sync_all().unwrap();
        (dir, path)
    }

    #[test]
    fn namespaced_ids_cannot_escape_the_journal_directory() {
        assert_eq!(Lookup::parse(ID).unwrap().run, RUN);
        for id in [
            "compress:",
            "compress:../other:1",
            "compress:/tmp/file:1",
            "compress:%2fetc:1",
            "compress:abc:0",
            "compress:abc:01",
            "compress:abc:-1",
            "compress:abc:1:2",
            "compress:abc:18446744073709551616",
        ] {
            assert!(Lookup::parse(id).is_err(), "{id}");
        }
    }

    #[test]
    fn completed_outcomes_keep_physical_evidence_historical() {
        let (dir, path) = fixture(true);
        let before = fs::read(&path).unwrap();
        let report = explain_journal(&path, &Lookup::parse(ID).unwrap()).unwrap();
        assert_eq!(report.exit_code, 0);
        assert!(report.run_finished);
        assert_eq!(report.operation.verification, "recorded_only");
        assert!(!report.operation.content_verified_now);
        let result = report.operation.recorded_result.as_ref().unwrap();
        assert_eq!(
            result.reclaim.as_ref().unwrap().referenced_bytes_saved,
            57344
        );
        assert!(!dir.path().join("source-not-opened.bin").exists());
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn interrupted_intents_never_become_success_or_reclaim_evidence() {
        let (_dir, path) = fixture(false);
        let report = explain_journal(&path, &Lookup::parse(ID).unwrap()).unwrap();
        assert_eq!(report.exit_code, 4);
        assert!(!report.run_finished);
        assert!(report.operation.recorded_result.is_none());
        assert!(!report.operation.content_verified_now);
        assert_eq!(report.operation.verification, "budget_exhausted");
        assert!(report.summary.contains("remains unknown"));
    }

    #[test]
    fn missing_operations_and_foreign_run_ids_are_not_silently_substituted() {
        let (_dir, path) = fixture(true);
        assert_eq!(
            explain_journal(&path, &Lookup::parse("compress:abc-42-0:9").unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            explain_journal(&path, &Lookup::parse("compress:different:1").unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn active_journals_are_refused_by_the_shared_validator() {
        let (_dir, path) = fixture(true);
        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer.try_lock().unwrap();
        assert!(explain_journal(&path, &Lookup::parse(ID).unwrap()).is_err());
    }

    #[test]
    fn ordinary_deletion_ids_fall_through_without_loading_config() {
        let matches = crate::cli_command()
            .try_get_matches_from([
                "sbh",
                "--config",
                "/nonexistent-compression-explanation-config",
                "explain",
                "--id",
                "ordinary-deletion-id",
            ])
            .unwrap();
        assert_eq!(run(&matches).unwrap(), None);
        let matches = crate::cli_command()
            .try_get_matches_from(["sbh", "--json", "explain", "--id", ID])
            .unwrap();
        let (_, command) = matches.subcommand().unwrap();
        assert_eq!(command.get_one::<String>("id").unwrap(), ID);
    }
}
