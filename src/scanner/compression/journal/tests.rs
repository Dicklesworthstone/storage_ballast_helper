use super::*;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;

const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn fixture() -> (tempfile::TempDir, AuditSession, File, CompressionFileReport) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("cold.bin");
    fs::write(&path, b"abc").unwrap();
    let file = File::open(&path).unwrap();
    let mut report = CompressionFileReport::new(&path);
    report.logical_bytes = 3;
    report.physical_data_bytes_before = Some(4096);
    report.sha256_before = Some(ABC.into());
    let policy = CompressionPolicy {
        min_size_bytes: 1,
        max_bytes: 64,
        ..Default::default()
    };
    let session = AuditSession::new(root.join("compression-journal"), 2, &policy);
    (temp, session, file, report)
}

fn intent_only() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let (temp, mut session, file, mut report) = fixture();
    session.prepare(&mut report, &file).unwrap();
    let journal = session.path().unwrap().to_path_buf();
    drop(session);
    (temp, journal, report.path)
}

#[test]
fn constructing_and_finishing_an_unused_session_writes_nothing() {
    let (temp, mut session, _, _) = fixture();
    assert!(session.path().is_none());
    session.finish(0, 0).unwrap();
    assert!(!session.failed());
    assert!(!temp.path().join("compression-journal").exists());
}

#[test]
fn intent_is_readable_before_mutation_and_live_writer_cannot_be_recovered() {
    let (_temp, mut session, file, mut report) = fixture();
    session.prepare(&mut report, &file).unwrap();
    assert!(!report.mutation_attempted);
    let path = session.path().unwrap();
    let parsed = parse_records(&fs::read(path).unwrap()).unwrap();
    assert_eq!(parsed.operations.len(), 1);
    assert!(parsed.operations[0].1.is_none());
    assert_eq!(parsed.operations[0].0.sha256_before, ABC);
    assert_eq!(
        parsed.operations[0].0.operation_id,
        report.operation_id.as_deref().unwrap()
    );
    assert!(
        recover(path, 64, 30).is_err(),
        "an active run must not appear interrupted"
    );
    assert_eq!(fs::read(&report.path).unwrap(), b"abc");
}

#[test]
fn interrupted_intent_verifies_content_without_rewriting_or_claiming_reclaim() {
    let (_temp, journal, source) = intent_only();
    let before_journal = fs::read(&journal).unwrap();
    let before_source = fs::metadata(&source).unwrap();
    let report = recover(&journal, 64, 30).unwrap();
    assert!(!report.run_finished);
    assert_eq!(report.exit_code, 4);
    assert!(report.recorded_exit_code.is_none());
    assert_eq!(report.operations.len(), 1);
    assert!(report.operations[0].content_verified_now);
    assert!(report.operations[0].recorded_result.is_none());
    assert!(report.operations[0].detail.contains("remain unknown"));
    assert_eq!(fs::read(&journal).unwrap(), before_journal);
    assert_eq!(fs::read(&source).unwrap(), b"abc");
    let after = fs::metadata(&source).unwrap();
    assert_eq!(
        (after.ino(), after.len(), after.mtime(), after.mtime_nsec()),
        (
            before_source.ino(),
            before_source.len(),
            before_source.mtime(),
            before_source.mtime_nsec()
        )
    );
}

#[test]
fn completed_failure_is_durable_and_preserves_its_nonzero_exit_code() {
    let (_temp, mut session, file, mut item) = fixture();
    session.prepare(&mut item, &file).unwrap();
    item.outcome = "failed".into();
    item.detail = "new protection appeared before the first ioctl".into();
    session.complete(&item).unwrap();
    session.finish(2, 0).unwrap();
    let path = session.path().unwrap().to_path_buf();
    drop(session);
    let report = recover(&path, 64, 30).unwrap();
    assert!(report.run_finished);
    assert_eq!(report.recorded_exit_code, Some(2));
    assert_eq!(report.exit_code, 2);
    let operation = &report.operations[0];
    assert_eq!(operation.verification, "recorded_only");
    assert!(!operation.content_verified_now);
    assert!(
        !operation
            .recorded_result
            .as_ref()
            .unwrap()
            .mutation_attempted
    );
}

#[test]
fn a_torn_last_record_is_uncertain_but_a_malformed_complete_record_is_an_error() {
    let (_temp, journal, _) = intent_only();
    let prefix = fs::read(&journal).unwrap();
    let mut torn = prefix.clone();
    torn.extend_from_slice(b"{\"schema\":\"sbh.compression.journal.v1\",\xff");
    let parsed = parse_records(&torn).unwrap();
    assert!(parsed.truncated_tail);
    assert_eq!(parsed.operations.len(), 1);
    assert!(parsed.operations[0].1.is_none());
    torn.push(b'\n');
    assert!(parse_records(&torn).is_err());
    let mut blank = prefix;
    blank.push(b'\n');
    assert!(
        parse_records(&blank).is_err(),
        "complete blank lines must not disappear"
    );
}

#[test]
fn recovery_rejects_forged_sequences_run_ids_and_premature_success_footers() {
    let (_temp, journal, _) = intent_only();
    let text = fs::read_to_string(journal).unwrap();
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for (field, replacement) in [
        ("sequence", serde_json::json!(99)),
        ("run_id", serde_json::json!("another-run")),
        ("schema", serde_json::json!("sbh.compression.journal.v99")),
    ] {
        let mut changed = records.clone();
        changed[1][field] = replacement;
        let bytes = changed.iter().fold(String::new(), |mut out, record| {
            out.push_str(&record.to_string());
            out.push('\n');
            out
        });
        assert!(parse_records(bytes.as_bytes()).is_err(), "{field}");
    }
    let mut bytes = text.into_bytes();
    let footer = serde_json::json!({
        "schema": SCHEMA, "run_id": records[0]["run_id"], "sequence": 2,
        "at": "2026-10-14T00:00:00Z", "entry": {
            "kind": "run_finished", "exit_code": 0, "unvisited_files": 0
        }
    });
    bytes.extend_from_slice(format!("{footer}\n").as_bytes());
    assert!(
        parse_records(&bytes).is_err(),
        "an intent without an outcome is not success"
    );
}

#[test]
fn oversized_outcome_poisoning_leaves_the_original_intent_recoverable() {
    let (_temp, mut session, file, mut item) = fixture();
    session.prepare(&mut item, &file).unwrap();
    let path = session.path().unwrap().to_path_buf();
    let before = fs::read(&path).unwrap();
    item.outcome = "failed".into();
    item.detail = "x".repeat(MAX_RECORD_BYTES);
    assert!(session.complete(&item).is_err());
    assert!(session.failed());
    assert!(session.finish(2, 0).is_err());
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "check the record budget before writing"
    );
    drop(session);
    assert!(!recover(&path, 64, 30).unwrap().run_finished);
}

#[test]
fn refused_journal_creation_never_modifies_the_selected_file() {
    let (temp, _, file, mut item) = fixture();
    let occupied = temp.path().join("occupied");
    fs::write(&occupied, b"retain existing data").unwrap();
    let mut session = AuditSession::new(occupied.clone(), 1, &CompressionPolicy::default());
    assert!(session.prepare(&mut item, &file).is_err());
    assert!(session.failed());
    assert!(!item.mutation_attempted);
    assert_eq!(fs::read(&occupied).unwrap(), b"retain existing data");
    assert_eq!(fs::read(&item.path).unwrap(), b"abc");
}

#[test]
fn journal_permissions_are_private_and_are_never_repaired_by_widening() {
    let (temp, mut session, file, mut item) = fixture();
    let directory = temp.path().join("compression-journal");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(session.prepare(&mut item, &file).is_err());
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o755);
    assert!(fs::read_dir(&directory).unwrap().next().is_none());
    let (_temp, journal, _) = intent_only();
    assert_eq!(fs::metadata(&journal).unwrap().mode() & 0o077, 0);
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(recover(&journal, 64, 30).is_err());
}

#[test]
fn symlinked_and_multi_link_journals_are_not_recovery_authority() {
    let (temp, journal, _) = intent_only();
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&journal, &alias).unwrap();
    assert!(recover(&alias, 64, 30).is_err());
    fs::hard_link(&journal, temp.path().join("hardlink")).unwrap();
    assert!(recover(&journal, 64, 30).is_err());
}

#[test]
fn changed_bytes_are_detected_even_if_size_and_mtime_were_restored() {
    let (_temp, journal, source) = intent_only();
    let mtime = filetime::FileTime::from_last_modification_time(&fs::metadata(&source).unwrap());
    fs::write(&source, b"xyz").unwrap();
    filetime::set_file_mtime(&source, mtime).unwrap();
    let report = recover(&journal, 64, 30).unwrap();
    assert_eq!(report.operations[0].verification, "content_mismatch");
    assert!(!report.operations[0].content_verified_now);
    assert_eq!(report.exit_code, 4);
    assert_eq!(
        fs::read(source).unwrap(),
        b"xyz",
        "recovery must not repair or replace data"
    );
}

#[test]
fn recovery_budget_exhaustion_is_not_success_or_replay() {
    let (_temp, journal, source) = intent_only();
    let report = recover(&journal, 1, 30).unwrap();
    assert_eq!(report.operations[0].verification, "budget_exhausted");
    assert!(!report.operations[0].content_verified_now);
    assert_eq!(report.exit_code, 4);
    assert_eq!(fs::read(source).unwrap(), b"abc");
    assert!(recover(&journal, 0, 30).is_err());
    assert!(recover(&journal, 64, 0).is_err());
}

#[test]
fn journal_read_budget_is_checked_before_reading_the_payload() {
    let (_temp, journal, _) = intent_only();
    OpenOptions::new()
        .write(true)
        .open(&journal)
        .unwrap()
        .set_len(MAX_JOURNAL_BYTES + 1)
        .unwrap();
    let error = recover(&journal, 64, 30).unwrap_err();
    assert!(error.to_string().contains("32 MiB"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "APFS refuses file names that are not UTF-8 (EILSEQ)"
)]
fn native_path_bytes_survive_intent_storage_and_recovery() {
    use std::os::unix::ffi::OsStringExt;
    let (temp, mut session, file, mut item) = fixture();
    let native = temp
        .path()
        .canonicalize()
        .unwrap()
        .join(std::ffi::OsString::from_vec(b"cold-\xff.bin".to_vec()));
    fs::rename(&item.path, &native).unwrap();
    item.path = native.clone();
    session.prepare(&mut item, &file).unwrap();
    let journal = session.path().unwrap().to_path_buf();
    drop(session);
    let parsed = parse_records(&fs::read(&journal).unwrap()).unwrap();
    assert_eq!(
        decode_path(&parsed.operations[0].0.path_hex).unwrap(),
        native
    );
    let recovered = recover(&journal, 64, 30).unwrap();
    assert!(recovered.operations[0].content_verified_now);
    assert!(serde_json::to_value(recovered).is_ok());
}

#[test]
fn native_path_decoding_refuses_nul_relative_traversal_and_invalid_hex() {
    for value in [
        "",
        "00",
        "ffg0",
        "2f746d702f00",
        "72656c6174697665",
        "2f746d702f2e2e2f66696c65",
    ] {
        assert!(decode_path(value).is_err(), "{value}");
    }
}

#[test]
fn appending_a_torn_outcome_does_not_erase_the_prepared_intent() {
    let (_temp, journal, _) = intent_only();
    let mut file = OpenOptions::new().append(true).open(&journal).unwrap();
    file.write_all(b"{\"entry\":{\"kind\":\"file_finished\"")
        .unwrap();
    file.sync_all().unwrap();
    drop(file);
    let report = recover(&journal, 64, 30).unwrap();
    assert!(report.truncated_tail);
    assert!(!report.run_finished);
    assert_eq!(report.exit_code, 4);
    assert!(report.operations[0].content_verified_now);
    assert!(report.operations[0].recorded_result.is_none());
}
