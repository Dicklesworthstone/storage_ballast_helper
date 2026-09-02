//! Explain-ledger verification (bd-rc-master-ajg1.3.6).
//!
//! A real daemon, run under the fs-stats overlay against a pressured fixture
//! mount, deletes a stale cargo target. Every `artifact_delete` it writes
//! must cite a decision id that `sbh explain` resolves at all four levels,
//! the selectors must agree with each other, the ledger schema and the
//! JSONL `decision` line are pinned, retention prunes by timestamp, and
//! `sbh emergency --yes` prints ids without writing a byte of ledger.

#![allow(missing_docs)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};
use storage_ballast_helper::logger::sqlite::SqliteLogger;

// ──────────────────── fixtures ────────────────────

/// A cargo target that classifies as Definite (`CACHEDIR.TAG` plus the
/// `debug/{deps,incremental,build,.fingerprint}` layout) with every mtime
/// set `age` in the past. Its birth time is now, so callers disable the
/// age floor (`min_file_age_minutes = 0`).
fn definite_target(project: &Path, age: Duration, rlib_bytes: usize) -> PathBuf {
    let target = project.join("target");
    let debug = target.join("debug");
    for sub in ["deps", "incremental", "build", ".fingerprint"] {
        fs::create_dir_all(debug.join(sub)).unwrap();
    }
    fs::write(
        target.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
    )
    .unwrap();
    fs::write(
        debug.join("deps").join("libfixture.rlib"),
        vec![0xA5u8; rlib_bytes],
    )
    .unwrap();
    fs::write(debug.join("incremental").join("unit-0"), b"x").unwrap();
    fs::write(debug.join(".fingerprint").join("lib-fixture"), b"x").unwrap();
    let mtime = filetime::FileTime::from_system_time(SystemTime::now() - age);
    set_mtime_recursive(&target, mtime);
    target
}

fn set_mtime_recursive(path: &Path, mtime: filetime::FileTime) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            set_mtime_recursive(&entry.path(), mtime);
        }
    }
    let _ = filetime::set_file_mtime(path, mtime);
}

fn scratch() -> tempfile::TempDir {
    let preferred = PathBuf::from("/data/tmp");
    if preferred.is_dir() {
        tempfile::tempdir_in(preferred).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

/// `sbh --config <config> <args>`, captured. Stdout is a pipe here, which
/// the CLI treats as JSON unless told otherwise, so runs without `--json`
/// are pinned to human output.
fn sbh(config: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(common::sbh_bin_path());
    command.arg("--config").arg(config).args(args);
    if !args.contains(&"--json") {
        command.env("SBH_OUTPUT_FORMAT", "human");
    }
    command.output().expect("spawn sbh")
}

fn stdout_json(output: &std::process::Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| {
            panic!(
                "no JSON on stdout:\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    serde_json::from_str(line).expect("valid JSON line")
}

fn is_decision_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

// ──────────────────── daemon runner ────────────────────

/// A daemon under the overlay: one pressured fixture mount (11% free of
/// 1 TB: Orange) holding the scan root, and a quiet read-only `/`.
struct Daemon {
    child: Child,
    config_path: PathBuf,
    data_dir: PathBuf,
    stderr_path: PathBuf,
}

impl Daemon {
    fn spawn(dir: &Path, root: &Path) -> Self {
        let data_dir = dir.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let config = format!(
            r#"[paths]
ballast_dir = "{ballast}"
jsonl_log = "{jsonl}"
sqlite_db = "{sqlite}"
state_file = "{state}"
[ballast]
file_count = 1
file_size_bytes = 1048576
[pressure]
poll_interval_ms = 500
[scanner]
root_paths = ["{root}"]
min_file_age_minutes = 0
min_rescan_interval_secs = 5
max_depth = 6
parallelism = 2
[notifications]
enabled = false
"#,
            ballast = data_dir.join("ballast").display(),
            jsonl = data_dir.join("activity.jsonl").display(),
            sqlite = data_dir.join("activity.sqlite3").display(),
            state = data_dir.join("state.json").display(),
            root = root.display(),
        );
        let config_path = dir.join("config.toml");
        fs::write(&config_path, config).unwrap();
        let table = format!(
            r#"{{"mounts":[{{"path":"{}","fs_type":"ext4","total":1000000000000,"free":110000000000,"readonly":false,"series":[]}},{{"path":"/","fs_type":"ext4","total":1000000000000,"free":500000000000,"readonly":true,"series":[]}}]}}"#,
            dir.display()
        );
        let stderr_path = dir.join("daemon.stderr");
        let child = Command::new(common::sbh_bin_path())
            .arg("--config")
            .arg(&config_path)
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr_path).unwrap())
            .env_remove("INVOCATION_ID")
            .env_remove("NOTIFY_SOCKET")
            .env("SBH_TEST_MODE", "1")
            .env("SBH_TEST_FS_STATS", table)
            .spawn()
            .expect("spawn sbh daemon");
        Self {
            child,
            config_path,
            data_dir,
            stderr_path,
        }
    }

    fn events(&self) -> Vec<Value> {
        fs::read_to_string(self.data_dir.join("activity.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn events_of(&self, kind: &str) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|event| event["event"].as_str() == Some(kind))
            .collect()
    }

    fn successful_deletes(&self) -> Vec<Value> {
        self.events_of("artifact_delete")
            .into_iter()
            .filter(|event| event["ok"] != Value::Bool(false))
            .collect()
    }

    fn stderr_tail(&self) -> String {
        let text = fs::read_to_string(&self.stderr_path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(25)..].join("\n")
    }

    fn signal(&self, sig: &str) {
        let _ = Command::new("kill")
            .arg(sig)
            .arg(self.child.id().to_string())
            .status();
    }

    /// Wait until the daemon has deleted something; a forced scan is
    /// requested once if the first passes did not reclaim.
    fn wait_for_a_deletion(&mut self, timeout: Duration) {
        let started = Instant::now();
        let mut nudged = false;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon") {
                panic!(
                    "daemon exited early ({status}); stderr tail:\n{}",
                    self.stderr_tail()
                );
            }
            if !self.successful_deletes().is_empty() {
                eprintln!(
                    "[explain_ledger] first deletion after {:?} (forced scan: {nudged})",
                    started.elapsed()
                );
                return;
            }
            assert!(
                started.elapsed() <= timeout,
                "no artifact_delete after {timeout:?}; events: {:?}; stderr tail:\n{}",
                self.events()
                    .iter()
                    .map(|e| e["event"].as_str().unwrap_or("?").to_string())
                    .collect::<Vec<_>>(),
                self.stderr_tail()
            );
            if !nudged && started.elapsed() > Duration::from_secs(20) {
                self.signal("-USR1");
                nudged = true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn stop(mut self) {
        self.signal("-TERM");
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if self.child.try_wait().expect("poll daemon").is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ──────────────────── the ledger the daemon writes ────────────────────

/// `PRAGMA table_info(decision_log)`, one `name type notnull pk` per column.
/// Changing the schema is allowed; changing it silently is not.
const DECISION_LOG_SCHEMA: &[&str] = &[
    "id INTEGER 0 1",
    "decision_id TEXT 1 0",
    "timestamp TEXT 1 0",
    "path TEXT 1 0",
    "action TEXT 1 0",
    "effective_action TEXT 0 0",
    "policy_mode TEXT 1 0",
    "total_score REAL 1 0",
    "posterior_abandoned REAL 1 0",
    "expected_loss_keep REAL 1 0",
    "expected_loss_delete REAL 1 0",
    "vetoed INTEGER 1 0",
    "veto_reason TEXT 0 0",
    "record TEXT 1 0",
];

/// Top-level keys every JSONL `decision` line must carry.
const DECISION_LINE_KEYS: &[&str] = &[
    "decision_id",
    "details",
    "event",
    "path",
    "score",
    "severity",
    "size",
    "ts",
];

/// Keys the writer may additionally stamp on a line (run provenance); any
/// other extra key is a schema change and fails the pin.
const DECISION_LINE_OPTIONAL_KEYS: &[&str] = &["run_id", "schema_version"];

/// Keys every serialized `DecisionRecord` (the `details` payload, and what
/// level 3 returns) must carry.
const DECISION_RECORD_KEYS: &[&str] = &[
    "action",
    "age_secs",
    "classification",
    "decision_id",
    "expected_loss_delete",
    "expected_loss_keep",
    "factor_contributions",
    "factors",
    "id",
    "path",
    "policy_mode",
    "posterior_abandoned",
    "size_bytes",
    "timestamp",
    "total_score",
    "trace_id",
    "vetoed",
];

fn table_info(db: &Path) -> Vec<String> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut stmt = conn.prepare("PRAGMA table_info(decision_log)").unwrap();
    stmt.query_map([], |row| {
        Ok(format!(
            "{} {} {} {}",
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(5)?
        ))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn decision_log_ids(db: &Path) -> Vec<String> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut stmt = conn
        .prepare("SELECT decision_id FROM decision_log ORDER BY id")
        .unwrap();
    stmt.query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn ids_of(payload: &Value, key: &str) -> BTreeSet<String> {
    payload["decisions"]
        .as_array()
        .map(|decisions| decisions.iter().map(|d| d[key].to_string()).collect())
        .unwrap_or_default()
}

#[test]
#[allow(clippy::too_many_lines)]
fn daemon_deletions_resolve_through_explain_and_the_ledger_is_pinned() {
    let dir = scratch();
    let root = dir.path().join("root");
    let stale = definite_target(
        &root.join("stale-proj"),
        Duration::from_hours(48),
        256 * 1024,
    );

    let mut daemon = Daemon::spawn(dir.path(), &root);
    daemon.wait_for_a_deletion(Duration::from_secs(90));
    let deletes = daemon.successful_deletes();
    let decisions = daemon.events_of("decision");
    let config = daemon.config_path.clone();
    let db = daemon.data_dir.join("activity.sqlite3");
    daemon.stop();

    assert!(
        deletes
            .iter()
            .any(|event| event["path"].as_str() == Some(&stale.to_string_lossy())),
        "the stale target is what got deleted: {deletes:?}"
    );
    assert!(!stale.exists(), "deleted target is gone from disk");

    // Every successful deletion cites a decision id that resolves at every
    // level, human and JSON, and matches a recorded decision for that path.
    let mut delete_ids = BTreeSet::new();
    for delete in &deletes {
        let id = delete["decision_id"]
            .as_str()
            .unwrap_or_else(|| panic!("artifact_delete without decision_id: {delete}"));
        assert!(is_decision_id(id), "malformed decision id {id}");
        delete_ids.insert(id.to_string());
        assert!(
            decisions
                .iter()
                .any(|d| d["decision_id"] == id && d["path"] == delete["path"]),
            "no JSONL decision {id} for {}",
            delete["path"]
        );

        let mut previous_key_count = 0;
        for level in ["0", "1", "2", "3"] {
            let json = sbh(
                &config,
                &["--json", "explain", "--id", id, "--level", level],
            );
            assert!(
                json.status.success(),
                "explain --id {id} --level {level} --json: {}",
                String::from_utf8_lossy(&json.stderr)
            );
            let payload = stdout_json(&json);
            assert_eq!(payload["source"], "sqlite", "the daemon's ledger is read");
            assert_eq!(payload["count"], 1);
            let decision = &payload["decisions"][0];
            assert_eq!(decision["id"], id);
            assert_eq!(decision["path"], delete["path"]);
            let key_count = keys(decision).len();
            assert!(
                key_count >= previous_key_count,
                "level {level} shows no less than the level below"
            );
            previous_key_count = key_count;

            let human = sbh(
                &config,
                &["--verbose", "explain", "--id", id, "--level", level],
            );
            assert!(human.status.success());
            let stdout = String::from_utf8_lossy(&human.stdout);
            assert!(
                stdout.contains(&format!("Decision {id}")),
                "level {level} names the id:\n{stdout}"
            );
            let stderr = String::from_utf8_lossy(&human.stderr);
            assert!(
                stderr.contains(&format!(
                    "[SBH-EXPLAIN] decision_id={id} level={level} source=sqlite"
                )),
                "verbose trace line at level {level}:\n{stderr}"
            );
        }
        let full = stdout_json(&sbh(
            &config,
            &["--json", "explain", "--id", id, "--level", "3"],
        ));
        let record_keys = keys(&full["decisions"][0]);
        for key in DECISION_RECORD_KEYS {
            assert!(record_keys.contains(*key), "level 3 record lacks {key}");
        }

        // --path returns only this path's decisions and includes this one.
        let by_path = stdout_json(&sbh(
            &config,
            &[
                "--json",
                "explain",
                "--path",
                delete["path"].as_str().unwrap(),
                "--limit",
                "100",
            ],
        ));
        let paths: BTreeSet<String> = ids_of(&by_path, "path");
        assert_eq!(paths.len(), 1, "one path only: {paths:?}");
        assert!(ids_of(&by_path, "id").contains(&json!(id).to_string()));
    }

    // --last and --since cover the same records once the limits are wide.
    let last = stdout_json(&sbh(
        &config,
        &["--json", "explain", "--last", "1000", "--level", "0"],
    ));
    let since = stdout_json(&sbh(
        &config,
        &[
            "--json", "explain", "--since", "1h", "--limit", "1000", "--level", "0",
        ],
    ));
    let last_records = ids_of(&last, "decision_id");
    assert_eq!(
        last_records,
        ids_of(&since, "decision_id"),
        "--last and --since disagree"
    );
    assert_eq!(
        last_records.len(),
        decision_log_ids(&db).len(),
        "--last 1000 returns every ledger row"
    );
    for id in &delete_ids {
        assert!(
            ids_of(&last, "id").contains(&json!(id).to_string()),
            "--last omits deletion decision {id}"
        );
    }

    // Schema and JSONL line pinned.
    assert_eq!(
        table_info(&db),
        DECISION_LOG_SCHEMA,
        "decision_log schema changed"
    );
    let line = &decisions[0];
    let line_keys = keys(line);
    for key in DECISION_LINE_KEYS {
        assert!(
            line_keys.contains(*key),
            "JSONL decision line lost {key}: {line}"
        );
    }
    let unexpected: Vec<&String> = line_keys
        .iter()
        .filter(|key| {
            !DECISION_LINE_KEYS.contains(&key.as_str())
                && !DECISION_LINE_OPTIONAL_KEYS.contains(&key.as_str())
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "JSONL decision line grew unknown keys {unexpected:?}: {line}"
    );
    let details: Value = serde_json::from_str(line["details"].as_str().unwrap()).unwrap();
    assert_eq!(
        details["id"], line["decision_id"],
        "details carry the same id"
    );
    for key in DECISION_RECORD_KEYS {
        assert!(keys(&details).contains(*key), "JSONL details lack {key}");
    }

    // Retention: rows older than 30 days go, younger ones stay, and explain
    // no longer resolves the pruned id.
    let before = decision_log_ids(&db).len();
    let conn = rusqlite::Connection::open(&db).unwrap();
    let old = (chrono::Utc::now() - chrono::Duration::days(31))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let young = (chrono::Utc::now() - chrono::Duration::days(29))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    for (id, timestamp) in [("aaaaaaaaaaa1", &old), ("aaaaaaaaaaa2", &young)] {
        conn.execute(
            "INSERT INTO decision_log (decision_id, timestamp, path, action, effective_action, policy_mode, \
             total_score, posterior_abandoned, expected_loss_keep, expected_loss_delete, vetoed, veto_reason, record) \
             SELECT ?1, ?2, path, action, effective_action, policy_mode, total_score, posterior_abandoned, \
             expected_loss_keep, expected_loss_delete, vetoed, veto_reason, record FROM decision_log ORDER BY id LIMIT 1",
            rusqlite::params![id, timestamp],
        )
        .unwrap();
    }
    drop(conn);
    assert!(
        sbh(&config, &["explain", "--id", "aaaaaaaaaaa1"])
            .status
            .success(),
        "the aged row resolves before pruning"
    );
    let pruned = SqliteLogger::open(&db)
        .unwrap()
        .prune_decision_log(30)
        .unwrap();
    assert_eq!(pruned, 1, "exactly the 31-day-old row is pruned");
    let after = decision_log_ids(&db);
    assert_eq!(after.len(), before + 1);
    assert!(!after.contains(&"aaaaaaaaaaa1".to_string()));
    assert!(after.contains(&"aaaaaaaaaaa2".to_string()));
    let gone = sbh(&config, &["--json", "explain", "--id", "aaaaaaaaaaa1"]);
    assert!(!gone.status.success(), "pruned id no longer resolves");
    assert_eq!(stdout_json(&gone)["error"], "no_matching_decision");
}

// ──────────────────── emergency: zero writes, ids on stdout ────────────────────

/// Byte size and mtime of every file under `dir` (recursively), for a
/// before/after comparison.
fn tree_fingerprint(dir: &Path) -> Vec<(PathBuf, u64, SystemTime)> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(tree_fingerprint(&path));
            } else if let Ok(metadata) = fs::metadata(&path) {
                out.push((path, metadata.len(), metadata.modified().unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn emergency_prints_decision_ids_and_writes_no_ledger() {
    let dir = scratch();
    let home = dir.path().join("home");
    let data = home.join(".local").join("share").join("sbh");
    fs::create_dir_all(&data).unwrap();
    // A pre-existing ledger and activity log that emergency must not touch.
    fs::write(data.join("activity.sqlite3"), b"not even a database").unwrap();
    fs::write(data.join("activity.jsonl"), b"{\"event\":\"sentinel\"}\n").unwrap();
    let untouched = tree_fingerprint(&home);

    // JSON: every candidate carries a resolvable-looking id and the target
    // is actually removed (100% target-free never stops early).
    let root_json = dir.path().join("root-json");
    let target = definite_target(&root_json.join("proj"), Duration::from_hours(48), 64 * 1024);
    let mut command = Command::new(common::sbh_bin_path());
    command
        .args(["--json", "emergency"])
        .arg(&root_json)
        .args(["--yes", "--target-free", "100", "--min-age", "0"])
        .env("HOME", &home)
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME");
    let output = command.output().expect("spawn sbh emergency");
    assert!(
        output.status.success(),
        "emergency --yes --json: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["command"], "emergency");
    let candidates = payload["candidates"].as_array().expect("candidates array");
    assert!(
        !candidates.is_empty(),
        "the stale target is a candidate: {payload}"
    );
    for candidate in candidates {
        let id = candidate["decision_id"].as_str().expect("decision_id");
        assert!(is_decision_id(id), "malformed id {id} in {candidate}");
    }
    assert!(
        candidates
            .iter()
            .any(|c| c["path"].as_str() == Some(&target.to_string_lossy())),
        "the target is listed: {payload}"
    );
    assert_eq!(
        payload["items_deleted"].as_u64().unwrap_or(0),
        u64::try_from(candidates.len()).unwrap()
    );
    assert!(!target.exists(), "emergency deleted the target");

    // Human: the plan names each candidate's id.
    let root_human = dir.path().join("root-human");
    definite_target(
        &root_human.join("proj"),
        Duration::from_hours(48),
        64 * 1024,
    );
    let mut command = Command::new(common::sbh_bin_path());
    command
        .arg("emergency")
        .arg(&root_human)
        .args(["--yes", "--target-free", "100", "--min-age", "0"])
        .env("SBH_OUTPUT_FORMAT", "human")
        .env("HOME", &home)
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME");
    let output = command.output().expect("spawn sbh emergency");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let id_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains(", id "))
        .collect();
    assert!(!id_lines.is_empty(), "candidate lines carry ids:\n{stdout}");
    for line in id_lines {
        let id = line.rsplit(", id ").next().unwrap().trim_end_matches(')');
        assert!(is_decision_id(id), "malformed id in line {line:?}");
    }

    // Zero writes: nothing under HOME changed or appeared.
    assert_eq!(
        tree_fingerprint(&home),
        untouched,
        "emergency wrote into the user's data dir"
    );
    assert!(
        !home.join(".config").exists(),
        "emergency must not create a config dir"
    );
}

// ──────────────────── explain --why-not / --replay ────────────────────

/// A config whose ledger lives under `dir` and whose age floor is off, so a
/// fixture born now can be scored on its merits. `extra` is appended raw.
fn explain_config(dir: &Path, extra: &str) -> PathBuf {
    let data = dir.join("data");
    fs::create_dir_all(&data).unwrap();
    let config = format!(
        r#"[paths]
ballast_dir = "{ballast}"
jsonl_log = "{jsonl}"
sqlite_db = "{sqlite}"
state_file = "{state}"
[scanner]
min_file_age_minutes = 0
[notifications]
enabled = false
{extra}"#,
        ballast = data.join("ballast").display(),
        jsonl = data.join("activity.jsonl").display(),
        sqlite = data.join("activity.sqlite3").display(),
        state = data.join("state.json").display(),
    );
    let path = dir.join("config.toml");
    fs::write(&path, config).unwrap();
    path
}

fn why_not(config: &Path, path: &Path, counterfactual: bool) -> Value {
    let mut args = vec!["--json", "explain", "--why-not", path.to_str().unwrap()];
    if counterfactual {
        args.push("--counterfactual");
    }
    let output = sbh(config, &args);
    assert!(
        output.status.success(),
        "explain --why-not {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    stdout_json(&output)
}

#[test]
#[allow(clippy::too_many_lines)]
fn why_not_names_the_first_rail_for_each_fixture_class() {
    let dir = scratch();
    let config = explain_config(dir.path(), "");
    let root = dir.path().join("root");

    // A marker inside the directory protects it before anything is scored.
    let protected = definite_target(&root.join("protected-proj"), Duration::from_hours(48), 4096);
    fs::write(protected.join(".sbh-protect"), b"keep\n").unwrap();
    let report = why_not(&config, &protected, false);
    assert!(
        report["verdict"]
            .as_str()
            .unwrap()
            .starts_with("protected:"),
        "{report}"
    );
    assert!(report["protection"].is_string(), "{report}");

    // A source tree is refused by scoring or by the preflight, never scored
    // as reclaimable.
    let source = root.join("src-proj");
    fs::create_dir_all(source.join("src")).unwrap();
    fs::write(source.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    fs::write(source.join("src").join("main.rs"), "fn main() {}\n").unwrap();
    let report = why_not(&config, &source, true);
    let verdict = report["verdict"].as_str().unwrap();
    assert!(
        verdict.starts_with("vetoed by scoring:")
            || verdict.starts_with("refused by the deletion preflight:")
            || verdict.starts_with("score "),
        "a source tree must not come out reclaimable: {report}"
    );
    assert_ne!(
        report["decision"]["action"], "delete",
        "a source tree is never Delete: {report}"
    );

    // A fresh Definite cargo target is scored on its merits with the age
    // floor off; the counterfactuals cover the three knobs and any flip
    // they name lands on Delete.
    let target = definite_target(
        &root.join("fresh-proj"),
        Duration::from_hours(48),
        256 * 1024,
    );
    let report = why_not(&config, &target, true);
    let verdict = report["verdict"].as_str().unwrap();
    assert!(
        verdict.starts_with("decided ")
            || verdict.starts_with("score ")
            || verdict.starts_with("nothing keeps it"),
        "{report}"
    );
    assert!(report["preflight"]["ok"].as_bool().unwrap(), "{report}");
    assert!(
        is_decision_id(report["decision"]["id"].as_str().unwrap()),
        "{report}"
    );
    assert_eq!(report["trace"]["category"], "RustTarget", "{report}");
    let counterfactuals = report["counterfactuals"].as_array().unwrap();
    let factors: Vec<&str> = counterfactuals
        .iter()
        .map(|c| c["factor"].as_str().unwrap())
        .collect();
    if verdict.starts_with("nothing keeps it") {
        assert_eq!(
            factors,
            ["none"],
            "already Delete needs no change: {report}"
        );
    } else {
        assert_eq!(factors, ["age", "size", "pressure"], "{report}");
    }

    // Weak evidence (a bare build dir holding one object file) is kept, and
    // the counterfactuals cover the three knobs; any flip they name lands on
    // Delete, and anything they cannot flip says so.
    let weak = root.join("weak-proj").join("build");
    fs::create_dir_all(&weak).unwrap();
    fs::write(weak.join("main.o"), vec![0u8; 8192]).unwrap();
    set_mtime_recursive(
        &weak,
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_hours(48)),
    );
    let report = why_not(&config, &weak, true);
    let verdict = report["verdict"].as_str().unwrap();
    assert!(
        !verdict.starts_with("nothing keeps it"),
        "a bare build dir is not reclaimable at Green: {report}"
    );
    let counterfactuals = report["counterfactuals"].as_array().unwrap();
    let factors: Vec<&str> = counterfactuals
        .iter()
        .map(|c| c["factor"].as_str().unwrap())
        .collect();
    assert!(
        factors == ["age", "size", "pressure"] || factors == ["veto"],
        "{report}"
    );
    for item in counterfactuals {
        if item["needed"].is_string() {
            assert_eq!(item["action_after"], "Delete", "{item}");
            assert!(item["needed_value"].is_number(), "{item}");
        } else {
            assert!(item["note"].is_string(), "{item}");
        }
    }

    // A file is not what the scanner scores.
    let file = target.join("CACHEDIR.TAG");
    let report = why_not(&config, &file, false);
    assert!(
        report["scanner_note"]
            .as_str()
            .unwrap()
            .contains("directories"),
        "{report}"
    );
    assert!(report["decision"].is_null());

    // With the default five-minute floor the same target is too young.
    let floored = explain_config(&dir.path().join("floored"), "");
    fs::write(
        &floored,
        fs::read_to_string(&floored)
            .unwrap()
            .replace("min_file_age_minutes = 0", "min_file_age_minutes = 5"),
    )
    .unwrap();
    let report = why_not(&floored, &target, false);
    assert!(
        report["trace"]["mtime_check"]
            .as_str()
            .unwrap()
            .contains("below minimum"),
        "{report}"
    );

    // Human output carries the same verdict and the factor table.
    let human = sbh(
        &config,
        &[
            "explain",
            "--why-not",
            target.to_str().unwrap(),
            "--counterfactual",
        ],
    );
    assert!(human.status.success());
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.starts_with("Why not: "), "{text}");
    assert!(text.contains("verdict:"), "{text}");
    assert!(text.contains("Counterfactuals"), "{text}");
}

#[test]
fn replay_matches_the_record_until_the_config_changes() {
    let dir = scratch();
    let config = explain_config(dir.path(), "");
    let root = dir.path().join("root");
    definite_target(&root.join("proj"), Duration::from_hours(48), 256 * 1024);

    // A dry-run clean records its plan in the ledger.
    let clean = sbh(
        &config,
        &[
            "--json",
            "clean",
            root.to_str().unwrap(),
            "--dry-run",
            "--min-score",
            "0",
        ],
    );
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let last = stdout_json(&sbh(&config, &["--json", "explain", "--last", "1"]));
    let id = last["decisions"][0]["id"].as_str().unwrap().to_string();

    // Same code, same config: no drift, every factor reproduces.
    let replay = stdout_json(&sbh(&config, &["--json", "explain", "--replay", &id]));
    assert_eq!(replay["mode"], "replay");
    assert_eq!(replay["id"], id.as_str());
    assert_eq!(replay["drift"], Value::Bool(false), "{replay}");
    assert_eq!(
        replay["stored_action"], replay["replayed_action"],
        "{replay}"
    );
    for factor in replay["factors"].as_array().unwrap() {
        let delta = factor["delta"].as_f64().unwrap();
        assert!(delta.abs() < 1e-6, "{factor}");
    }
    let approximations = replay["approximations"].as_array().unwrap();
    assert_eq!(
        approximations.len(),
        1,
        "only the non-persisted open-file evidence is approximated: {approximations:?}"
    );

    // A heavier structure weight changes the total: drift is reported.
    let retuned = explain_config(
        &dir.path().join("retuned"),
        "[scoring]\nstructure_weight = 0.30\nage_weight = 0.05\n",
    );
    fs::write(
        &retuned,
        fs::read_to_string(&retuned).unwrap().replace(
            &format!(
                "sqlite_db = \"{}\"",
                dir.path().join("retuned/data/activity.sqlite3").display()
            ),
            &format!(
                "sqlite_db = \"{}\"",
                dir.path().join("data/activity.sqlite3").display()
            ),
        ),
    )
    .unwrap();
    let replay = stdout_json(&sbh(&retuned, &["--json", "explain", "--replay", &id]));
    assert_eq!(replay["drift"], Value::Bool(true), "{replay}");
    let structure = replay["factors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "total_score")
        .unwrap();
    assert!(
        structure["delta"].as_f64().unwrap().abs() > 0.005,
        "{replay}"
    );

    // Human output and the unknown-id path.
    let human = sbh(&config, &["explain", "--replay", &id]);
    assert!(human.status.success());
    assert!(
        String::from_utf8_lossy(&human.stdout).starts_with(&format!("Replay {id}")),
        "{}",
        String::from_utf8_lossy(&human.stdout)
    );
    let unknown = sbh(&config, &["explain", "--replay", "000000000000"]);
    assert_eq!(unknown.status.code(), Some(1));
}
