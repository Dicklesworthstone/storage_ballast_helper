//! Exit-code and stream contract (C-EXIT, bd-rc-master-ajg1.4.4), asserted
//! against the built binary: 0 ok, 1 user error or pressure condition,
//! 2 runtime/IO failure, 4 partial success; human reports on stdout,
//! diagnostics on stderr; `--json` reports carry `exit_code`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Run the binary in human output mode (stdout is a pipe here, which would
/// otherwise select JSON); `--json` in `args` still wins.
fn sbh(config: &Path, args: &[&str]) -> Output {
    Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("SBH_TEST_MODE")
        .env("SBH_OUTPUT_FORMAT", "human")
        .output()
        .expect("run sbh")
}

/// A config whose paths live under `dir`, so no host state is read or
/// written.
fn config_in(dir: &Path) -> std::path::PathBuf {
    let data = dir.join("data");
    fs::create_dir_all(&data).unwrap();
    let config = format!(
        "[paths]\nballast_dir = {:?}\njsonl_log = {:?}\nsqlite_db = {:?}\nstate_file = {:?}\n\
         [scanner]\ninclude_user_temp_dir = false\nroot_paths = [{:?}]\nmin_file_age_minutes = 0\n[notifications]\nenabled = false\n",
        data.join("ballast").display().to_string(),
        data.join("activity.jsonl").display().to_string(),
        data.join("activity.sqlite3").display().to_string(),
        data.join("state.json").display().to_string(),
        dir.join("root").display().to_string(),
    );
    let path = dir.join("config.toml");
    fs::write(&path, config).unwrap();
    fs::create_dir_all(dir.join("root")).unwrap();
    path
}

/// A directory on the build volume. `check` on a tmpfs or ramfs path also
/// requires a clean host RAM-scratch assessment (bd-paeg), so a threshold
/// test on a tempdir under a busy tmpfs `/tmp` would test the host instead.
fn disk_tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `check --need` above what the volume has is a pressure condition: exit 1
/// (not the I/O class), and the report is on stdout.
#[test]
fn check_unmet_need_is_exit_one_with_the_report_on_stdout() {
    let dir = disk_tempdir();
    let config = config_in(dir.path());
    let need = u64::MAX / 2;
    let output = sbh(
        &config,
        &[
            "check",
            "--need",
            &need.to_string(),
            &dir.path().display().to_string(),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let out = stdout(&output);
    assert!(out.contains("required"), "report on stdout: {out:?}");
    assert!(
        !stderr(&output).contains("required"),
        "report must not be on stderr: {}",
        stderr(&output)
    );

    let json = sbh(
        &config,
        &[
            "--json",
            "check",
            "--need",
            &need.to_string(),
            &dir.path().display().to_string(),
        ],
    );
    assert_eq!(json.status.code(), Some(1));
    let payload: serde_json::Value = serde_json::from_str(stdout(&json).trim()).unwrap();
    assert_eq!(payload["exit_code"], 1);
    assert_eq!(payload["status"], "critical");
}

/// Plenty of apparent tmpfs blocks must not hide insufficient host/process RAM.
/// Only mount capacity is injected; the binary reads native memory evidence.
#[cfg(target_os = "linux")]
#[test]
fn ram_backed_need_checks_native_memory_after_filesystem_capacity_passes() {
    let dir = disk_tempdir();
    let config = config_in(dir.path());
    let capacity = u64::MAX / 2;
    let need = u64::MAX / 4;
    let table = serde_json::json!({
        "mounts": [{
            "path": dir.path(),
            "fs_type": "tmpfs",
            "ram_backed": true,
            "total": capacity,
            "free": capacity,
        }],
    });
    let output = Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(config)
        .args(["--json", "check", "--target-free", "0", "--need"])
        .arg(need.to_string())
        .arg(dir.path())
        .env("SBH_TEST_MODE", "1")
        .env("SBH_TEST_FS_STATS", table.to_string())
        .output()
        .expect("run RAM-backed preflight");
    // Restricted CI namespaces may make native cgroup/process evidence partial.
    // Neither a known shortfall nor incomplete evidence may report success.
    assert!(matches!(output.status.code(), Some(1 | 4)), "{output:?}");
    let payload: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(payload["free_bytes"], capacity);
    let admission = &payload["ram_write_admission"];
    assert_eq!(admission["schema"], "sbh.ram_write_admission.v1");
    assert_eq!(admission["requested_bytes"], need);
    assert_eq!(admission["read_only"], true);
    assert!(matches!(admission["exit_code"].as_i64(), Some(1 | 4)));
    if let Some(available) = admission["host_available_bytes"].as_u64() {
        assert!(available < need);
    }
    assert!(
        matches!(
            payload["reason"].as_str(),
            Some(
                "ram_write_headroom" | "ram_write_admission_incomplete" | "ram_scratch_incomplete"
            )
        ),
        "{payload}"
    );
}

/// `check` on a volume above its threshold is exit 0 and prints nothing.
#[test]
fn check_above_threshold_is_exit_zero() {
    let dir = disk_tempdir();
    let config = config_in(dir.path());
    let output = sbh(
        &config,
        &[
            "check",
            "--target-free",
            "0",
            &dir.path().display().to_string(),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
}

fn inode_fixture_check(config: &Path, path: &Path, inodes: &serde_json::Value) -> Output {
    let table = serde_json::json!({
        "mounts": [{
            "path": path,
            "fs_type": "ext4",
            "total": 1_000_000,
            "free": 900_000,
            "inodes": inodes,
        }],
    });
    Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(config)
        .args(["--json", "check", "--target-free", "0"])
        .arg(path)
        .env("SBH_TEST_MODE", "1")
        .env("SBH_TEST_FS_STATS", table.to_string())
        .output()
        .expect("run inode preflight")
}

#[test]
fn check_inode_exhaustion_fails_even_when_byte_capacity_is_healthy() {
    let dir = disk_tempdir();
    let config = config_in(dir.path());
    let output = inode_fixture_check(
        &config,
        dir.path(),
        &serde_json::json!({"total": 1000, "free": 10, "available": 0}),
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let payload: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(payload["reason"], "inode_pressure");
    assert_eq!(payload["exit_code"], 1);
    assert_eq!(payload["free_pct"], 90.0);
    assert_eq!(payload["free_bytes"], 900_000);
    assert_eq!(payload["inodes"]["status"], "known");
    assert_eq!(payload["inodes"]["stats"]["available"], 0);
    assert_eq!(payload["inodes"]["pressure"]["level"], "critical");
}

#[test]
fn check_inode_accounting_unknown_is_explicit_and_does_not_read_host_counters() {
    let dir = disk_tempdir();
    let config = config_in(dir.path());
    let output = inode_fixture_check(&config, dir.path(), &serde_json::Value::Null);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let payload: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(payload["inodes"]["status"], "unavailable");
    assert!(payload["inodes"]["stats"].is_null());
    assert!(payload["inodes"]["pressure"].is_null());
    assert_eq!(payload["free_bytes"], 900_000);
}

#[test]
fn check_inode_pressure_can_be_disabled_without_hiding_raw_counters() {
    let dir = disk_tempdir();
    let config = config_in(dir.path());
    let base = fs::read_to_string(&config).unwrap();
    fs::write(
        &config,
        format!("{base}\n[pressure.inodes]\nenabled = false\n"),
    )
    .unwrap();
    let output = inode_fixture_check(
        &config,
        dir.path(),
        &serde_json::json!({"total": 1000, "free": 0, "available": 0}),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let payload: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(payload["inodes"]["status"], "disabled");
    assert_eq!(payload["inodes"]["enabled"], false);
    assert_eq!(payload["inodes"]["stats"]["available"], 0);
    assert!(payload["inodes"]["pressure"].is_null());
}

/// `check` without `--target-free` uses the daemon's Yellow line, absolute
/// floors included (bd-ud9s): a large disk well above its floor is not under
/// pressure just because its free share is below the percentage.
#[test]
fn check_honours_the_absolute_free_floors() {
    let dir = disk_tempdir();
    let config = config_in(dir.path());
    let base = fs::read_to_string(&config).unwrap();
    let percentages = "[pressure]\ngreen_min_free_pct = 99.9\nyellow_min_free_pct = 99.8\n\
                       orange_min_free_pct = 99.7\nred_min_free_pct = 99.6\n";
    let target = dir.path().display().to_string();

    fs::write(&config, format!("{base}{percentages}")).unwrap();
    let without_floors = sbh(&config, &["check", &target]);
    assert_eq!(without_floors.status.code(), Some(1), "{without_floors:?}");

    let floors = "green_min_free_bytes = 4\nyellow_min_free_bytes = 3\n\
                  orange_min_free_bytes = 2\nred_min_free_bytes = 1\n";
    fs::write(&config, format!("{base}{percentages}{floors}")).unwrap();
    let with_floors = sbh(&config, &["check", &target]);
    assert_eq!(with_floors.status.code(), Some(0), "{with_floors:?}");
}

/// A path that cannot be stat'ed is an I/O failure: exit 2.
#[test]
fn check_on_a_missing_path_is_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path());
    let missing = dir.path().join("does-not-exist");
    let output = sbh(&config, &["check", &missing.display().to_string()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

/// Nothing to reclaim is success for both `clean` and `emergency`.
#[test]
fn clean_and_emergency_with_nothing_to_reclaim_are_exit_zero() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path());
    let root = dir.path().join("root").display().to_string();

    let clean = sbh(&config, &["clean", "--dry-run", &root]);
    assert_eq!(clean.status.code(), Some(0), "{clean:?}");

    let emergency = sbh(&config, &["emergency", "--yes", &root]);
    assert_eq!(emergency.status.code(), Some(0), "{emergency:?}");
    assert!(
        stdout(&emergency).contains("no cleanup candidates found"),
        "report on stdout: {emergency:?}"
    );

    let json = sbh(&config, &["--json", "emergency", "--yes", &root]);
    assert_eq!(json.status.code(), Some(0), "{json:?}");
    let payload: serde_json::Value = serde_json::from_str(stdout(&json).trim()).unwrap();
    assert_eq!(payload["candidates_count"], 0);
}

/// Bad arguments are user errors: exit 1 (clap's own usage errors keep
/// clap's exit 2, which is the runtime class and out of this contract).
#[test]
fn user_errors_are_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path());
    let output = sbh(&config, &["explain", "--id", "not-a-decision-id"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

/// Status is a read-only view of recorded evidence. A missing database must
/// be explicit without becoming an operational error or creating a log.
#[test]
fn status_ram_scratch_unavailable_is_explicit_and_does_not_create_database() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path());
    let database = dir.path().join("data/activity.sqlite3");
    let output = sbh(&config, &["--json", "status"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(json["ram_scratch"]["availability"], "unavailable");
    assert!(json["ram_scratch"]["detail"].is_string());
    assert!(!database.exists());
    let human = sbh(&config, &["status"]);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert!(stdout(&human).contains("RAM scratch: UNKNOWN (activity evidence unavailable)"));
    assert!(!database.exists());
}

fn append_warning(database: &Path, minutes_ago: i64, code: &str, message: &str) {
    use storage_ballast_helper::logger::sqlite::{ActivityRow, SqliteLogger};

    let at = chrono::Utc::now() - chrono::Duration::minutes(minutes_ago);
    let db = SqliteLogger::open(database).unwrap();
    db.log_activity(&ActivityRow {
        timestamp: at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        event_type: "info".to_string(),
        severity: "warning".to_string(),
        path: None,
        size_bytes: None,
        score: None,
        score_factors: None,
        pressure_level: None,
        free_pct: None,
        duration_ms: None,
        success: 1,
        error_code: Some(code.to_string()),
        error_message: None,
        details: Some(message.to_string()),
    })
    .unwrap();
}

/// The daemon's growth-attribution reports reach `sbh status`: the latest per
/// mount within the window, read-only, and not the budget warnings that share
/// their code.
#[test]
fn status_shows_the_latest_space_report_per_mount_read_only() {
    use storage_ballast_helper::daemon::attribution::{Consumer, report};

    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path());
    let database = dir.path().join("data/activity.sqlite3");
    let missing = sbh(&config, &["--json", "status"]);
    let json: serde_json::Value = serde_json::from_str(stdout(&missing).trim()).unwrap();
    assert!(json["space_reports"]["unavailable"].is_string(), "{json}");
    assert!(!database.exists());

    let consumer = |path: &str, gib: u64| Consumer {
        path: PathBuf::from(path),
        bytes: gib << 30,
        complete: true,
        estimated: None,
    };
    let older = report(
        "red",
        Path::new("/"),
        10,
        &[consumer("/home/ubuntu", 90)],
        &[],
    );
    let newer = report(
        "critical",
        Path::new("/"),
        10,
        &[consumer("/home/ubuntu", 120)],
        &[(
            PathBuf::from("/home/ubuntu"),
            vec![consumer("/home/ubuntu/.cache", 100)],
        )],
    );
    append_warning(
        &database,
        300,
        "SBH-2007",
        &older.replace("red on /", "red on /old"),
    );
    append_warning(&database, 70, "SBH-2007", &older);
    append_warning(&database, 12, "SBH-2007", &newer);
    append_warning(
        &database,
        2,
        "SBH-2007",
        "priority pre-scan stopped by cpu after 38 entries in 1.0s",
    );
    let before = fs::read(&database).unwrap();

    let output = sbh(&config, &["--json", "status"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    let reports = json["space_reports"]["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 1, "{json}");
    assert_eq!(reports[0]["mount"], "/");
    assert_eq!(reports[0]["level"], "critical");
    assert_eq!(reports[0]["report"], newer.as_str());
    assert!((660..=780).contains(&reports[0]["age_seconds"].as_u64().unwrap()));

    let human = sbh(&config, &["status"]);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    let rendered = stdout(&human);
    assert!(
        rendered.contains("Space Attribution (daemon reports, last 3 h):"),
        "{rendered}"
    );
    assert!(
        rendered.contains("/ CRITICAL, 12 min ago: largest directories: \"/home/ubuntu\" 120.0 GiB; inside \"/home/ubuntu\": \"/home/ubuntu/.cache\" 100.0 GiB"),
        "{rendered}"
    );
    assert_eq!(
        fs::read(&database).unwrap(),
        before,
        "status changed the database"
    );
}

fn append_ram_scratch_notice(database: &Path, timestamp: &str, details: &serde_json::Value) {
    use storage_ballast_helper::logger::sqlite::{ActivityRow, SqliteLogger};

    let db = SqliteLogger::open(database).unwrap();
    db.log_activity(&ActivityRow {
        timestamp: timestamp.to_string(),
        event_type: "info".to_string(),
        severity: "warning".to_string(),
        path: None,
        size_bytes: None,
        score: None,
        score_factors: None,
        pressure_level: None,
        free_pct: None,
        duration_ms: None,
        success: 1,
        error_code: None,
        error_message: None,
        details: Some(serde_json::to_string_pretty(details).unwrap()),
    })
    .unwrap();
}

fn assert_ram_scratch_status(
    config: &Path,
    database: &Path,
    payload: &serde_json::Value,
    expected: &str,
) {
    let before = fs::read(database).unwrap();
    let output = sbh(config, &["--json", "status"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    let notice = &json["ram_scratch"];
    assert_eq!(notice["availability"], "recorded");
    assert_eq!(notice["state"], payload["state"]);
    assert_eq!(notice["complete"], false);
    assert_eq!(notice["freshness"], "stale");
    assert_eq!(notice["issue_kinds"], payload["issue_kinds"]);
    assert!(notice["notice_age_seconds"].as_u64().unwrap() > 2100);
    let human = sbh(config, &["status"]);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    let rendered = stdout(&human);
    assert!(rendered.contains(expected), "{rendered}");
    assert!(
        rendered.contains("latest recorded notice; freshness stale"),
        "{rendered}"
    );
    assert!(
        rendered.contains(payload["issue_kinds"][0].as_str().unwrap()),
        "{rendered}"
    );
    if payload["state"] == "warning" {
        assert_eq!(notice["tmpfs_used_bytes"], 4096);
        assert!(rendered.contains("tmpfs_exceeds_half_ram"), "{rendered}");
    } else {
        assert!(notice["tmpfs_used_bytes"].is_null());
        assert!(rendered.contains("Observed tmpfs unknown"), "{rendered}");
    }
    assert_eq!(
        fs::read(database).unwrap(),
        before,
        "status changed the database"
    );
}

/// A later appended incomplete notice wins even if its clock moved backward
/// and it is older than the freshness threshold. Human and JSON status retain
/// incomplete evidence, including pressure warnings and failed probes.
#[test]
fn status_ram_scratch_retains_incomplete_notices_in_human_and_json_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path());
    let database = dir.path().join("data/activity.sqlite3");
    append_ram_scratch_notice(
        &database,
        "2001-01-01T00:00:00Z",
        &serde_json::json!({
            "schema": "sbh.ram_scratch.observation.v1",
            "state": "recovered", "complete": true,
            "observation": {"host": {"complete": true, "assessment": {
                "tmpfs_used_bytes": 0,
                "process_swap": {"bytes": 0, "complete": true},
                "memory": {"swap_free_bytes": 0, "swap_total_bytes": 0}
            }}}
        }),
    );

    for (payload, expected) in [
        (
            serde_json::json!({
                "schema": "sbh.ram_scratch.observation.v1",
                "state": "incomplete", "complete": false,
                "issue_kinds": ["mount_covered"],
                "observation": {
                    "observed_at": "2000-01-01T00:00:00Z",
                    "host": {"complete": false, "assessment": null}
                }
            }),
            "RAM scratch: INCOMPLETE",
        ),
        (
            serde_json::json!({
                "schema": "sbh.ram_scratch.observation.v1",
                "state": "warning", "complete": false,
                "issue_kinds": ["mount_covered"],
                "observation": {
                    "observed_at": "2000-01-01T00:00:00Z",
                    "host": {"complete": false, "assessment": {
                        "tmpfs_used_bytes": 4096,
                        "process_swap": {"bytes": 0},
                        "memory": {"swap_free_bytes": 0, "swap_total_bytes": 0},
                        "reasons": ["tmpfs_exceeds_half_ram"]
                    }}
                }
            }),
            "RAM scratch: WARNING; INCOMPLETE",
        ),
        (
            serde_json::json!({
                "schema": "sbh.ram_scratch.observation.v1",
                "state": "incomplete", "complete": false,
                "issue_kinds": ["probe_stalled"], "detail": "probe is still running"
            }),
            "RAM scratch: INCOMPLETE",
        ),
    ] {
        append_ram_scratch_notice(&database, "2000-01-01T00:00:01Z", &payload);
        assert_ram_scratch_status(&config, &database, &payload, expected);
    }
}
