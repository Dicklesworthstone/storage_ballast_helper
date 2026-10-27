//! Exit-code and stream contract (C-EXIT, bd-rc-master-ajg1.4.4), asserted
//! against the built binary: 0 ok, 1 user error or pressure condition,
//! 2 runtime/IO failure, 4 partial success; human reports on stdout,
//! diagnostics on stderr; `--json` reports carry `exit_code`.

mod common;

use std::fs;
use std::path::Path;
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
