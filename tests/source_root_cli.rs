//! Binary-level source-root diagnostic regressions. No daemon is started and
//! no ballast is provisioned; every file examined belongs to the fixture.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

struct Fixture {
    directory: tempfile::TempDir,
    config: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(allow: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("sbh.toml");
        let root = directory.path().join("scan");
        fs::create_dir(&root).unwrap();
        let fixture = Self {
            directory,
            config,
            root,
        };
        fixture.configure(allow, "");
        fixture
    }

    fn configure(&self, allow: bool, extra: &str) {
        fs::write(
            &self.config,
            format!(
                "[scanner]\nroot_paths = [{}]\nallow_source_tree_roots = {allow}\n{extra}",
                serde_json::to_string(&self.root).unwrap(),
            ),
        )
        .unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sbh"));
        // Overrides apply to the subprocess only; parallel tests never mutate
        // this process's environment or inherit an operator's SBH opt-in.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SBH_") {
                command.env_remove(key);
            }
        }
        command
            .env("HOME", self.directory.path())
            .env("XDG_CONFIG_HOME", self.directory.path().join("config"))
            .env("XDG_DATA_HOME", self.directory.path().join("data"))
            .arg("--config")
            .arg(&self.config)
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run fixture sbh binary")
    }

    fn repository(&self, relative: &str) -> PathBuf {
        let repository = self.root.join(relative);
        fs::create_dir_all(repository.join(".git")).unwrap();
        repository
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "single JSON document required ({error}); stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// #33 is report-only in this release: plain `doctor` answers with the
/// source-root report, and a finding is a warning, not a failure.
fn reported(output: &Output, root: &Path) -> Value {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = json(output);
    assert_eq!(report["valid"], true);
    assert_eq!(report["status"], "warn");
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["source_roots"]["roots"][0]["root"], json!(root));
    assert_eq!(report["source_roots"]["roots"][0]["reclaim_allowed"], false);
    assert_eq!(
        report["assessment"],
        "report_only_configuration_not_enforced"
    );
    assert!(!report["warnings"].as_array().unwrap().is_empty());
    report
}

/// Commands with checks of their own name the root on stderr, keep stdout a
/// single JSON document, and go on to run those checks.
fn warned(output: &Output, root: &Path) -> Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sbh: warning: ") && stderr.contains(&root.display().to_string()),
        "{output:?}"
    );
    assert!(stderr.contains("report-only in this release"), "{output:?}");
    let own = json(output);
    assert!(
        own.get("source_roots").is_none(),
        "the command's own report"
    );
    own
}

#[test]
fn source_root_doctor_and_validation_report_nested_repositories_without_failing_or_mutating() {
    let fixture = Fixture::new(false);
    let repository = fixture.repository("team/project");
    let untracked = fixture.root.join("untracked-target");
    fs::create_dir(&untracked).unwrap();
    let evidence = untracked.join("evidence.txt");
    fs::write(&evidence, b"irreplaceable release evidence").unwrap();

    let report = reported(&fixture.run(&["doctor", "--json"]), &fixture.root);
    assert_eq!(
        report["source_roots"]["roots"][0]["finding"],
        "git_worktree"
    );
    assert_eq!(
        report["source_roots"]["roots"][0]["repositories"][0],
        json!(fs::canonicalize(&repository).unwrap())
    );
    warned(
        &fixture.run(&["doctor", "--system", "--json"]),
        &fixture.root,
    );
    let validation = fixture.run(&["config", "validate", "--json"]);
    assert!(validation.status.success(), "{validation:?}");
    assert_eq!(warned(&validation, &fixture.root)["valid"], true);

    assert_eq!(
        fs::read(&evidence).unwrap(),
        b"irreplaceable release evidence"
    );
    assert!(repository.join(".git").is_dir());
}

#[test]
fn source_root_gitfile_and_scan_root_inside_repository_are_detected() {
    let fixture = Fixture::new(false);
    fs::write(
        fixture.root.join(".git"),
        "gitdir: /missing/main/.git/worktrees/topic\n",
    )
    .unwrap();
    warned(
        &fixture.run(&["config", "validate", "--json"]),
        &fixture.root,
    );
    let build = fixture.root.join("target");
    fs::create_dir(&build).unwrap();
    fs::write(
        &fixture.config,
        format!(
            "[scanner]\nroot_paths = [{}]\n",
            serde_json::to_string(&build).unwrap()
        ),
    )
    .unwrap();
    let report = reported(&fixture.run(&["doctor", "--json"]), &build);
    assert_eq!(
        report["source_roots"]["roots"][0]["finding"],
        "git_worktree"
    );
}

#[test]
fn source_root_explicit_opt_in_clears_the_warning_and_revocation_is_visible_on_next_command() {
    let fixture = Fixture::new(true);
    fixture.repository("project");
    let doctor = fixture.run(&["doctor", "--json"]);
    assert!(doctor.status.success(), "{doctor:?}");
    let report = json(&doctor);
    assert_eq!(report["source_roots"]["allow_source_tree_roots"], true);
    assert_eq!(report["source_roots"]["roots"][0]["reclaim_allowed"], true);
    let validation = fixture.run(&["config", "validate", "--json"]);
    assert!(validation.status.success(), "{validation:?}");
    fixture.configure(false, "");
    reported(&fixture.run(&["doctor", "--json"]), &fixture.root);
    warned(
        &fixture.run(&["config", "validate", "--json"]),
        &fixture.root,
    );
}

#[test]
fn source_root_environment_override_is_explicit_and_can_revoke_file_opt_in() {
    let fixture = Fixture::new(false);
    fixture.repository("project");
    let allowed = fixture
        .command(&["doctor", "--json"])
        .env("SBH_SCANNER_ALLOW_SOURCE_TREE_ROOTS", "true")
        .output()
        .unwrap();
    assert!(allowed.status.success(), "{allowed:?}");
    assert_eq!(
        json(&allowed)["source_roots"]["allow_source_tree_roots"],
        true
    );
    fixture.configure(true, "");
    let denied = fixture
        .command(&["doctor", "--json"])
        .env("SBH_SCANNER_ALLOW_SOURCE_TREE_ROOTS", "false")
        .output()
        .unwrap();
    reported(&denied, &fixture.root);
    let invalid = fixture
        .command(&["doctor", "--json"])
        .env("SBH_SCANNER_ALLOW_SOURCE_TREE_ROOTS", "definitely")
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert_eq!(json(&invalid)["valid"], false);
    assert_eq!(json(&invalid)["source_roots"], Value::Null);
}

#[test]
fn source_root_clear_configuration_passes_but_new_repository_is_not_cached() {
    let fixture = Fixture::new(false);
    let initial = fixture.run(&["doctor", "--json"]);
    assert!(initial.status.success(), "{initial:?}");
    assert_eq!(
        json(&initial)["source_roots"]["roots"][0]["finding"],
        "clear"
    );
    fixture.repository("new/project");
    reported(&fixture.run(&["doctor", "--json"]), &fixture.root);
}

#[test]
fn source_root_diagnostics_do_not_make_unsafe_config_impossible_to_inspect() {
    let fixture = Fixture::new(false);
    fixture.repository("project");
    let output = fixture.run(&["config", "show", "--json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("allow_source_tree_roots"));
    warned(
        &fixture.run(&["config", "validate", "--json"]),
        &fixture.root,
    );
}

#[test]
fn source_root_permission_does_not_bypass_existing_strict_key_validation() {
    let fixture = Fixture::new(true);
    fixture.repository("project");
    fixture.configure(true, "not_an_sbh_setting = true\n");
    let output = fixture.run(&["config", "validate", "--strict", "--json"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("not_an_sbh_setting"));
}

use serde_json::json;
