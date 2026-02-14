//! Integration smoke tests for the scaffolded `sbh` CLI surface.

mod common;

#[test]
fn help_command_prints_usage() {
    let result = common::run_cli_case("help_command_prints_usage", &["--help"]);
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("Usage: sbh [OPTIONS] <COMMAND>"),
        "missing help banner; log: {}",
        result.log_path.display()
    );
}

#[test]
fn version_command_prints_version() {
    let result = common::run_cli_case("version_command_prints_version", &["--version"]);
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("storage_ballast_helper")
            || result.stdout.contains("sbh")
            || result.stderr.contains("storage_ballast_helper"),
        "missing version output; log: {}",
        result.log_path.display()
    );
}

#[test]
fn subcommands_have_scaffolded_handlers() {
    let cases: [(&[&str], &str); 18] = [
        (&["install"], "install: not yet implemented"),
        (&["uninstall"], "uninstall: not yet implemented"),
        (&["status"], "status: not yet implemented"),
        (&["stats"], "stats: not yet implemented"),
        (&["scan"], "scan: not yet implemented"),
        (&["clean"], "clean: not yet implemented"),
        (&["ballast"], "ballast: not yet implemented"),
        (
            &["ballast", "status"],
            "ballast status: not yet implemented",
        ),
        (&["config"], "config: not yet implemented"),
        (&["config", "show"], "config show: not yet implemented"),
        (&["daemon"], "daemon: not yet implemented"),
        (
            &["emergency", "/tmp", "--yes"],
            "emergency: not yet implemented",
        ),
        (&["protect", "--list"], "protect: not yet implemented"),
        (&["unprotect", "/tmp"], "unprotect: not yet implemented"),
        (&["tune"], "tune: not yet implemented"),
        (&["check", "/tmp"], "check: not yet implemented"),
        (&["blame"], "blame: not yet implemented"),
        (&["dashboard"], "dashboard: not yet implemented"),
    ];

    for (args, expected) in cases {
        let case_name = format!("subcommand_{}", args.join("_"));
        let result = common::run_cli_case(&case_name, args);
        assert!(
            result.status.success(),
            "subcommand {:?} failed; log: {}",
            args,
            result.log_path.display()
        );
        assert!(
            result.stdout.contains(expected) || result.stderr.contains(expected),
            "subcommand {:?} output mismatch; log: {}",
            args,
            result.log_path.display()
        );
    }
}

#[test]
fn json_mode_outputs_structured_payload() {
    let result = common::run_cli_case(
        "json_mode_outputs_structured_payload",
        &["status", "--json"],
    );
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("\"command\":\"status\"")
            && result.stdout.contains("\"status\":\"not_implemented\""),
        "expected structured JSON payload; log: {}",
        result.log_path.display()
    );
}

#[test]
fn completions_command_generates_shell_script() {
    let result = common::run_cli_case(
        "completions_command_generates_shell_script",
        &["completions", "bash"],
    );
    assert!(
        result.status.success(),
        "expected success; log: {}",
        result.log_path.display()
    );
    assert!(
        result.stdout.contains("sbh"),
        "expected completion script contents; log: {}",
        result.log_path.display()
    );
}
