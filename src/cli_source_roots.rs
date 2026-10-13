//! Read-only source-root checks at CLI dispatch, before diagnostic repairs.
//!
//! The config loader deliberately accepts source-containing roots so ballast
//! and independent recovery remain available. This assessment is not a claim
//! about the running daemon's installed policy.
//!
//! Report-only in this release (#33): findings are warnings and never change
//! `valid` or the exit code. As defined, a source root is any root with a Git
//! marker anywhere beneath it or an inconclusive inspection, which on real
//! hosts is every temp root, so failing here failed `doctor` and
//! `config validate` everywhere and kept the real validation from running.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{ArgMatches, parser::ValueSource};
use serde::Serialize;

use storage_ballast_helper::core::config::Config;
use storage_ballast_helper::scanner::source_roots::SourceRootReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Diagnostic {
    Doctor { source_only: bool },
    ConfigValidate,
}

impl Diagnostic {
    const fn command(self) -> &'static str {
        match self {
            Self::Doctor { .. } => "doctor",
            Self::ConfigValidate => "config validate",
        }
    }
}

fn diagnostic(matches: &ArgMatches) -> Option<Diagnostic> {
    match matches.subcommand() {
        Some(("doctor", doctor)) => {
            // The globals are propagated to the subcommand by clap. They do
            // not select an additional diagnostic target; defaults do not
            // count either. Do not duplicate DoctorArgs' growing target list.
            let has_target = doctor.ids().any(|id| {
                !matches!(
                    id.as_str(),
                    "config" | "json" | "no_color" | "verbose" | "quiet"
                ) && doctor.value_source(id.as_str()) == Some(ValueSource::CommandLine)
            });
            Some(Diagnostic::Doctor {
                source_only: !has_target,
            })
        }
        Some(("config", config)) if config.subcommand_name() == Some("validate") => {
            Some(Diagnostic::ConfigValidate)
        }
        _ => None,
    }
}

/// What this report is, as opposed to live enforcement.
const SCOPE: &str = "report_only_configuration_not_enforced";

#[derive(Debug, Serialize)]
struct Assessment {
    command: &'static str,
    status: &'static str,
    valid: bool,
    exit_code: i32,
    config_file: Option<PathBuf>,
    /// Explicitly distinguish this read-only assessment from live enforcement.
    #[serde(rename = "assessment")]
    scope: &'static str,
    source_roots: Option<SourceRootReport>,
    /// Roots the policy would not let sbh reclaim from. Report-only.
    warnings: Vec<String>,
    errors: Vec<String>,
    /// Other requested checks have not run after a failing prerequisite.
    remaining_checks: &'static str,
}

impl Assessment {
    fn from_config(diagnostic: Diagnostic, config: &Config) -> Self {
        let report = config.source_root_report();
        let warnings = report.failures();
        Self {
            command: diagnostic.command(),
            status: if warnings.is_empty() { "ok" } else { "warn" },
            valid: true,
            exit_code: 0,
            config_file: Some(config.paths.config_file.clone()),
            scope: SCOPE,
            source_roots: Some(report),
            warnings,
            errors: Vec::new(),
            remaining_checks: if matches!(diagnostic, Diagnostic::Doctor { source_only: true }) {
                "not_requested"
            } else {
                "pending"
            },
        }
    }

    fn load_error(diagnostic: Diagnostic, config_file: Option<PathBuf>, error: String) -> Self {
        Self {
            command: diagnostic.command(),
            status: "fail",
            valid: false,
            exit_code: 1,
            config_file,
            scope: SCOPE,
            source_roots: None,
            warnings: Vec::new(),
            errors: vec![error],
            remaining_checks: "not_run",
        }
    }

    fn write(&self, json: bool, output: &mut impl Write) -> io::Result<()> {
        if json {
            serde_json::to_writer_pretty(&mut *output, self).map_err(io::Error::other)?;
            writeln!(output)?;
            return Ok(());
        }
        writeln!(
            output,
            "Source-root configuration: {}",
            match (self.valid, self.warnings.is_empty()) {
                (false, _) => "FAIL",
                (true, false) => "WARN",
                (true, true) => "PASS",
            }
        )?;
        if let Some(report) = &self.source_roots {
            for root in &report.roots {
                writeln!(output, "  {}", root.diagnostic())?;
            }
        } else {
            for error in &self.errors {
                writeln!(output, "  {error}")?;
            }
        }
        if !self.warnings.is_empty() {
            writeln!(output, "{REPORT_ONLY_NOTE}")?;
        }
        writeln!(
            output,
            "This is a configuration assessment, not proof of live daemon enforcement."
        )?;
        if self.remaining_checks == "not_run" {
            writeln!(output, "Other requested checks were not run.")?;
        }
        Ok(())
    }

    /// The findings as warnings, for commands that go on to their own checks.
    fn warn(&self, output: &mut impl Write) -> io::Result<()> {
        for warning in &self.warnings {
            writeln!(output, "sbh: warning: {warning}")?;
        }
        if !self.warnings.is_empty() {
            writeln!(output, "sbh: warning: {REPORT_ONLY_NOTE}")?;
        }
        Ok(())
    }
}

const REPORT_ONLY_NOTE: &str = "source-root detection is report-only in this release: \
     nothing is refused, and these roots are still scanned and reclaimed";

/// `Some(code)` means this command was fully answered; `None` continues normal
/// dispatch. In particular, ballast, cleanup and config inspection do not gain
/// a new global loader failure. This function never mutates a source root.
pub fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
    let Some(diagnostic) = diagnostic(matches) else {
        return Ok(None);
    };
    let explicit_path = matches.get_one::<PathBuf>("config");
    let assessment = match Config::load(explicit_path.map(PathBuf::as_path)) {
        Ok(config) => Assessment::from_config(diagnostic, &config),
        Err(error) => Assessment::load_error(diagnostic, explicit_path.cloned(), error.to_string()),
    };
    if assessment.valid && !matches!(diagnostic, Diagnostic::Doctor { source_only: true }) {
        // Existing validation still owns strict/unknown-key checks, and the
        // existing doctor owns every selected PAL/service/release diagnostic.
        // The findings go to stderr so a `--json` document stays whole.
        assessment.warn(&mut io::stderr().lock())?;
        return Ok(None);
    }
    assessment.write(matches.get_flag("json"), &mut io::stdout().lock())?;
    Ok(Some(assessment.exit_code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> ArgMatches {
        crate::cli_app::Cli::command()
            .try_get_matches_from(args)
            .expect("real CLI schema accepts fixture arguments")
    }

    #[test]
    fn source_root_diagnostics_use_the_real_cli_schema_and_global_options() {
        assert_eq!(
            diagnostic(&parse(&["sbh", "doctor", "--json"])),
            Some(Diagnostic::Doctor { source_only: true })
        );
        assert_eq!(
            diagnostic(&parse(&["sbh", "--config", "/tmp/sbh-test.toml", "doctor"])),
            Some(Diagnostic::Doctor { source_only: true })
        );
        assert_eq!(
            diagnostic(&parse(&["sbh", "doctor", "--system", "--json"])),
            Some(Diagnostic::Doctor { source_only: false })
        );
        assert_eq!(
            diagnostic(&parse(&["sbh", "config", "validate", "--strict"])),
            Some(Diagnostic::ConfigValidate)
        );
    }

    #[test]
    fn source_root_validation_does_not_intercept_ballast_or_config_inspection() {
        for args in [
            vec!["sbh", "ballast", "status"],
            vec!["sbh", "config", "show"],
            vec!["sbh", "config", "path"],
            vec!["sbh", "status", "--json"],
        ] {
            assert_eq!(diagnostic(&parse(&args)), None, "{args:?}");
        }
    }

    #[test]
    fn source_root_report_names_each_blocked_root_and_repository() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        std::fs::create_dir_all(first.join("team/repository/.git")).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(second.join(".git"), "gitdir: /missing/linked/worktree\n").unwrap();
        let mut config = Config::default();
        config.scanner.root_paths = vec![first.clone(), second.clone()];
        let assessment = Assessment::from_config(Diagnostic::ConfigValidate, &config);
        // Report-only (#33): both roots are named, neither fails the command.
        assert!(assessment.valid);
        assert_eq!(assessment.status, "warn");
        assert!(assessment.errors.is_empty());
        assert_eq!(assessment.warnings.len(), 2);
        let report = assessment.source_roots.as_ref().unwrap();
        assert_eq!(report.roots.len(), 2);
        assert!(report.roots.iter().all(|root| !root.reclaim_allowed));
        assert_eq!(report.roots[0].root, first);
        assert_eq!(report.roots[1].root, second);
        assert!(
            report
                .roots
                .iter()
                .all(|root| !root.repositories.is_empty())
        );
        let mut json = Vec::new();
        assessment.write(true, &mut json).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed["exit_code"], 0);
        assert_eq!(parsed["valid"], true);
        assert_eq!(parsed["assessment"], SCOPE);
        assert_eq!(parsed["warnings"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["remaining_checks"], "pending");
        let mut text = Vec::new();
        assessment.write(false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("Source-root configuration: WARN"));
        assert!(text.contains("team/repository"));
        assert!(text.contains("scanner.allow_source_tree_roots = true"));
        assert!(text.contains("report-only in this release"));
        let mut stderr = Vec::new();
        assessment.warn(&mut stderr).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();
        assert_eq!(stderr.matches("sbh: warning: ").count(), 3);
        assert!(stderr.contains("team/repository"));
    }

    #[test]
    fn source_root_opt_in_does_not_authorize_an_unverified_root() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.scanner.root_paths = vec![directory.path().join("missing")];
        config.scanner.allow_source_tree_roots = true;
        let assessment = Assessment::from_config(Diagnostic::ConfigValidate, &config);
        // Still reported as not reclaimable; report-only, so not a failure.
        assert!(assessment.valid);
        assert_eq!(assessment.exit_code, 0);
        assert!(assessment.warnings[0].contains("cannot resolve"));
        let report = assessment.source_roots.as_ref().unwrap();
        assert!(!report.roots[0].reclaim_allowed);
    }
}
