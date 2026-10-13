//! Read-only source-root checks at CLI dispatch, before diagnostic repairs.
//!
//! The config loader deliberately accepts source-containing roots so ballast
//! and independent recovery remain available. Commands that certify a setup
//! must nevertheless fail when reclamation has not been explicitly authorized.
//! This assessment is not a claim about the running daemon's installed policy.

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

#[derive(Debug, Serialize)]
struct Assessment {
    command: &'static str,
    status: &'static str,
    valid: bool,
    exit_code: i32,
    config_file: Option<PathBuf>,
    /// Explicitly distinguish this read-only assessment from live enforcement.
    assessment: &'static str,
    source_roots: Option<SourceRootReport>,
    errors: Vec<String>,
    /// Other requested checks have not run after a failing prerequisite.
    remaining_checks: &'static str,
}

impl Assessment {
    fn from_config(diagnostic: Diagnostic, config: &Config) -> Self {
        let report = config.source_root_report();
        let errors = report.failures();
        let valid = errors.is_empty();
        Self {
            command: diagnostic.command(),
            status: if valid { "ok" } else { "fail" },
            valid,
            exit_code: i32::from(!valid),
            config_file: Some(config.paths.config_file.clone()),
            assessment: "configuration_only_not_live_daemon_enforcement",
            source_roots: Some(report),
            errors,
            remaining_checks: if matches!(diagnostic, Diagnostic::Doctor { source_only: true }) {
                "not_requested"
            } else {
                "not_run"
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
            assessment: "configuration_only_not_live_daemon_enforcement",
            source_roots: None,
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
            if self.valid { "PASS" } else { "FAIL" }
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
        writeln!(
            output,
            "This is a configuration assessment, not proof of live daemon enforcement."
        )?;
        if self.remaining_checks == "not_run" {
            writeln!(output, "Other requested checks were not run.")?;
        }
        Ok(())
    }
}

/// `Some(code)` means this command was fully answered; `None` continues normal
/// dispatch. In particular, ballast, cleanup and config inspection do not gain
/// a new global loader failure. This function never mutates a source root.
pub(super) fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
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
        assert!(!assessment.valid);
        assert_eq!(assessment.errors.len(), 2);
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
        assert_eq!(parsed["exit_code"], 1);
        assert_eq!(parsed["valid"], false);
        assert_eq!(parsed["remaining_checks"], "not_run");
        let mut text = Vec::new();
        assessment.write(false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("Source-root configuration: FAIL"));
        assert!(text.contains("team/repository"));
        assert!(text.contains("scanner.allow_source_tree_roots = true"));
    }

    #[test]
    fn source_root_opt_in_does_not_authorize_an_unverified_root() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.scanner.root_paths = vec![directory.path().join("missing")];
        config.scanner.allow_source_tree_roots = true;
        let assessment = Assessment::from_config(Diagnostic::ConfigValidate, &config);
        assert!(!assessment.valid);
        assert_eq!(assessment.exit_code, 1);
        assert!(assessment.errors[0].contains("cannot resolve"));
    }
}
