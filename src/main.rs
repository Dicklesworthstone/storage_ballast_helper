#![forbid(unsafe_code)]

//! sbh — Storage Ballast Helper CLI entry point.

use clap::{CommandFactory, FromArgMatches};

mod cli_app;
mod cli_source_roots;

fn main() {
    storage_ballast_helper::daemon::service::capture_sbh_binary_path();
    let matches = cli_app::Cli::command().get_matches();
    // Capture the same target the updater selects, before it can replace us.
    // In particular, `update --system` may install somewhere other than the
    // running executable's directory. Do not restart that other installation.
    storage_ballast_helper::update_handoff::capture_install_path(update_install_path(&matches));
    let args = cli_app::Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    // Keep one owner through backup, publication, and the final service checks.
    // Locking only during rename permits a second update to replace the image
    // the first transaction is still trying to activate. No lock is acquired
    // for read-only update commands or unrelated service controls.
    #[cfg(target_os = "linux")]
    let _update_lock = match lock_update_command(&matches) {
        Ok(guard) => guard,
        Err(error) => {
            report_update_lock_failure(&matches, &error);
            std::process::exit(2);
        }
    };
    match cli_source_roots::run(&matches) {
        Ok(Some(0)) => return,
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("sbh: could not write source-root diagnostics: {error}");
            std::process::exit(2);
        }
    }
    if let Err(e) = cli_app::run(&args) {
        eprintln!("sbh: {e}");
        std::process::exit(e.exit_code());
    }
}

#[cfg(any(target_os = "linux", test))]
fn update_mutates_binary(matches: &clap::ArgMatches) -> bool {
    let Some(("update", update)) = matches.subcommand() else {
        return false;
    };
    // Match run_update's dispatch order. In particular rollback takes priority
    // over --prune/--check/--dry-run in the existing CLI and must remain locked.
    if update.get_flag("list_backups") {
        return false;
    }
    if update.contains_id("rollback") {
        return true;
    }
    !update.contains_id("prune") && !update.get_flag("check") && !update.get_flag("dry_run")
}

#[cfg(target_os = "linux")]
fn lock_update_command(matches: &clap::ArgMatches) -> std::io::Result<Option<std::fs::File>> {
    if !update_mutates_binary(matches) {
        return Ok(None);
    }
    let path = storage_ballast_helper::update_handoff::install_path()
        .ok_or_else(|| std::io::Error::other("missing captured update destination"))?;
    storage_ballast_helper::update_handoff::acquire_update_lock(path).map(Some)
}

#[cfg(target_os = "linux")]
fn report_update_lock_failure(matches: &clap::ArgMatches, error: &std::io::Error) {
    if matches.get_flag("json") {
        use std::io::Write as _;

        let report = serde_json::json!({
            "command": "update",
            "applied": false,
            "success": false,
            "install_path": storage_ballast_helper::update_handoff::install_path()
                .map(|path| path.to_string_lossy()),
            "service_restart": null,
            "error": error.to_string(),
            "exit_code": 2,
        });
        let _ = writeln!(std::io::stdout().lock(), "{report}");
    }
    eprintln!("sbh: cannot start update transaction: {error}");
}

fn update_install_path(matches: &clap::ArgMatches) -> Option<std::path::PathBuf> {
    let ("update", update) = matches.subcommand()? else {
        return None;
    };
    Some(
        storage_ballast_helper::cli::update::default_install_dir(update.get_flag("system"))
            .join("sbh"),
    )
}

#[cfg(test)]
mod entrypoint_tests {
    use super::*;

    #[test]
    fn update_target_uses_the_updaters_destination_policy() {
        for (args, system) in [
            (vec!["sbh", "update"], false),
            (vec!["sbh", "update", "--user"], false),
            (vec!["sbh", "--json", "update", "--system"], true),
        ] {
            let matches = cli_app::Cli::command().try_get_matches_from(args).unwrap();
            assert_eq!(
                update_install_path(&matches),
                Some(storage_ballast_helper::cli::update::default_install_dir(system).join("sbh"))
            );
        }
    }

    #[test]
    fn ordinary_service_control_does_not_arm_update_verification() {
        let matches = cli_app::Cli::command()
            .try_get_matches_from(["sbh", "status"])
            .unwrap();
        assert_eq!(update_install_path(&matches), None);
    }

    #[test]
    fn applying_and_rolling_back_require_exclusive_ownership() {
        let cases: &[&[&str]] = &[
            &["update"],
            &["update", "--force"],
            &["update", "--system"],
            &["update", "--user"],
            &["update", "--rollback"],
            &["update", "--rollback", "snapshot"],
            &["update", "--rollback", "--dry-run"],
            &["update", "--rollback", "--check"],
            &["update", "--rollback", "--prune", "0"],
        ];
        for args in cases {
            let matches = cli_app::Cli::command()
                .try_get_matches_from(std::iter::once("sbh").chain(args.iter().copied()))
                .unwrap();
            assert!(update_mutates_binary(&matches), "{args:?}");
        }
    }

    #[test]
    fn read_only_and_backup_only_commands_do_not_lock_the_installation() {
        let cases: &[&[&str]] = &[
            &["version"],
            &["service", "restart"],
            &["update", "--check"],
            &["update", "--dry-run", "--force"],
            &["update", "--list-backups"],
            &["update", "--list-backups", "--rollback"],
            &["update", "--prune", "0"],
        ];
        for args in cases {
            let matches = cli_app::Cli::command()
                .try_get_matches_from(std::iter::once("sbh").chain(args.iter().copied()))
                .unwrap();
            assert!(!update_mutates_binary(&matches), "{args:?}");
        }
    }
}
