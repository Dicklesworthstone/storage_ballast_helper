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
}
