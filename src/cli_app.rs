//! Top-level CLI definition and dispatch.

use clap::{Parser, Subcommand};

/// Storage Ballast Helper — prevents disk-full scenarios from coding agent swarms.
#[derive(Parser)]
#[command(name = "sbh", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Subcommand)]
pub enum Command {
    /// Install sbh as a system service (systemd or launchd).
    Install,
    /// Uninstall the sbh system service.
    Uninstall,
    /// Show current daemon status and disk pressure.
    Status,
    /// Show historical statistics and deletion logs.
    Stats,
    /// Run a one-shot artifact scan (no deletion).
    Scan,
    /// Run a one-shot scan and clean matching artifacts.
    Clean,
    /// Manage ballast files (create, release, resize).
    Ballast,
    /// Show or update configuration.
    Config,
    /// Run the daemon in the foreground (used by systemd/launchd).
    Daemon,
}

/// Dispatch CLI commands. Stubs for now — each bead fills in the real logic.
///
/// # Errors
/// Returns an error if the subcommand fails.
#[allow(clippy::unnecessary_wraps)] // stubs — will return errors once commands are wired in
pub fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
        Command::Install => {
            println!("install: not yet implemented");
        }
        Command::Uninstall => {
            println!("uninstall: not yet implemented");
        }
        Command::Status => {
            println!("status: not yet implemented");
        }
        Command::Stats => {
            println!("stats: not yet implemented");
        }
        Command::Scan => {
            println!("scan: not yet implemented");
        }
        Command::Clean => {
            println!("clean: not yet implemented");
        }
        Command::Ballast => {
            println!("ballast: not yet implemented");
        }
        Command::Config => {
            println!("config: not yet implemented");
        }
        Command::Daemon => {
            println!("daemon: not yet implemented");
        }
    }
    Ok(())
}
