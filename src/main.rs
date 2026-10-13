#![forbid(unsafe_code)]

//! sbh — Storage Ballast Helper CLI entry point.

use clap::Parser;

mod cli_app;

fn main() {
    // Preserve the installed path before `update` can unlink our running inode.
    storage_ballast_helper::daemon::service::capture_sbh_binary_path();
    let args = cli_app::Cli::parse();
    if let Err(e) = cli_app::run(&args) {
        eprintln!("sbh: {e}");
        std::process::exit(e.exit_code());
    }
}
