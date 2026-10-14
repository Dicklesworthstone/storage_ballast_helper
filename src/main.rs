#![forbid(unsafe_code)]

//! sbh — Storage Ballast Helper CLI entry point.

use clap::{CommandFactory, FromArgMatches};

mod cli_app;
mod cli_compress;
mod cli_source_roots;

fn cli_command() -> clap::Command {
    cli_app::Cli::command().subcommand(cli_compress::command())
}

fn main() {
    storage_ballast_helper::daemon::service::capture_sbh_binary_path();
    let matches = cli_command().get_matches();
    // The opt-in compression command owns its report and exit status. Handle
    // it before converting legacy subcommands into the derive-based enum.
    match cli_compress::run(&matches) {
        Ok(Some(0)) => return,
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("sbh: could not write compression report: {error}");
            std::process::exit(2);
        }
    }
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
    #[cfg(target_os = "linux")]
    match linux_rollback::run(&matches) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("sbh: {error}");
            std::process::exit(error.exit_code());
        }
    }
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
    // Inventory still takes precedence over rollback, and rollback over prune.
    // Linux rollback previews never publish or activate an image.
    if update.get_flag("list_backups") {
        return false;
    }
    if update.contains_id("rollback") {
        return !update.get_flag("check") && !update.get_flag("dry_run");
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
            &["update", "--rollback", "--dry-run"],
            &["update", "--rollback", "--check"],
            &[
                "update",
                "--rollback",
                "snapshot",
                "--dry-run",
                "--prune",
                "0",
            ],
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

// Linux rollback needs the same verified activation as an ordinary update.
// Keep this entrypoint transaction inside the update lock; the BackupStore API
// remains a file-only operation for library callers and non-Linux platforms.
#[cfg(target_os = "linux")]
mod linux_rollback {
    use std::io::{self, Write as _};
    use std::path::{Path, PathBuf};

    use clap::ArgMatches;
    use serde::Serialize;
    use storage_ballast_helper::cli::update::{
        BackupStore, RollbackResult, UpdateServiceRestart, UpdateServiceRestartStatus,
    };
    use storage_ballast_helper::daemon::service::{SystemdConfig, SystemdServiceManager};
    use storage_ballast_helper::platform::pal::ServiceManager;

    use super::cli_app::CliError;

    struct Request {
        install_path: PathBuf,
        backup_id: Option<String>,
        user_scope: bool,
        dry_run: bool,
        check_only: bool,
    }

    impl Request {
        fn preview(&self) -> bool {
            self.dry_run || self.check_only
        }
    }

    // Retain the existing rollback fields while distinguishing file publication
    // from service activation. A restart failure must not imply restoration was
    // undone, and a preview must never look like an applied rollback.
    #[derive(Serialize)]
    struct Report {
        #[serde(flatten)]
        result: RollbackResult,
        applied: bool,
        dry_run: bool,
        check_only: bool,
        service_restart: Option<UpdateServiceRestart>,
    }

    pub fn run(matches: &ArgMatches) -> Result<bool, CliError> {
        let Some(("update", update)) = matches.subcommand() else {
            return Ok(false);
        };
        if update.get_flag("list_backups") || !update.contains_id("rollback") {
            return Ok(false);
        }
        let install_path = storage_ballast_helper::update_handoff::install_path()
            .ok_or_else(|| CliError::Internal("missing rollback destination".to_string()))?;
        let request = Request {
            install_path: install_path.to_path_buf(),
            backup_id: update.get_one::<String>("rollback").cloned(),
            user_scope: update.get_flag("user"),
            dry_run: update.get_flag("dry_run"),
            check_only: update.get_flag("check"),
        };
        let report = execute(
            &request,
            &BackupStore::open_default(),
            nix::unistd::geteuid().is_root(),
            || {
                // Lifecycle control only: no unit is generated or installed.
                // Use the selected destination, not current_exe after replacement.
                Box::new(SystemdServiceManager::new(SystemdConfig {
                    user_scope: request.user_scope,
                    binary_path: request.install_path.clone(),
                    read_write_paths: Vec::new(),
                }))
            },
        );
        let mut out = io::stdout().lock();
        if matches.get_flag("json") {
            serde_json::to_writer(&mut out, &report)?;
            writeln!(out)?;
        } else {
            write_human(&mut out, &report)?;
        }
        out.flush()?;
        if report.result.success {
            Ok(true)
        } else if report.applied {
            Err(CliError::Runtime(
                "rollback applied but service restart failed".to_string(),
            ))
        } else {
            Err(CliError::Runtime(
                report
                    .result
                    .error
                    .unwrap_or_else(|| "rollback failed".to_string()),
            ))
        }
    }

    fn execute<F>(request: &Request, store: &BackupStore, root: bool, manager: F) -> Report
    where
        F: FnOnce() -> Box<dyn ServiceManager>,
    {
        let result = if request.preview() {
            preview_restore(store, &request.install_path, request.backup_id.as_deref())
        } else {
            store.rollback(&request.install_path, request.backup_id.as_deref())
        };
        let result = result.unwrap_or_else(|error| RollbackResult {
            success: false,
            snapshot_id: request.backup_id.clone().unwrap_or_default(),
            restored_version: String::new(),
            install_path: request.install_path.clone(),
            error: Some(error),
        });
        let mut report = Report {
            applied: result.success && !request.preview(),
            result,
            dry_run: request.dry_run,
            check_only: request.check_only,
            service_restart: None,
        };
        if !report.applied {
            return report;
        }
        let manager = manager();
        let restart = activate(manager.as_ref(), request.user_scope, root);
        if restart.status == UpdateServiceRestartStatus::Failed {
            report.result.success = false;
            report.result.error = Some(format!(
                "binary restored but service activation failed: {}",
                restart.error.as_deref().unwrap_or("unknown service error")
            ));
        }
        report.service_restart = Some(restart);
        report
    }

    fn activate(
        manager: &dyn ServiceManager,
        user_scope: bool,
        root: bool,
    ) -> UpdateServiceRestart {
        let scope = if user_scope { "user" } else { "system" };
        // Match the ordinary update's ordering: missing services succeed even
        // for non-root callers; only loaded system services require root.
        match manager.is_loaded() {
            Ok(false) => UpdateServiceRestart::skipped("systemd", scope, "service is not loaded"),
            Ok(true) if !user_scope && !root => UpdateServiceRestart::failed(
                "systemd",
                scope,
                "restarting a system-scope service requires root; the binary was restored; run `sudo sbh service --systemd restart`",
            ),
            Ok(true) => match manager.restart() {
                // With the update handoff armed, the existing Linux manager
                // verifies both ExecStart and the running replacement's inode.
                Ok(()) => UpdateServiceRestart::restarted("systemd", scope),
                Err(error) => UpdateServiceRestart::failed("systemd", scope, error.to_string()),
            },
            Err(error) => UpdateServiceRestart::failed(
                "systemd",
                scope,
                format!("failed to determine whether service is loaded: {error}"),
            ),
        }
    }

    fn preview_restore(
        store: &BackupStore,
        install_path: &Path,
        backup_id: Option<&str>,
    ) -> Result<RollbackResult, String> {
        let entries = store.list();
        let snapshot = match backup_id {
            Some(id) => entries
                .iter()
                .find(|entry| entry.id == id)
                .ok_or_else(|| format!("backup '{id}' not found"))?,
            None => entries.first().ok_or("no backups available for rollback")?,
        };
        let metadata = std::fs::symlink_metadata(&snapshot.path)
            .map_err(|error| format!("cannot inspect rollback backup: {error}"))?;
        if !metadata.is_file() {
            return Err("rollback backup is not a regular file".to_string());
        }
        // This is a read-only plan, not execution or supply-chain validation.
        Ok(RollbackResult {
            success: true,
            snapshot_id: snapshot.id.clone(),
            restored_version: snapshot.version.clone(),
            install_path: install_path.to_path_buf(),
            error: None,
        })
    }

    fn write_human(out: &mut impl io::Write, report: &Report) -> io::Result<()> {
        if report.applied {
            writeln!(
                out,
                "Restored {} from backup {} to {}.",
                report.result.restored_version,
                report.result.snapshot_id,
                report.result.install_path.display()
            )?;
        } else if report.result.success {
            writeln!(
                out,
                "Would restore {} from backup {} to {} (no files or services changed).",
                report.result.restored_version,
                report.result.snapshot_id,
                report.result.install_path.display()
            )?;
        }
        if let Some(restart) = &report.service_restart {
            writeln!(out, "{}", restart.message)?;
        }
        if let Some(error) = &report.result.error {
            writeln!(out, "Rollback failed: {error}")?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use storage_ballast_helper::core::errors::{Result as ServiceResult, SbhError};

        struct MockService {
            loaded: bool,
            probe_fails: bool,
            restart_fails: bool,
            restarts: Arc<AtomicUsize>,
        }

        impl ServiceManager for MockService {
            fn install(&self) -> ServiceResult<()> {
                panic!("rollback must not install a unit")
            }

            fn uninstall(&self) -> ServiceResult<()> {
                panic!("rollback must not uninstall a unit")
            }

            fn status(&self) -> ServiceResult<String> {
                panic!("use loaded state")
            }

            fn is_loaded(&self) -> ServiceResult<bool> {
                if self.probe_fails {
                    Err(SbhError::Runtime {
                        details: "fixture query denied".to_string(),
                    })
                } else {
                    Ok(self.loaded)
                }
            }

            fn restart(&self) -> ServiceResult<()> {
                self.restarts.fetch_add(1, Ordering::SeqCst);
                if self.restart_fails {
                    Err(SbhError::Runtime {
                        details: "fixture activation failed".to_string(),
                    })
                } else {
                    Ok(())
                }
            }
        }

        fn fixture() -> (tempfile::TempDir, BackupStore, Request) {
            let temp = tempfile::tempdir().unwrap();
            let install_path = temp.path().join("custom destination/sbh");
            std::fs::create_dir_all(install_path.parent().unwrap()).unwrap();
            std::fs::write(&install_path, b"previous image").unwrap();
            let store = BackupStore::open(temp.path().join("backups"));
            let backup = store.create(&install_path, "0.7.0").unwrap();
            std::fs::write(&install_path, b"current image").unwrap();
            let request = Request {
                install_path,
                backup_id: Some(backup.id),
                user_scope: true,
                dry_run: false,
                check_only: false,
            };
            (temp, store, request)
        }

        #[test]
        fn rollback_activates_loaded_services_and_skips_absent_ones() {
            for (loaded, user_scope, root, expected, restart_count) in [
                (false, false, false, UpdateServiceRestartStatus::Skipped, 0),
                (true, true, false, UpdateServiceRestartStatus::Restarted, 1),
                (true, false, true, UpdateServiceRestartStatus::Restarted, 1),
                (true, false, false, UpdateServiceRestartStatus::Failed, 0),
            ] {
                let (_temp, store, mut request) = fixture();
                request.user_scope = user_scope;
                let restarts = Arc::new(AtomicUsize::new(0));
                let report = execute(&request, &store, root, || {
                    Box::new(MockService {
                        loaded,
                        probe_fails: false,
                        restart_fails: false,
                        restarts: restarts.clone(),
                    })
                });
                assert!(report.applied);
                assert_eq!(
                    report.result.success,
                    expected != UpdateServiceRestartStatus::Failed
                );
                assert_eq!(report.service_restart.as_ref().unwrap().status, expected);
                assert_eq!(restarts.load(Ordering::SeqCst), restart_count);
                assert_eq!(
                    std::fs::read(&request.install_path).unwrap(),
                    b"previous image"
                );
                let json = serde_json::to_value(&report).unwrap();
                assert_eq!(json["applied"], true);
                assert_eq!(json["snapshot_id"], request.backup_id.as_deref().unwrap());
                if expected == UpdateServiceRestartStatus::Failed {
                    assert!(report.result.error.unwrap().contains("requires root"));
                }
            }
        }

        #[test]
        fn activation_errors_do_not_claim_the_restoration_was_undone() {
            for probe_fails in [true, false] {
                let (_temp, store, request) = fixture();
                let restarts = Arc::new(AtomicUsize::new(0));
                let report = execute(&request, &store, false, || {
                    Box::new(MockService {
                        loaded: true,
                        probe_fails,
                        restart_fails: true,
                        restarts: restarts.clone(),
                    })
                });
                assert!(report.applied);
                assert!(!report.result.success);
                assert_eq!(
                    report.service_restart.as_ref().unwrap().status,
                    UpdateServiceRestartStatus::Failed
                );
                assert_eq!(restarts.load(Ordering::SeqCst), usize::from(!probe_fails));
                assert_eq!(
                    std::fs::read(&request.install_path).unwrap(),
                    b"previous image"
                );
                let expected = if probe_fails {
                    "fixture query denied"
                } else {
                    "fixture activation failed"
                };
                assert!(report.result.error.as_ref().unwrap().contains(expected));
                let mut out = Vec::new();
                write_human(&mut out, &report).unwrap();
                let text = String::from_utf8(out).unwrap();
                assert!(text.contains("Restored 0.7.0"));
                assert!(text.contains("Rollback failed"));
            }
        }

        #[test]
        fn previews_never_restore_or_construct_a_service_manager() {
            use std::os::unix::fs::MetadataExt as _;

            for dry_run in [true, false] {
                let (_temp, store, mut request) = fixture();
                request.dry_run = dry_run;
                request.check_only = !dry_run;
                let before = std::fs::metadata(&request.install_path).unwrap().ino();
                let report = execute(&request, &store, false, || {
                    panic!("preview touched service")
                });
                assert!(report.result.success);
                assert!(!report.applied);
                assert!(report.service_restart.is_none());
                assert_eq!(
                    std::fs::metadata(&request.install_path).unwrap().ino(),
                    before
                );
                assert_eq!(
                    std::fs::read(&request.install_path).unwrap(),
                    b"current image"
                );
                assert_eq!(store.list().len(), 1);
                let mut out = Vec::new();
                write_human(&mut out, &report).unwrap();
                assert!(
                    String::from_utf8(out)
                        .unwrap()
                        .contains("no files or services changed")
                );
            }
        }

        #[test]
        fn missing_snapshot_leaves_binary_and_service_untouched() {
            let (_temp, store, mut request) = fixture();
            request.backup_id = Some("missing-snapshot".to_string());
            for dry_run in [true, false] {
                request.dry_run = dry_run;
                let report = execute(&request, &store, false, || {
                    panic!("failed restore touched service")
                });
                assert!(!report.result.success);
                assert!(!report.applied);
                assert!(report.service_restart.is_none());
                assert!(report.result.error.unwrap().contains("not found"));
                assert_eq!(
                    std::fs::read(&request.install_path).unwrap(),
                    b"current image"
                );
            }
        }

        #[test]
        fn preview_selects_latest_backup_and_rejects_symlink_sources() {
            let (_temp, store, mut request) = fixture();
            let snapshot = store.list().remove(0);
            request.backup_id = None;
            request.dry_run = true;
            let report = execute(&request, &store, false, || {
                panic!("preview touched service")
            });
            assert_eq!(report.result.snapshot_id, snapshot.id);
            assert!(report.result.success);
            let saved = snapshot.path.with_extension("retained");
            std::fs::rename(&snapshot.path, &saved).unwrap();
            std::os::unix::fs::symlink(&saved, &snapshot.path).unwrap();
            for dry_run in [true, false] {
                request.dry_run = dry_run;
                let report = execute(&request, &store, false, || {
                    panic!("invalid source touched service")
                });
                assert!(!report.result.success);
                assert!(!report.applied);
                assert!(report.service_restart.is_none());
                assert_eq!(
                    std::fs::read(&request.install_path).unwrap(),
                    b"current image"
                );
            }
        }
    }
}
