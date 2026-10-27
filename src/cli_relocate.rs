//! `sbh relocate`: report, relocate, or restore dormant protected scratch.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use serde::Serialize;
use storage_ballast_helper::relocate::SCHEMA;
use storage_ballast_helper::relocate::config::{DEFAULT_CONFIG_PATH, RelocationConfig};
use storage_ballast_helper::relocate::ledger::{Ledger, WriterLock};
use storage_ballast_helper::relocate::plan::{self, Candidate, Plan, Verdict};

/// The `relocate` subcommand.
pub fn command() -> Command {
    Command::new("relocate")
        .about("Report, relocate, or restore protected scratch that has been dormant for weeks")
        .after_help(format!(
            "A .sbh-protect marker never expires, but protection means \"never delete\", not \"never move\". \
A protected tree under a scratch root whose every entry has been unchanged and unread for min_idle_days \
(14 by default), and that no process holds, may be copied to the configured target, verified with a \
checksum pass, and replaced by a stub that names the copy. Nothing is deleted before the copy verifies.\n\n\
Without --apply this only reports. Settings come from {DEFAULT_CONFIG_PATH}; --apply moves trees only when it says \
enabled = true and names a target, and otherwise reports and records ledger observations.\n\n\
Examples:\n  sbh relocate\n  sbh relocate --all --json\n  sudo sbh relocate --apply\n  sudo sbh relocate --restore /dev/shm/old-scratch"
        ))
        .arg(Arg::new("relocation_config").long("relocation-config").value_name("PATH")
            .value_parser(value_parser!(PathBuf))
            .help(format!("Relocation settings, default {DEFAULT_CONFIG_PATH}")))
        .arg(Arg::new("apply").long("apply").action(ArgAction::SetTrue)
            .conflicts_with("restore")
            .help("Relocate the eligible trees (Linux; with enabled = false, report and record observations only)"))
        .arg(Arg::new("restore").long("restore").value_name("STUB")
            .value_parser(value_parser!(PathBuf))
            .help("Copy a relocated tree back over its stub and verify it"))
        .arg(Arg::new("all").long("all").action(ArgAction::SetTrue)
            .help("List every unit, not just the eligible ones"))
        .arg(Arg::new("min_idle_days").long("min-idle-days").value_name("DAYS")
            .value_parser(value_parser!(u64).range(1..))
            .help("Override min_idle_days for this run"))
        .arg(Arg::new("root").long("root").value_name("PATH").action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf))
            .help("Search this root instead of the configured ones (repeatable)"))
        // Proof runs on a disposable fixture: ctime cannot be set back, and
        // libfaketime does not reach Rust's clock, so the clock moves instead.
        // Fenced to explicit roots and a non-default ledger.
        .arg(Arg::new("assume_now").long("assume-now").value_name("RFC3339").hide(true)
            .requires("root")
            .value_parser(|value: &str| chrono::DateTime::parse_from_rfc3339(value).map(|time| time.timestamp()))
            .help("Evaluate as if it were this time (fixtures only; needs --root and a non-default state_dir)"))
}

#[derive(Debug, Serialize)]
struct Report<'a> {
    schema: &'static str,
    config: Option<PathBuf>,
    min_idle_days: u64,
    target: Option<&'a str>,
    enabled: bool,
    marked_trees: usize,
    entries: u64,
    truncated: bool,
    observation_save: ObservationSave,
    totals: BTreeMap<&'static str, (usize, u64)>,
    candidates: Vec<&'a Candidate>,
    #[cfg(target_os = "linux")]
    outcomes: Vec<storage_ballast_helper::relocate::execute::Outcome>,
}

#[derive(Debug, Serialize)]
struct ObservationSave {
    saved: bool,
    reason: Option<String>,
}

/// One coherent ledger snapshot. A report may proceed without a writer lock
/// or usable history, but must then remain read-only for its whole lifetime.
struct LedgerSession {
    ledger: Ledger,
    _lock: Option<WriterLock>,
    write_blocker: Option<String>,
}

impl LedgerSession {
    fn open(state_dir: &Path, apply: bool) -> Result<Self, (i32, String)> {
        let (lock, mut write_blocker) = match WriterLock::acquire(state_dir) {
            Ok(lock) => (Some(lock), None),
            Err(error) => {
                let busy = error.kind() == io::ErrorKind::WouldBlock;
                let reason = if busy {
                    "another relocation is updating the ledger".to_string()
                } else {
                    format!("cannot lock the relocation ledger: {error}")
                };
                if apply {
                    return Err((if busy { 3 } else { 1 }, reason));
                }
                (None, Some(reason))
            }
        };
        // Only a genuinely absent file is a new ledger. If existing history
        // cannot be read, reporting uses no historical evidence and cannot
        // replace it; apply refuses before planning or starting a transfer.
        let ledger = match Ledger::load(state_dir) {
            Ok(ledger) => ledger,
            Err(error) => {
                let reason = format!(
                    "cannot read the relocation ledger; existing state was preserved and historical observations are unavailable: {error}"
                );
                if apply {
                    return Err((1, reason));
                }
                write_blocker = Some(reason);
                Ledger::default()
            }
        };
        Ok(Self {
            ledger,
            _lock: lock,
            write_blocker,
        })
    }

    fn save_observations(&self, state_dir: &Path) -> ObservationSave {
        let result = self.write_blocker.as_ref().map_or_else(
            || {
                self.ledger
                    .save(state_dir)
                    .map_err(|error| format!("cannot durably save the relocation ledger: {error}"))
            },
            |reason| Err(reason.clone()),
        );
        match result {
            Ok(()) => ObservationSave {
                saved: true,
                reason: None,
            },
            Err(reason) => ObservationSave {
                saved: false,
                reason: Some(reason),
            },
        }
    }
}

fn verdict_key(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Eligible => "eligible",
        Verdict::Changed { .. } => "changed",
        Verdict::Read { .. } => "read",
        Verdict::Observing { .. } => "observing",
        Verdict::Held { .. } => "held",
        Verdict::Excluded { .. } => "excluded",
        Verdict::NotRelocatable => "not_relocatable",
        Verdict::CrossesMount => "crosses_mount",
        Verdict::Unreadable => "unreadable",
        Verdict::Truncated => "truncated",
    }
}

fn gib(bytes: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let gib = bytes as f64 / f64::from(1u32 << 30);
    gib
}

fn describe(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Eligible => "dormant".into(),
        Verdict::Changed { idle_days } => format!("changed {idle_days}d ago"),
        Verdict::Read { idle_days } => format!("read {idle_days}d ago"),
        Verdict::Observing { observed_days } => {
            format!("no atime; quiet for {observed_days}d of observation")
        }
        Verdict::Held { reason } => format!("in use: {reason}"),
        Verdict::Excluded { pattern } => format!("excluded by {pattern}"),
        Verdict::NotRelocatable => "marker says relocatable = false".into(),
        Verdict::CrossesMount => "contains another mount".into(),
        Verdict::Unreadable => "not fully readable".into(),
        Verdict::Truncated => "walk budget ran out".into(),
    }
}

/// Dispatch `sbh relocate`; `None` for any other command.
pub fn run(matches: &ArgMatches) -> io::Result<Option<i32>> {
    let Some(("relocate", command)) = matches.subcommand() else {
        return Ok(None);
    };
    let json = matches.get_flag("json");
    if let Some(stub) = command.get_one::<PathBuf>("restore") {
        return Ok(Some(restore(stub, json)));
    }
    let (config, config_path) = match load_config(command) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("sbh relocate: {error}");
            return Ok(Some(1));
        }
    };
    // With relocation disabled, --apply still sweeps and records ledger
    // observations, so one timer can watch a host before it may move anything.
    let apply = command.get_flag("apply") && config.enabled;
    if command.get_flag("apply") && !config.enabled {
        eprintln!(
            "sbh relocate: relocation is not enabled in {DEFAULT_CONFIG_PATH}; reporting only"
        );
    }
    if apply && let Some(problem) = apply_blocker(&config) {
        eprintln!("sbh relocate: {problem}");
        return Ok(Some(1));
    }
    let now = match command.get_one::<i64>("assume_now") {
        Some(_) if config.state_dir == RelocationConfig::default().state_dir => {
            eprintln!("sbh relocate: --assume-now needs a config with its own state_dir");
            return Ok(Some(1));
        }
        Some(assumed) => *assumed,
        None => chrono::Utc::now().timestamp(),
    };
    // The same lock covers reports, disabled --apply sweeps, and active
    // transfers, from before the load until after the final completion save.
    let mut session = match LedgerSession::open(&config.state_dir, apply) {
        Ok(session) => session,
        Err((code, reason)) => {
            eprintln!("sbh relocate: {reason}");
            return Ok(Some(code));
        }
    };
    let platform = storage_ballast_helper::platform::current();
    let plan = plan::build_plan(&config, &platform, &mut session.ledger, now);
    let observation_save = session.save_observations(&config.state_dir);
    if apply && !observation_save.saved {
        eprintln!(
            "sbh relocate: {}; no transfer started",
            observation_save
                .reason
                .as_deref()
                .unwrap_or("ledger save failed")
        );
        return Ok(Some(1));
    }

    #[cfg(target_os = "linux")]
    let outcomes = if apply {
        execute(&config, &platform, &mut session.ledger, &plan, now)
    } else {
        Vec::new()
    };

    let show_all = command.get_flag("all");
    let candidates: Vec<&Candidate> = plan
        .candidates
        .iter()
        .filter(|candidate| show_all || candidate.selected)
        .collect();
    let report = Report {
        schema: SCHEMA,
        config: config_path,
        min_idle_days: config.min_idle_days,
        target: config.target.as_deref(),
        enabled: config.enabled,
        marked_trees: plan.marked_trees,
        entries: plan.entries,
        truncated: plan.truncated,
        observation_save,
        totals: totals(&plan),
        candidates,
        #[cfg(target_os = "linux")]
        outcomes,
    };
    let mut out = io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        write_human(&mut out, &report, &plan)?;
    }
    out.flush()?;
    #[cfg(target_os = "linux")]
    if report.outcomes.iter().any(|outcome| {
        matches!(
            outcome,
            storage_ballast_helper::relocate::execute::Outcome::Failed { .. }
        )
    }) {
        return Ok(Some(4));
    }
    Ok(Some(0))
}

/// The config file, with this run's overrides applied and validated.
fn load_config(command: &ArgMatches) -> io::Result<(RelocationConfig, Option<PathBuf>)> {
    let (mut config, path) = RelocationConfig::load(
        command
            .get_one::<PathBuf>("relocation_config")
            .map(PathBuf::as_path),
    )?;
    if let Some(days) = command.get_one::<u64>("min_idle_days") {
        config.min_idle_days = *days;
    }
    if let Some(roots) = command.get_many::<PathBuf>("root") {
        config.roots = roots.cloned().collect();
    }
    config.validate()?;
    Ok((config, path))
}

/// Totals over whole marked trees, so each byte counts once; the selected
/// units (which may sit below a tree that is still in use) separately.
fn totals(plan: &Plan) -> BTreeMap<&'static str, (usize, u64)> {
    let mut totals: BTreeMap<&'static str, (usize, u64)> = BTreeMap::new();
    for candidate in plan
        .candidates
        .iter()
        .filter(|candidate| candidate.stats.depth == 0)
    {
        let entry = totals.entry(verdict_key(&candidate.verdict)).or_default();
        entry.0 += 1;
        entry.1 += candidate.stats.bytes;
    }
    let selected = plan.selected();
    totals.insert(
        "selected",
        (
            selected.len(),
            selected.iter().map(|candidate| candidate.stats.bytes).sum(),
        ),
    );
    totals
}

fn apply_blocker(config: &RelocationConfig) -> Option<String> {
    if cfg!(not(target_os = "linux")) {
        return Some("--apply is supported on Linux only".into());
    }
    if config.target.is_none() {
        return Some(format!("no target; set target in {DEFAULT_CONFIG_PATH}"));
    }
    None
}

#[cfg(target_os = "linux")]
fn execute(
    config: &RelocationConfig,
    platform: &dyn storage_ballast_helper::platform::pal::Platform,
    ledger: &mut Ledger,
    plan: &Plan,
    now: i64,
) -> Vec<storage_ballast_helper::relocate::execute::Outcome> {
    use storage_ballast_helper::relocate::execute::{self, Outcome};
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut moved = 0u64;
    let mut outcomes = Vec::new();
    for candidate in plan.selected() {
        if moved.saturating_add(candidate.stats.bytes) > config.max_bytes_per_run {
            continue;
        }
        let outcome = execute::relocate(config, platform, ledger, candidate, &stamp, now);
        if let Outcome::Relocated { bytes, .. } = &outcome {
            moved += bytes;
        }
        // One line per unit in the journal as it happens, not only at the end.
        eprintln!(
            "sbh relocate: {}",
            serde_json::to_string(&outcome).unwrap_or_default()
        );
        outcomes.push(outcome);
    }
    outcomes
}

fn restore(stub: &std::path::Path, json: bool) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let result = storage_ballast_helper::relocate::execute::restore(stub);
        let (code, message) = match &result {
            Ok(restored) => match &restored.kept_stub {
                None => (0, format!("restored {}", restored.path.display())),
                Some((kept, names)) if names.is_empty() => (
                    0,
                    format!(
                        "restored {}; previous stub preserved for recovery at {}",
                        restored.path.display(),
                        kept.display()
                    ),
                ),
                Some((kept, names)) => (
                    0,
                    format!(
                        "restored {}; the old stub held other files ({}) and was kept at {}",
                        restored.path.display(),
                        names.join(", "),
                        kept.display()
                    ),
                ),
            },
            Err(error) => (4, format!("restore failed: {error}")),
        };
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "schema": SCHEMA,
                    "restore": stub,
                    "ok": result.is_ok(),
                    "message": message,
                    "kept_stub": result.as_ref().ok()
                        .and_then(|restored| restored.kept_stub.as_ref())
                        .map(|(path, names)| serde_json::json!({
                            "path": path,
                            "additional_entries": names,
                        })),
                })
            );
        } else {
            println!("sbh relocate: {message}");
        }
        code
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = json;
        eprintln!(
            "sbh relocate: --restore is supported on Linux only ({})",
            stub.display()
        );
        1
    }
}

fn write_human(out: &mut impl Write, report: &Report<'_>, plan: &Plan) -> io::Result<()> {
    writeln!(
        out,
        "sbh relocate: {} marked trees, {} units >= min_bytes, {} entries walked{}",
        report.marked_trees,
        plan.candidates.len(),
        report.entries,
        if report.truncated {
            " (walk budget ran out)"
        } else {
            ""
        }
    )?;
    writeln!(
        out,
        "  idle window {}d; target {}; {}",
        report.min_idle_days,
        report.target.unwrap_or("(none)"),
        if report.enabled {
            "enabled"
        } else {
            "report only"
        }
    )?;
    if report.observation_save.saved {
        writeln!(out, "  observations saved")?;
    } else {
        writeln!(
            out,
            "  observations not saved: {}",
            report
                .observation_save
                .reason
                .as_deref()
                .unwrap_or("ledger unavailable")
        )?;
    }
    for (key, (count, bytes)) in &report.totals {
        writeln!(out, "  {key:<16} {count:>5} trees {:>9.1} GiB", gib(*bytes))?;
    }
    for candidate in &report.candidates {
        writeln!(
            out,
            "{} {:>8.1} GiB  {}  ({})",
            if candidate.selected { "*" } else { " " },
            gib(candidate.stats.bytes),
            candidate.stats.path.display(),
            describe(&candidate.verdict)
        )?;
    }
    #[cfg(target_os = "linux")]
    for outcome in &report.outcomes {
        writeln!(
            out,
            "{}",
            serde_json::to_string(outcome).unwrap_or_default()
        )?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::*;
    use storage_ballast_helper::relocate::ledger::LEDGER_FILENAME;

    #[test]
    fn concurrent_report_cannot_overwrite_newer_transfer_state_even_after_unlock() {
        let tmp = tempfile::tempdir().unwrap();
        let active = WriterLock::acquire(tmp.path()).unwrap();
        let mut current = Ledger::default();
        current
            .in_progress
            .insert(PathBuf::from("/tmp/first"), "backup:first/".into());
        current.save(tmp.path()).unwrap();

        let mut report = LedgerSession::open(tmp.path(), false).unwrap();
        assert_eq!(
            report.ledger, current,
            "report can read the current snapshot"
        );
        report
            .ledger
            .observe(Path::new("/tmp/observed"), 1, true, 10, 20);
        // The writer advances while the report holds its earlier snapshot.
        current
            .in_progress
            .insert(PathBuf::from("/tmp/second"), "backup:second/".into());
        current.save(tmp.path()).unwrap();
        let saved_bytes = fs::read(tmp.path().join(LEDGER_FILENAME)).unwrap();
        drop(active);

        let status = report.save_observations(tmp.path());
        assert!(!status.saved);
        assert!(status.reason.unwrap().contains("another relocation"));
        assert_eq!(
            fs::read(tmp.path().join(LEDGER_FILENAME)).unwrap(),
            saved_bytes
        );
        assert_eq!(Ledger::load(tmp.path()).unwrap(), current);
    }

    #[test]
    fn a_report_writer_blocks_apply_until_its_last_save() {
        let tmp = tempfile::tempdir().unwrap();
        let mut report = LedgerSession::open(tmp.path(), false).unwrap();
        report
            .ledger
            .observe(Path::new("/tmp/observed"), 1, true, 10, 20);
        let (code, reason) = LedgerSession::open(tmp.path(), true).err().unwrap();
        assert_eq!(code, 3);
        assert!(reason.contains("another relocation"));
        assert!(report.save_observations(tmp.path()).saved);
        drop(report);

        let apply = LedgerSession::open(tmp.path(), true).unwrap();
        assert!(
            apply
                .ledger
                .observations
                .contains_key(Path::new("/tmp/observed"))
        );
    }

    #[test]
    fn corrupt_history_is_preserved_by_reports_and_refused_by_apply() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LEDGER_FILENAME);
        let corrupt = b"{\"in_progress\": {\"/tmp/valuable\": \"backup:";
        fs::write(&path, corrupt).unwrap();
        let mut report = LedgerSession::open(tmp.path(), false).unwrap();
        assert_eq!(report.ledger, Ledger::default());
        report
            .ledger
            .observe(Path::new("/tmp/new"), 1, true, 10, 20);
        let status = report.save_observations(tmp.path());
        assert!(!status.saved);
        assert!(
            status
                .reason
                .unwrap()
                .contains("historical observations are unavailable")
        );
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        drop(report);

        let (code, reason) = LedgerSession::open(tmp.path(), true).err().unwrap();
        assert_eq!(code, 1);
        assert!(reason.contains("existing state was preserved"));
        assert_eq!(fs::read(path).unwrap(), corrupt);
    }

    #[test]
    fn inaccessible_state_remains_read_only_for_reports_and_blocks_apply() {
        let tmp = tempfile::tempdir().unwrap();
        // Deterministic access failure even when this test runs as root.
        let state = tmp.path().join("state");
        fs::write(&state, b"existing state path").unwrap();
        let report = LedgerSession::open(&state, false).unwrap();
        assert!(!report.save_observations(&state).saved);
        assert_eq!(fs::read(&state).unwrap(), b"existing state path");
        assert_eq!(LedgerSession::open(&state, true).err().unwrap().0, 1);
    }

    #[test]
    fn report_exposes_observation_save_status_in_json_and_human_output() {
        let plan = Plan {
            marked_trees: 0,
            candidates: Vec::new(),
            entries: 0,
            truncated: false,
        };
        let report = Report {
            schema: SCHEMA,
            config: None,
            min_idle_days: 14,
            target: None,
            enabled: false,
            marked_trees: 0,
            entries: 0,
            truncated: false,
            observation_save: ObservationSave {
                saved: false,
                reason: Some("another relocation is updating the ledger".into()),
            },
            totals: BTreeMap::new(),
            candidates: Vec::new(),
            #[cfg(target_os = "linux")]
            outcomes: Vec::new(),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["observation_save"]["saved"], false);
        assert_eq!(
            json["observation_save"]["reason"],
            "another relocation is updating the ledger"
        );
        let mut human = Vec::new();
        write_human(&mut human, &report, &plan).unwrap();
        assert!(
            String::from_utf8(human)
                .unwrap()
                .contains("observations not saved: another relocation is updating the ledger")
        );
    }
}
