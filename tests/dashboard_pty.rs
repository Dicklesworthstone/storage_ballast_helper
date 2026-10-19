//! The dashboard under a pseudo-terminal (bd-rc-master-ajg1.4.15, and
//! deliverable 1 of 4.12): the shipped binary is driven through a pty
//! against a sandbox daemon, so the whole chain is exercised: key routing,
//! rendering, the confirmation modal, the control socket, the daemon's
//! ballast coordinator, and the activity log.
//!
//! No terminal is needed on the host: `openpty` provides both ends. The
//! master side is read on a thread; keys are written to it with the same
//! pauses a person would leave. The cockpit's backend opens `/dev/tty`,
//! so the child must own the slave as its controlling terminal: util-linux
//! `setsid -c` makes it one (a new session with stdin as the tty) without
//! any unsafe `pre_exec` in this crate.

#![cfg(all(feature = "tui", target_os = "linux"))]

mod common;

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::pty::{Winsize, openpty};
use serde_json::Value;

/// Scratch under `/data/tmp` when it exists (a real, non-volatile mount on
/// the development hosts), else the system temp dir.
fn scratch() -> tempfile::TempDir {
    let preferred = PathBuf::from("/data/tmp");
    let base = if preferred.is_dir() {
        preferred
    } else {
        std::env::temp_dir()
    };
    tempfile::tempdir_in(base).unwrap()
}

/// A sandbox config: two 1 MiB ballast files, the daemon's own files
/// beside them, one empty scan root, fast polling.
fn write_config(dir: &Path) -> PathBuf {
    let data = dir.join("data");
    let root = dir.join("root");
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&root).unwrap();
    let config = format!(
        r"[paths]
ballast_dir = {ballast:?}
jsonl_log = {jsonl:?}
sqlite_db = {sqlite:?}
state_file = {state:?}
[ballast]
file_count = 2
file_size_bytes = 1048576
[pressure]
poll_interval_ms = 500
green_min_free_pct = 0.04
yellow_min_free_pct = 0.03
orange_min_free_pct = 0.02
red_min_free_pct = 0.01
[scanner]
include_user_temp_dir = false
root_paths = [{root:?}]
[notifications]
enabled = false
",
        ballast = data.join("ballast").display().to_string(),
        jsonl = data.join("activity.jsonl").display().to_string(),
        sqlite = data.join("activity.sqlite3").display().to_string(),
        state = data.join("state.json").display().to_string(),
        root = root.display().to_string(),
    );
    let path = dir.join("config.toml");
    fs::write(&path, config).unwrap();
    path
}

struct SandboxDaemon {
    child: Child,
    data_dir: PathBuf,
    stderr_path: PathBuf,
}

impl SandboxDaemon {
    fn spawn(dir: &Path, config: &Path) -> Self {
        let stderr_path = dir.join("daemon.stderr");
        let stderr = File::create(&stderr_path).unwrap();
        let child = Command::new(common::sbh_bin_path())
            .arg("--config")
            .arg(config)
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .env_remove("INVOCATION_ID")
            .env_remove("NOTIFY_SOCKET")
            .spawn()
            .expect("spawn sbh daemon");
        Self {
            child,
            data_dir: dir.join("data"),
            stderr_path,
        }
    }

    fn state(&self) -> Option<Value> {
        let raw = fs::read_to_string(self.data_dir.join("state.json")).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn events_of(&self, kind: &str) -> Vec<Value> {
        fs::read_to_string(self.data_dir.join("activity.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event.get("event").and_then(Value::as_str) == Some(kind))
            .collect()
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    /// Wait until `predicate` holds for the state file, failing fast when
    /// the daemon exits.
    fn wait_for(&mut self, what: &str, timeout: Duration, predicate: impl Fn(&Value) -> bool) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon") {
                panic!("daemon exited ({status}) before {what}:\n{}", self.stderr());
            }
            if self.state().is_some_and(|state| predicate(&state)) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; state = {:?}\n{}",
                self.state(),
                self.stderr()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop(mut self) {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.child.try_wait().expect("poll daemon").is_none() {
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.wait();
    }
}

/// The cockpit on a pty: the child's three standard streams are the slave
/// end; everything it draws lands in `output`.
struct PtyDashboard {
    child: Child,
    writer: File,
    output: Arc<Mutex<Vec<u8>>>,
}

impl PtyDashboard {
    fn spawn(config: &Path, args: &[&str]) -> Self {
        let mut command_line: Vec<OsString> =
            vec!["--config".into(), config.into(), "dashboard".into()];
        command_line.extend(args.iter().map(OsString::from));
        // The slave copy is dropped here: the reader sees EOF when sbh exits.
        Self::spawn_program(
            &common::sbh_bin_path(),
            &command_line,
            &[("SBH_OUTPUT_FORMAT", "human")],
        )
        .0
    }

    /// `program` with a fresh pty as its controlling terminal. Also returns a
    /// copy of the slave end, for reading the terminal settings afterwards.
    fn spawn_program(program: &Path, argv: &[OsString], envs: &[(&str, &str)]) -> (Self, OwnedFd) {
        let size = Winsize {
            ws_row: 32,
            ws_col: 110,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = openpty(Some(&size), None).expect("openpty");
        let slave: OwnedFd = pty.slave;
        let master: OwnedFd = pty.master;
        let kept = slave.try_clone().unwrap();
        // `setsid -c -w`: new session, stdin (the slave) becomes the
        // controlling terminal, and the wrapper exits with the program's
        // status. The spawned process is not a group leader, so setsid execs
        // in place: the child's pid is the program's.
        let child = Command::new("setsid")
            .args(["-c", "-w", "--"])
            .arg(program)
            .args(argv)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .env("TERM", "xterm-256color")
            .envs(envs.iter().copied())
            .env_remove("NO_COLOR")
            .spawn()
            .expect("spawn a program on a pty");
        let writer = File::from(master.try_clone().unwrap());
        let mut reader = File::from(master);
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                }
            }
        });
        (
            Self {
                child,
                writer,
                output,
            },
            kept,
        )
    }

    /// What the cockpit has drawn so far, escape sequences stripped.
    fn text(&self) -> String {
        self.text_from(0)
    }

    /// What the cockpit drew from byte offset `from` on.
    fn text_from(&self, from: usize) -> String {
        let bytes = self
            .output
            .lock()
            .unwrap()
            .get(from..)
            .unwrap_or_default()
            .to_vec();
        strip_escapes(&String::from_utf8_lossy(&bytes))
    }

    /// Send `keys`; returns the output offset before them, so a check can
    /// look only at what the press caused.
    fn press(&mut self, keys: &str) -> usize {
        let from = self.output.lock().unwrap().len();
        self.writer.write_all(keys.as_bytes()).unwrap();
        self.writer.flush().unwrap();
        thread::sleep(Duration::from_millis(350));
        from
    }

    /// Cursor addressing replaces the spaces between runs of text, so the
    /// comparison ignores whitespace on both sides.
    fn wait_for_text_from(&self, from: usize, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let squeezed = |text: &str| text.split_whitespace().collect::<String>();
        let wanted = squeezed(needle);
        while !squeezed(&self.text_from(from)).contains(&wanted) {
            assert!(
                Instant::now() < deadline,
                "cockpit never drew {needle:?} after offset {from}; output so far:\n{}",
                self.text()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait_exit(mut self, timeout: Duration) -> (std::process::ExitStatus, String) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll dashboard") {
                thread::sleep(Duration::from_millis(100));
                return (status, self.text());
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!(
                    "the program on the pty did not exit; output:\n{}",
                    self.text()
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Poll `sbh status --json` (which has the daemon write a fresh state)
/// until the pool reports `expected` available files.
fn wait_for_status_available(config: &Path, expected: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let output = Command::new(common::sbh_bin_path())
            .arg("--config")
            .arg(config)
            .args(["--json", "status"])
            .env_remove("SBH_TEST_MODE")
            .output()
            .expect("run sbh status");
        let last = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let available = serde_json::from_str::<Value>(&last)
            .ok()
            .and_then(|payload| payload["ballast"]["available_count"].as_u64());
        if available == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "pool never reached {expected} available file(s); last status:\n{last}"
        );
        thread::sleep(Duration::from_millis(250));
    }
}

/// Drop CSI/OSC sequences and control bytes so frame text can be searched.
fn strip_escapes(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.next() {
                Some('[') => {
                    // CSI: parameters and intermediates end at a final byte 0x40..=0x7e.
                    for next in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: ends at BEL or ST (ESC \).
                    let mut prev = '\0';
                    for next in chars.by_ref() {
                        if next == '\u{7}' || (prev == '\u{1b}' && next == '\\') {
                            break;
                        }
                        prev = next;
                    }
                }
                _ => {}
            }
            continue;
        }
        if c == '\n' || c == ' ' || !c.is_control() {
            out.push(c);
        }
    }
    out
}

/// One session, end to end: the cockpit opens on the Ballast screen, every
/// screen draws its header, quick-release plus Enter releases one ballast
/// file through the daemon (its event and pool count prove it), and `q`
/// exits cleanly.
#[test]
fn pty_session_walks_the_screens_and_releases_one_ballast_file() {
    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("SKIP: util-linux setsid is not installed; the pty session needs it");
        return;
    }
    let dir = scratch();
    let config = write_config(dir.path());
    let mut daemon = SandboxDaemon::spawn(dir.path(), &config);
    daemon.wait_for("a provisioned pool", Duration::from_secs(40), |state| {
        state["ballast"]["available"].as_u64() == Some(2)
    });
    assert!(
        daemon.events_of("ballast_release").is_empty(),
        "no release before the operator asks"
    );

    let mut cockpit =
        PtyDashboard::spawn(&config, &["--new-dashboard", "--start-screen", "ballast"]);
    // --start-screen ballast: the Ballast panes are the first thing drawn,
    // under the tab bar.
    cockpit.wait_for_text_from(0, "Volume Detail", Duration::from_secs(20));
    cockpit.wait_for_text_from(0, "7:Diagnostics", Duration::from_secs(10));

    // Every screen by number; each is recognised by a pane only it draws,
    // looked for in what was drawn after the key press.
    for (key, pane) in [
        ("2", "Events"),
        ("3", "Evidence"),
        ("4", "Score Breakdown"),
        ("6", "Log Entries"),
        ("7", "System Health"),
        ("1", "Pressure Matrix"),
        ("5", "Volume Detail"),
    ] {
        let from = cockpit.press(key);
        cockpit.wait_for_text_from(from, pane, Duration::from_secs(10));
    }
    // The VOI overlay shows the daemon's scheduler block (4.11).
    let from = cockpit.press("v");
    cockpit.wait_for_text_from(from, "VOI Scheduler", Duration::from_secs(10));
    cockpit.wait_for_text_from(from, "paths/cycle", Duration::from_secs(10));
    cockpit.wait_for_text_from(from, "last plan", Duration::from_secs(10));
    cockpit.press("\u{1b}");

    // Help opens and closes; the palette opens and closes.
    let from = cockpit.press("?");
    cockpit.wait_for_text_from(from, "Help", Duration::from_secs(10));
    cockpit.wait_for_text_from(from, "Navigation", Duration::from_secs(10));
    cockpit.press("\u{1b}");
    let from = cockpit.press(":");
    cockpit.wait_for_text_from(from, "Command Palette", Duration::from_secs(10));
    cockpit.press("\u{1b}");

    // Quick-release: x opens the confirmation on the selected volume, Enter
    // sends the release to the daemon over its control socket.
    let from = cockpit.press("x");
    cockpit.wait_for_text_from(from, "Confirmation Required", Duration::from_secs(10));
    let from = cockpit.press("\r");
    // The cockpit's own verdict first: it names the failure when the
    // release did not happen, which the daemon's state alone cannot.
    cockpit.wait_for_text_from(from, "ballast", Duration::from_secs(10));
    thread::sleep(Duration::from_millis(500));
    let verdict = cockpit.text_from(from);
    let squeezed = |text: &str| text.split_whitespace().collect::<String>();
    assert!(
        squeezed(&verdict).contains(&squeezed("released 1 ballast file(s) on")),
        "the release did not succeed; cockpit said:\n{verdict}\n--- daemon stderr:\n{}",
        daemon.stderr()
    );
    assert!(
        !squeezed(&verdict).contains("directly"),
        "the release must go through the running daemon, not the direct route; cockpit said:\n{verdict}"
    );
    // `sbh status` asks the daemon for a fresh state write, so its pool
    // count is current rather than whatever the periodic write last saw.
    wait_for_status_available(&config, 1, Duration::from_secs(20));

    // Log Search (4.10): the release the daemon just logged is findable —
    // `/`, a typed query, Enter — and the query line shows what was typed.
    let from = cockpit.press("6");
    cockpit.wait_for_text_from(from, "Log Entries", Duration::from_secs(10));
    cockpit.press("/");
    let from = cockpit.press("type:ballast_release");
    cockpit.wait_for_text_from(from, "type:ballast_release", Duration::from_secs(10));
    let from = cockpit.press("\r");
    cockpit.wait_for_text_from(from, "type=ballast_release", Duration::from_secs(10));
    // Exactly the one release the daemon logged is on the page.
    cockpit.wait_for_text_from(from, "page 1 (1 entries)", Duration::from_secs(10));

    cockpit.press("q");
    let (status, text) = cockpit.wait_exit(Duration::from_secs(20));
    assert!(status.success(), "dashboard exit {status}; output:\n{text}");
    assert!(
        !text.contains("TUI feature not enabled") && !text.contains("not a TTY"),
        "{text}"
    );

    let releases = daemon.events_of("ballast_release");
    assert_eq!(releases.len(), 1, "one release event: {releases:?}");
    assert_eq!(
        releases[0]["pressure"].as_str(),
        Some("control"),
        "an operator release says so: {}",
        releases[0]
    );
    let released_path = releases[0]["path"].as_str().unwrap_or_default();
    assert!(
        released_path.starts_with(dir.path().join("data/ballast").to_str().unwrap()),
        "the released file is one of the sandbox pool's: {released_path}"
    );
    assert!(
        !Path::new(released_path).exists(),
        "the released file is gone from disk"
    );

    daemon.stop();
}

/// Incident replay (4.13): a captured activity log drives the cockpit
/// with no daemon at all. At max speed the cursor lands on the last event
/// at once, the Timeline shows the log's events, `,` steps back (and
/// pauses), and `q` exits.
#[test]
fn pty_replay_session_drives_the_cockpit_from_a_captured_log() {
    use storage_ballast_helper::logger::jsonl::{EventType, LogEntry, Severity};

    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("SKIP: util-linux setsid is not installed; the pty session needs it");
        return;
    }
    let dir = scratch();
    let config = write_config(dir.path());
    let log = dir.path().join("captured.jsonl");
    let mut lines = String::new();
    for (i, event) in [
        EventType::BallastProvision,
        EventType::ScanComplete,
        EventType::BallastRelease,
        EventType::ArtifactDelete,
    ]
    .into_iter()
    .enumerate()
    {
        let mut entry = LogEntry::new(event, Severity::Info);
        entry.ts = format!("2026-08-30T10:00:0{i}Z");
        entry.mount_point = Some("/data".to_string());
        entry.pressure = Some(if i >= 2 { "orange" } else { "green" }.to_string());
        entry.free_pct = Some(if i >= 2 { 12.0 } else { 40.0 });
        entry.path = Some(format!("/work/proj{i}/target"));
        lines.push_str(&serde_json::to_string(&entry).unwrap());
        lines.push('\n');
    }
    lines.push_str("this line is not json\n");
    fs::write(&log, lines).unwrap();

    let mut replay = PtyDashboard::spawn(
        &config,
        &[
            "--replay",
            log.to_str().unwrap(),
            "--speed",
            "max",
            "--start-screen",
            "timeline",
        ],
    );
    replay.wait_for_text_from(0, "REPLAY captured.jsonl", Duration::from_secs(20));
    replay.wait_for_text_from(0, "4/4 max", Duration::from_secs(10));
    replay.wait_for_text_from(0, "ballast_release", Duration::from_secs(10));
    // The frame is drawn as a diff, so only the cells that changed arrive:
    // the "paused" suffix is new text, the cursor count changes one digit.
    let from = replay.press(",");
    replay.wait_for_text_from(from, "paused", Duration::from_secs(10));
    replay.press("q");
    let (status, text) = replay.wait_exit(Duration::from_secs(20));
    assert!(status.success(), "replay exit {status}; output:\n{text}");
    assert!(
        text.contains("unparseable line") || text.contains("1 unparseable"),
        "the skipped line is reported: {text}"
    );
}

/// An explicit cockpit request without a terminal is refused with the TTY
/// message (the e2e shell suite covers the same on a pipe; here it guards
/// the pty test's premise that the pty is what makes the difference).
#[test]
fn without_a_pty_the_explicit_cockpit_is_refused() {
    let dir = scratch();
    let config = write_config(dir.path());
    let output = Command::new(common::sbh_bin_path())
        .arg("--config")
        .arg(&config)
        .args(["dashboard", "--new-dashboard"])
        .env("SBH_OUTPUT_FORMAT", "human")
        .stdin(Stdio::null())
        .output()
        .expect("run sbh dashboard on a pipe");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("stdout is not a TTY"), "{stderr}");
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

const LEAVE_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049l";

/// A SIGTERM from another process ends the cockpit inside ftui-tty's 2 s
/// grace: the loop sees it, stops drawing on the screen ftui-tty restored,
/// tears down and exits with 128 + 15. Before, the loop drew on until
/// ftui-tty gave up waiting and exited the process itself, 2 s later.
#[test]
fn pty_sigterm_ends_the_cockpit_promptly_without_drawing_on_the_shell() {
    use storage_ballast_helper::logger::jsonl::{EventType, LogEntry, Severity};

    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("SKIP: util-linux setsid is not installed; the pty session needs it");
        return;
    }
    let dir = scratch();
    let config = write_config(dir.path());
    let log = dir.path().join("captured.jsonl");
    let mut lines = String::new();
    for (i, event) in [EventType::BallastProvision, EventType::ScanComplete]
        .into_iter()
        .enumerate()
    {
        let mut entry = LogEntry::new(event, Severity::Info);
        entry.ts = format!("2026-08-30T10:00:0{i}Z");
        lines.push_str(&serde_json::to_string(&entry).unwrap());
        lines.push('\n');
    }
    fs::write(&log, lines).unwrap();

    let replay = PtyDashboard::spawn(
        &config,
        &["--replay", log.to_str().unwrap(), "--speed", "max"],
    );
    replay.wait_for_text_from(0, "REPLAY captured.jsonl", Duration::from_secs(20));
    let output = Arc::clone(&replay.output);
    let sent = Instant::now();
    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(replay.child.id().to_string())
            .status()
            .unwrap()
            .success()
    );
    let (status, text) = replay.wait_exit(Duration::from_secs(10));
    let elapsed = sent.elapsed();
    assert_eq!(status.code(), Some(128 + 15), "{text}");
    assert!(
        elapsed < Duration::from_millis(1800),
        "exit took {elapsed:?}: that is ftui-tty's own exit after its 2 s grace, not the loop's"
    );
    let bytes = output.lock().unwrap().clone();
    let last_leave = bytes
        .windows(LEAVE_ALTERNATE_SCREEN.len())
        .rposition(|window| window == LEAVE_ALTERNATE_SCREEN)
        .expect("the alternate screen was left");
    let after = strip_escapes(&String::from_utf8_lossy(&bytes[last_leave..]));
    assert!(
        after.trim().is_empty(),
        "drawn on the restored screen: {after:?}"
    );
}

/// The child half of `a_panic_restores_the_terminal_before_its_message`:
/// it does nothing unless that test runs it on a pty.
#[test]
#[ignore = "the child process of a_panic_restores_the_terminal_before_its_message"]
fn guard_panic_child() {
    use ftui_backend::BackendFeatures;
    use ftui_tty::TtySessionOptions;
    use storage_ballast_helper::tui::terminal_guard::TerminalGuard;

    if std::env::var_os("SBH_GUARD_PANIC_CHILD").is_none() {
        return;
    }
    let _guard = TerminalGuard::open(TtySessionOptions {
        alternate_screen: true,
        intercept_signals: true,
        features: BackendFeatures {
            mouse_capture: true,
            ..BackendFeatures::default()
        },
    })
    .expect("the pty is this process's terminal");
    panic!("guard-probe");
}

/// A panic while the cockpit owns the terminal, in a build where panics
/// unwind (debug and test builds; release builds abort, and ftui-tty's own
/// hook covers them): the terminal is restored before the message is
/// printed, so the message stays on the normal screen, nothing leaves the
/// alternate screen again after it (which would move the cursor back over
/// it), and the terminal settings are back to cooked mode.
#[test]
fn a_panic_restores_the_terminal_before_its_message() {
    use nix::sys::termios::{LocalFlags, tcgetattr};

    if Command::new("setsid").arg("--version").output().is_err() {
        eprintln!("SKIP: util-linux setsid is not installed; the pty session needs it");
        return;
    }
    let argv: Vec<OsString> = [
        "guard_panic_child",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let (child, slave) = PtyDashboard::spawn_program(
        &std::env::current_exe().unwrap(),
        &argv,
        &[("SBH_GUARD_PANIC_CHILD", "1")],
    );
    let cooked = LocalFlags::ECHO | LocalFlags::ICANON;
    assert!(tcgetattr(&slave).unwrap().local_flags.contains(cooked));
    let output = Arc::clone(&child.output);
    let (status, text) = child.wait_exit(Duration::from_secs(60));
    let bytes = output.lock().unwrap().clone();

    let probe = find(&bytes, b"guard-probe")
        .unwrap_or_else(|| panic!("no panic message on the terminal:\n{text}"));
    let leave = find(&bytes, LEAVE_ALTERNATE_SCREEN).expect("the alternate screen was left");
    assert!(
        leave < probe,
        "the message was printed on the alternate screen:\n{text}"
    );
    assert_eq!(
        find(&bytes[probe..], LEAVE_ALTERNATE_SCREEN),
        None,
        "the alternate screen was left again after the message"
    );
    assert!(
        !text.contains("panicked while processing panic")
            && !text.contains("panic in a destructor"),
        "{text}"
    );
    // libtest reports the panicking test as failed (101); an abort while
    // unwinding would end the process by SIGABRT instead.
    assert_eq!(status.code(), Some(101), "{text}");
    let flags = tcgetattr(&slave).unwrap().local_flags;
    assert!(
        flags.contains(cooked),
        "the terminal was left raw: {flags:?}"
    );
}
