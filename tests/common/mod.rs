use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CmdResult {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub log_path: PathBuf,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn resolve_bin_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_sbh") {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    let exe_name = if cfg!(windows) { "sbh.exe" } else { "sbh" };
    let fallback = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .and_then(|deps| deps.parent().map(PathBuf::from))
        .map(|debug_dir| debug_dir.join(exe_name));

    match fallback {
        Some(path) if path.exists() => path,
        _ => panic!(
            "unable to resolve sbh binary path for integration test (checked CARGO_BIN_EXE_sbh and debug sibling path)"
        ),
    }
}

pub fn run_cli_case(case_name: &str, args: &[&str]) -> CmdResult {
    let root = std::env::temp_dir().join("sbh-test-logs");
    fs::create_dir_all(&root).expect("create temp test log dir");

    let log_path = root.join(format!("{}-{}.log", sanitize(case_name), now_millis()));
    let bin_path = resolve_bin_path();

    let output = Command::new(&bin_path)
        .args(args)
        .env("SBH_TEST_VERBOSE", "1")
        .env("SBH_OUTPUT_FORMAT", "human")
        .env("RUST_BACKTRACE", "1")
        .output()
        .expect("execute sbh command");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let mut log_content = String::new();
    log_content.push_str(&format!("case={case_name}\n"));
    log_content.push_str(&format!("bin={}\n", bin_path.display()));
    log_content.push_str(&format!("args={args:?}\n"));
    log_content.push_str(&format!("status={}\n", output.status));
    log_content.push_str("----- stdout -----\n");
    log_content.push_str(&stdout);
    log_content.push('\n');
    log_content.push_str("----- stderr -----\n");
    log_content.push_str(&stderr);
    log_content.push('\n');
    fs::write(&log_path, log_content).expect("write test log");

    CmdResult {
        status: output.status,
        stdout,
        stderr,
        log_path,
    }
}
