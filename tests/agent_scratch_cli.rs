//! Exercise the shipped command's read-only report and uncertainty contract.
//! Fixtures supply their own config and transcript roots; no daemon is started.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

const SESSION_ID: &str = "11111111-1111-4111-8111-111111111111";
const PROJECT: &str = "-data-agent-project";

struct Fixture {
    directory: tempfile::TempDir,
    config: PathBuf,
    scratch: PathBuf,
    session: PathBuf,
    transcripts: PathBuf,
    transcript: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let scratch = directory.path().join("scratch");
        let session = scratch
            .join(format!("claude-{}", nix::unistd::geteuid().as_raw()))
            .join(PROJECT)
            .join(SESSION_ID);
        let transcripts = directory.path().join("transcripts");
        let transcript = transcripts
            .join(PROJECT)
            .join(format!("{SESSION_ID}.jsonl"));
        fs::create_dir_all(&session).unwrap();
        fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        fs::write(session.join("work.bin"), [42_u8; 8192]).unwrap();
        fs::hard_link(session.join("work.bin"), session.join("same-data")).unwrap();
        fs::write(session.parent().unwrap().join(".sbh-protect"), b"").unwrap();
        fs::write(&transcript, b"{\"type\":\"fixture\"}\n").unwrap();

        // This different configured root must not broaden an explicit PATH.
        let configured_root = directory.path().join("configured");
        fs::create_dir_all(
            configured_root
                .join("claude-1234")
                .join(PROJECT)
                .join(SESSION_ID),
        )
        .unwrap();
        let config = directory.path().join("sbh.toml");
        fs::write(
            &config,
            format!(
                "[scanner]\nroot_paths = [{}]\n",
                serde_json::to_string(&configured_root).unwrap()
            ),
        )
        .unwrap();
        Self {
            directory,
            config,
            scratch,
            session,
            transcripts,
            transcript,
        }
    }

    fn run(&self, extra: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sbh"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SBH_") {
                command.env_remove(key);
            }
        }
        command
            .env("HOME", self.directory.path())
            .env("XDG_CONFIG_HOME", self.directory.path().join("config"))
            .env("XDG_DATA_HOME", self.directory.path().join("data"))
            .env("XDG_STATE_HOME", self.directory.path().join("state"))
            .arg("--config")
            .arg(&self.config)
            .args(["check", "--agent-scratch"])
            .arg(&self.scratch)
            .arg("--transcript-root")
            .arg(&self.transcripts)
            .args(["--json", "--agent-scratch-timeout-secs", "5"])
            .args(extra)
            .output()
            .expect("run agent scratch report")
    }

    fn assert_unchanged(&self) {
        assert_eq!(
            fs::read(self.session.join("work.bin")).unwrap(),
            [42_u8; 8192]
        );
        assert_eq!(
            fs::read(self.session.join("same-data")).unwrap(),
            [42_u8; 8192]
        );
        assert!(self.session.parent().unwrap().join(".sbh-protect").exists());
        assert_eq!(
            fs::read(&self.transcript).unwrap(),
            b"{\"type\":\"fixture\"}\n"
        );
        for directory in ["config", "data", "state"] {
            assert!(
                !self.directory.path().join(directory).exists(),
                "read-only command created {directory} state"
            );
        }
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "single JSON report required ({error}); stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn explicit_root_reports_protected_sessions_without_writing_state_or_payloads() {
    let fixture = Fixture::new();
    let output = fixture.run(&[]);
    // Process visibility depends on host permissions; incomplete evidence must
    // remain useful without turning fresh sessions into idle ones.
    assert!(matches!(output.status.code(), Some(0 | 4)), "{output:?}");
    let report = json(&output);
    assert_eq!(report["schema"], "sbh.agent_scratch.v1");
    assert_eq!(report["read_only"], true);
    assert_eq!(report["exit_code"], output.status.code().unwrap());
    assert_eq!(report["sessions_found"], 1);
    assert_eq!(report["idle_sessions"], 0);
    let session = &report["sessions"][0];
    assert_eq!(
        session["path"],
        serde_json::json!(fixture.session.canonicalize().unwrap())
    );
    assert_eq!(session["session_id"], SESSION_ID);
    assert_eq!(session["observed_logical_bytes"], 8192);
    assert!(session["observed_allocated_bytes"].is_u64());
    assert!(!session["native_path_hex"].as_str().unwrap().is_empty());
    assert!(session["reclaimable_bytes"].is_null());
    assert!(!session["protections"].as_array().unwrap().is_empty());
    assert_ne!(session["state"], "idle");
    fixture.assert_unchanged();
}

#[test]
fn exhausted_budget_and_invalid_limits_have_explicit_json_exit_statuses() {
    let fixture = Fixture::new();
    let output = fixture.run(&["--agent-scratch-max-entries", "1"]);
    let report = json(&output);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(report["exit_code"], 4);
    assert_eq!(report["complete"], false);
    assert_eq!(report["idle_sessions"], 0);
    assert!(!report["issues"].as_array().unwrap().is_empty());

    let output = fixture.run(&["--agent-scratch-top", "0"]);
    let report = json(&output);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["exit_code"], 1);
    assert_eq!(report["read_only"], true);
    assert_eq!(report["complete"], false);
    assert!(report["error"].as_str().unwrap().contains("top 1..2048"));
    fixture.assert_unchanged();
}
