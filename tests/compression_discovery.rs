//! Exercise the real read-only CLI, not a separate model of its selection logic.

#![cfg(all(
    feature = "cli",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs;
use std::path::Path;
use std::process::Command;

fn cold(path: &Path) {
    fs::write(path, b"preserve this payload").unwrap();
    filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(1, 0)).unwrap();
}

fn command(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sbh"));
    command.arg("--config").arg(config).args([
        "--json",
        "compress",
        "--discover",
        "--min-size-bytes",
        "1",
        "--min-age-secs",
        "3600",
    ]);
    command
}

#[test]
fn discover_preserves_inputs_and_creates_no_journal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    fs::create_dir(&root).unwrap();
    let path = root.join("cold.bin");
    cold(&path);
    let config = temp.path().join("config.toml");
    fs::write(
        &config,
        format!(
            "[paths]\nstate_file = {:?}\n",
            temp.path().join("state.json")
        ),
    )
    .unwrap();
    let output = command(&config).arg("--").arg(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sbh.compression.discovery.v1");
    assert_eq!(report["read_only"], true);
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["discovery"]["complete"], true);
    assert_eq!(report["discovery"]["selected_files"], 1);
    assert_eq!(fs::read(&path).unwrap(), b"preserve this payload");
    assert!(!temp.path().join("compression-journal").exists());
    assert!(!temp.path().join("state.json").exists());
}

#[test]
fn a_partial_discovery_has_exit_four_and_no_invented_complete_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    fs::create_dir(&root).unwrap();
    cold(&root.join("a.bin"));
    cold(&root.join("b.bin"));
    let config = temp.path().join("config.toml");
    fs::write(&config, "").unwrap();
    let output = command(&config)
        .args(["--max-entries", "1", "--"])
        .arg(&root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["exit_code"], 4);
    assert_eq!(report["discovery"]["complete"], false);
    assert_eq!(report["discovery"]["entries_examined"], 1);
    assert!(report["candidates"].as_array().unwrap().is_empty());
    assert!(report["discovery"]["resume_after_hex"].is_null());
    assert_eq!(
        fs::read(root.join("a.bin")).unwrap(),
        b"preserve this payload"
    );
    assert_eq!(
        fs::read(root.join("b.bin")).unwrap(),
        b"preserve this payload"
    );
}
