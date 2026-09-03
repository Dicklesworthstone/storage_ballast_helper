//! Fuzz harness bodies for the parsers that face untrusted or
//! operator-authored input (W0, G7.6).
//!
//! `fuzz/fuzz_targets/*` call these under libFuzzer (`cargo fuzz run
//! <target>`), and `tests/fuzz_smoke.rs` runs the same functions over the
//! seed corpora and deterministic mutations on every test run, so the
//! invariants hold even where libFuzzer is not available. Every function
//! must return for any input without panicking; when a parse succeeds, the
//! value must serialize and parse back to itself (or validate), and the
//! consumers that render it must not panic either.

use crate::core::config::Config;
use crate::daemon::control::{ControlCommand, ControlRequest, ControlResponse};
use crate::daemon::metrics;
use crate::daemon::self_monitor::DaemonState;
use crate::logger::jsonl::{EventType, LogEntry};
use crate::logger::schema::validate_line;
use crate::scanner::decision_record::{DecisionRecord, ExplainLevel, format_explain};
use crate::scanner::protection::ProtectionMetadata;

/// The seven harness names, in the order the fuzz crate declares them.
pub const TARGETS: [&str; 7] = [
    "config_parse",
    "jsonl_reader",
    "checksum_parsers",
    "provenance_manifest",
    "control_protocol",
    "protect_marker",
    "state_json",
];

/// Run the harness called `name` (for the smoke test and `--stage fuzz`).
pub fn run(name: &str, data: &[u8]) {
    match name {
        "config_parse" => config_parse(data),
        "jsonl_reader" => jsonl_reader(data),
        "checksum_parsers" => checksum_parsers(data),
        "provenance_manifest" => provenance_manifest(data),
        "control_protocol" => control_protocol(data),
        "protect_marker" => protect_marker(data),
        "state_json" => state_json(data),
        other => panic!("unknown fuzz target {other}"),
    }
}

/// Operator-authored `config.toml`: the lenient parser never panics, a
/// parsed config validates without panicking, and its serialization parses
/// back with no unknown keys.
pub fn config_parse(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok((config, _unknown)) = Config::parse_toml(text) else {
        return;
    };
    let _ = config.validate();
    let Ok(rendered) = toml::to_string(&config) else {
        return;
    };
    match Config::parse_toml(&rendered) {
        Ok((_again, unknown)) => assert!(
            unknown.is_empty(),
            "serialized config reported unknown keys: {unknown:?}"
        ),
        Err(error) => panic!("serialized config does not parse back: {error}\n{rendered}"),
    }
}

/// The JSONL activity log as `sbh explain`, the dashboard and replay read it.
///
/// The C-EVENT validator and the entry parser never panic, an entry
/// round-trips, and an embedded decision record explains at every level.
pub fn jsonl_reader(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for line in text.lines() {
        let _ = validate_line(line);
        let Ok(entry) = serde_json::from_str::<LogEntry>(line) else {
            continue;
        };
        let rendered = serde_json::to_string(&entry).expect("a parsed entry serializes");
        serde_json::from_str::<LogEntry>(&rendered).expect("a serialized entry parses back");
        if entry.event == EventType::Decision
            && let Some(details) = &entry.details
            && let Ok(record) = serde_json::from_str::<DecisionRecord>(details)
        {
            for level in [
                ExplainLevel::L0,
                ExplainLevel::L1,
                ExplainLevel::L2,
                ExplainLevel::L3,
            ] {
                let _ = format_explain(&record, level);
                let _ = record.to_json_at_level(level);
            }
            let _ = record.to_json_compact();
        }
    }
}

/// `SHA256SUMS` in GNU, GNU binary-mode and BSD forms: the lookup never
/// panics and only ever returns a lowercase 64-hex digest.
pub fn checksum_parsers(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut names: Vec<&str> = text
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|name| name.trim_start_matches('*'))
        .collect();
    names.push("sbh-linux-amd64");
    for name in names {
        #[cfg(feature = "cli")]
        if let Some(hex) = crate::cli::sha256_from_manifest(text, name) {
            assert_eq!(hex.len(), 64, "digest length for {name}: {hex}");
            assert!(
                hex.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "digest for {name} is not lowercase hex: {hex}"
            );
        }
        #[cfg(not(feature = "cli"))]
        let _ = name;
    }
}

/// The network-sourced asset manifest: parsing never panics and a parsed
/// manifest round-trips exactly.
pub fn provenance_manifest(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    #[cfg(feature = "cli")]
    {
        use crate::cli::assets::AssetManifest;
        let Ok(manifest) = AssetManifest::from_json(text) else {
            return;
        };
        let rendered = serde_json::to_string(&manifest).expect("a parsed manifest serializes");
        let again = AssetManifest::from_json(&rendered).expect("a serialized manifest parses back");
        assert_eq!(again, manifest, "manifest round-trip changed the value");
    }
    #[cfg(not(feature = "cli"))]
    let _ = text;
}

/// The control-socket protocol (local but privileged): request lines never
/// panic the parser or the command decoder, and response lines round-trip.
pub fn control_protocol(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for line in text.lines() {
        if let Ok(request) = serde_json::from_str::<ControlRequest>(line) {
            let _ = ControlCommand::parse(&request);
        }
        if let Ok(response) = serde_json::from_str::<ControlResponse>(line) {
            let rendered = serde_json::to_string(&response).expect("a parsed response serializes");
            serde_json::from_str::<ControlResponse>(&rendered)
                .expect("a serialized response parses back");
        }
    }
}

/// `.sbh-protect` marker metadata: parsing never panics and a parsed
/// marker round-trips exactly (the `protected_by` alias included).
pub fn protect_marker(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(metadata) = toml::from_str::<ProtectionMetadata>(text) else {
        return;
    };
    let Ok(rendered) = toml::to_string(&metadata) else {
        return;
    };
    let again: ProtectionMetadata =
        toml::from_str(&rendered).expect("a serialized marker parses back");
    assert_eq!(again, metadata, "marker round-trip changed the value");
}

/// `state.json` across versions: parsing never panics, a parsed state
/// round-trips to a stable form, and the Prometheus rendering of any state
/// is a valid exposition.
pub fn state_json(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(state) = serde_json::from_str::<DaemonState>(text) else {
        return;
    };
    // JSON has no non-finite numbers: `1e999` parses as infinity and
    // serializes as `null`, so the first round-trip may normalise the value
    // (a fuzz finding, seed `non_finite_floats.json`). The invariant is that
    // the normalised form is stable: a second round-trip changes nothing.
    let rendered = serde_json::to_string(&state).expect("a parsed state serializes");
    let again: DaemonState =
        serde_json::from_str(&rendered).expect("a serialized state parses back");
    let rendered_again = serde_json::to_string(&again).expect("a re-parsed state serializes");
    assert_eq!(
        rendered_again, rendered,
        "state round-trip is not idempotent after one normalisation"
    );
    let exposition = metrics::render(&state, "fuzz");
    if let Err(problem) = metrics::validate_exposition(&exposition) {
        panic!("metrics rendered from a parsed state are invalid: {problem}\n{exposition}");
    }
}
