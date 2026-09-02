//! C-EVENT: the activity log line contract.
//!
//! Every JSONL line the daemon writes carries `ts`, `event`, `severity`,
//! `schema_version` and `run_id`; each event type has a typed payload
//! (see [`validate_value`]). Lines without `schema_version` are the v1
//! lines written before 0.5.2 and stay readable: `stats`, `explain` and the
//! dashboard must keep working on the fleet hosts' old logs, so v1 lines
//! validate against the v1 rules (no `run_id`, same payloads).
//!
//! `error` is reserved for failures of sbh itself; conditions worth acting
//! on that are not failures are `info` lines with `warning` severity.

use serde_json::Value;

/// Version stamped on every line the current writer produces.
pub const SCHEMA_VERSION: u32 = 2;

/// Event types the contract knows, as they appear in `event`.
pub const EVENT_TYPES: &[&str] = &[
    "artifact_delete",
    "ballast_release",
    "ballast_replenish",
    "ballast_provision",
    "pressure_change",
    "scan_complete",
    "daemon_start",
    "daemon_stop",
    "config_reload",
    "policy_transition",
    "info",
    "error",
    "emergency",
    "decision",
];

/// Severities the contract allows.
pub const SEVERITIES: &[&str] = &["debug", "info", "warning", "critical"];

/// What a whole log validated to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JsonlReport {
    /// Non-empty lines seen.
    pub lines: usize,
    /// Lines without `schema_version` (pre-0.5.2 writers).
    pub v1_lines: usize,
    /// Lines at the current schema version.
    pub v2_lines: usize,
}

/// Validate one JSONL line; returns the schema version it satisfies.
pub fn validate_line(line: &str) -> Result<u32, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("not a JSON object: {e}"))?;
    validate_value(&value)
}

/// Validate one parsed line; returns the schema version it satisfies.
pub fn validate_value(value: &Value) -> Result<u32, String> {
    let object = value.as_object().ok_or("line is not a JSON object")?;
    let string = |key: &str| -> Result<&str, String> {
        object
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("missing or empty `{key}`"))
    };

    let ts = string("ts")?;
    if !looks_like_utc_timestamp(ts) {
        return Err(format!("`ts` is not an RFC 3339 UTC timestamp: {ts}"));
    }
    let event = string("event")?;
    if !EVENT_TYPES.contains(&event) {
        return Err(format!("unknown event type `{event}`"));
    }
    let severity = string("severity")?;
    if !SEVERITIES.contains(&severity) {
        return Err(format!("unknown severity `{severity}`"));
    }

    let version = match object.get("schema_version") {
        None => 1,
        Some(Value::Number(n)) if n.as_u64() == Some(u64::from(SCHEMA_VERSION)) => {
            string("run_id")?;
            SCHEMA_VERSION
        }
        Some(other) => return Err(format!("unsupported schema_version {other}")),
    };

    let has = |key: &str| object.get(key).is_some_and(|v| !v.is_null());
    let require = |key: &str| -> Result<(), String> {
        if has(key) {
            Ok(())
        } else {
            Err(format!("`{event}` line without `{key}`"))
        }
    };
    match event {
        "artifact_delete" => {
            require("path")?;
            require("ok")?;
            if object.get("ok") == Some(&Value::Bool(false)) {
                require("error_code")?;
            }
        }
        "ballast_release" | "ballast_replenish" | "ballast_provision" => {
            require("path")?;
            require("size")?;
        }
        "pressure_change" => {
            require("pressure")?;
            require("free_pct")?;
        }
        "scan_complete" => require("duration_ms")?,
        "decision" => {
            require("decision_id")?;
            require("path")?;
            require("details")?;
        }
        "error" => require("error_code")?,
        "emergency" => require("free_pct")?,
        "daemon_start" | "daemon_stop" | "config_reload" | "policy_transition" => {
            require("details")?;
        }
        _ => {}
    }
    Ok(version)
}

/// Validate a whole JSONL text. Blank lines are skipped. Returns the line
/// numbers (1-based) and reasons of every invalid line.
pub fn validate_jsonl(text: &str) -> Result<JsonlReport, Vec<(usize, String)>> {
    let mut report = JsonlReport::default();
    let mut errors = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        report.lines += 1;
        match validate_line(line) {
            Ok(1) => report.v1_lines += 1,
            Ok(_) => report.v2_lines += 1,
            Err(reason) => errors.push((index + 1, reason)),
        }
    }
    if errors.is_empty() {
        Ok(report)
    } else {
        Err(errors)
    }
}

/// `2026-09-02T12:34:56.789Z` or without fraction; nothing else.
fn looks_like_utc_timestamp(ts: &str) -> bool {
    let bytes = ts.as_bytes();
    if bytes.len() < 20 || !ts.ends_with('Z') {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    digits(0..4)
        && bytes[4] == b'-'
        && digits(5..7)
        && bytes[7] == b'-'
        && digits(8..10)
        && bytes[10] == b'T'
        && digits(11..13)
        && bytes[13] == b':'
        && digits(14..16)
        && bytes[16] == b':'
        && digits(17..19)
        && (bytes.len() == 20 || bytes[19] == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2_DELETE: &str = r#"{"ts":"2026-09-02T12:00:00.000Z","event":"artifact_delete","severity":"info","schema_version":2,"run_id":"1a2b-3c4d","path":"/data/p/target","size":1024,"ok":true,"decision_id":"d-1"}"#;
    const V1_DELETE: &str = r#"{"ts":"2026-08-18T09:15:02.417Z","event":"artifact_delete","severity":"info","path":"/data/p/target","size":1024,"ok":true}"#;

    #[test]
    fn a_current_line_validates_at_v2_and_an_old_line_at_v1() {
        assert_eq!(validate_line(V2_DELETE), Ok(2));
        assert_eq!(validate_line(V1_DELETE), Ok(1));
    }

    #[test]
    fn a_v2_line_without_run_id_fails() {
        let line = V2_DELETE.replace(r#","run_id":"1a2b-3c4d""#, "");
        let err = validate_line(&line).unwrap_err();
        assert!(err.contains("run_id"), "{err}");
    }

    #[test]
    fn unknown_events_severities_and_versions_fail() {
        let bad_event = V2_DELETE.replace("artifact_delete", "artifact_deleet");
        assert!(
            validate_line(&bad_event)
                .unwrap_err()
                .contains("unknown event")
        );
        let bad_severity = V2_DELETE.replace(r#""severity":"info""#, r#""severity":"notice""#);
        assert!(
            validate_line(&bad_severity)
                .unwrap_err()
                .contains("unknown severity")
        );
        let bad_version = V2_DELETE.replace(r#""schema_version":2"#, r#""schema_version":3"#);
        assert!(
            validate_line(&bad_version)
                .unwrap_err()
                .contains("unsupported schema_version")
        );
        assert!(validate_line("not json").is_err());
        assert!(validate_line("[1,2]").is_err());
    }

    #[test]
    fn payloads_are_checked_per_event() {
        let no_path = V2_DELETE.replace(r#""path":"/data/p/target","#, "");
        assert!(validate_line(&no_path).unwrap_err().contains("`path`"));
        let failed_without_code = V2_DELETE.replace(r#""ok":true"#, r#""ok":false"#);
        assert!(
            validate_line(&failed_without_code)
                .unwrap_err()
                .contains("error_code")
        );
        let error_line = r#"{"ts":"2026-09-02T12:00:00Z","event":"error","severity":"critical","schema_version":2,"run_id":"r","error_code":"SBH-2004","error_message":"refused writes"}"#;
        assert_eq!(validate_line(error_line), Ok(2));
        let ballast = r#"{"ts":"2026-09-02T12:00:00Z","event":"ballast_release","severity":"info","schema_version":2,"run_id":"r","path":"/x/SBH_BALLAST_FILE_00001.dat","size":1048576,"pressure":"red","free_pct":4.0,"ok":true}"#;
        assert_eq!(validate_line(ballast), Ok(2));
        let policy = r#"{"ts":"2026-09-02T12:00:00Z","event":"policy_transition","severity":"info","schema_version":2,"run_id":"r","details":"promote: canary -> enforce"}"#;
        assert_eq!(validate_line(policy), Ok(2));
        let decision_without_id = r#"{"ts":"2026-09-02T12:00:00Z","event":"decision","severity":"info","schema_version":2,"run_id":"r","path":"/p","details":"{}"}"#;
        assert!(
            validate_line(decision_without_id)
                .unwrap_err()
                .contains("decision_id")
        );
    }

    /// Lines as a v0.5.1 daemon wrote them on the fleet: no schema version,
    /// no run id, the same payload keys.
    #[test]
    fn a_v051_log_validates_as_v1() {
        let fixture = "\
{\"ts\":\"2026-08-18T09:15:00.001Z\",\"event\":\"daemon_start\",\"severity\":\"info\",\"details\":\"version=0.5.1 config_hash=abc\"}
{\"ts\":\"2026-08-18T09:15:01.100Z\",\"event\":\"pressure_change\",\"severity\":\"info\",\"pressure\":\"orange\",\"free_pct\":11.4,\"mount_point\":\"/\",\"details\":\"green -> orange\"}
{\"ts\":\"2026-08-18T09:15:02.417Z\",\"event\":\"scan_complete\",\"severity\":\"info\",\"duration_ms\":812,\"details\":\"paths_scanned=17 candidates=0 engine=v2\"}

{\"ts\":\"2026-08-18T09:15:03.000Z\",\"event\":\"artifact_delete\",\"severity\":\"warning\",\"path\":\"/data/p/target\",\"ok\":false,\"error_code\":\"SBH-2003\",\"error_message\":\"safety veto\"}
{\"ts\":\"2026-08-18T09:15:04.000Z\",\"event\":\"error\",\"severity\":\"critical\",\"error_code\":\"SBH-2001\",\"error_message\":\"pressure check failed\"}
";
        let report = validate_jsonl(fixture).unwrap();
        assert_eq!(
            report,
            JsonlReport {
                lines: 5,
                v1_lines: 5,
                v2_lines: 0
            }
        );
    }

    #[test]
    fn a_whole_log_reports_every_bad_line_with_its_number() {
        let text = format!("{V2_DELETE}\n{{\"ts\":\"nope\"}}\n{V1_DELETE}\n");
        let errors = validate_jsonl(&text).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, 2);
        assert!(errors[0].1.contains("ts"), "{}", errors[0].1);
    }
}
