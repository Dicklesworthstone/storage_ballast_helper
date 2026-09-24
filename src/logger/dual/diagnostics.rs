//! Producer-side bounds for repetitive operational diagnostics.
//!
//! Audit events never enter this limiter. Suppression is accounted separately
//! from channel loss and summarized by the existing logger thread, including
//! during quiet periods and shutdown. No sender waits for a lock or for I/O.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::ActivityEvent;

pub(super) const WINDOW: Duration = Duration::from_secs(60);
const PER_TEMPLATE: u8 = 3;
const PER_SEVERITY: usize = 64;
/// Conservative JSON string-payload budget, separately for each severity.
/// Fixed schema fields and the periodic summary are outside this budget.
const PAYLOAD_BUDGET: usize = 256 * 1024;
const TEMPLATE_CHARS: usize = 256;
const INSPECT_CHARS: usize = 1024;
const CODE_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    severity: usize,
    code: String,
    template: String,
}

impl Key {
    fn for_event(event: &ActivityEvent) -> Option<(Self, usize)> {
        let (severity, code, message) = match event {
            ActivityEvent::Info { message } => (0, "", message),
            ActivityEvent::Warning { code, message } => (1, code.as_str(), message),
            ActivityEvent::Error { code, message } => (2, code.as_str(), message),
            // In particular: failed deletion attempts feed statistics and are
            // audit records, not disposable repeated error messages.
            _ => return None,
        };
        Some((
            Self {
                severity,
                code: code.chars().take(CODE_CHARS).collect(),
                template: message_template(message),
            },
            payload_cost(code, message),
        ))
    }
}

/// Bound serialized string content as well as event counts. JSON escaping
/// can expand a control byte to six bytes; Unicode UTF-8 stays unchanged.
/// Oversized input is rejected without scanning its whole message.
fn payload_cost(code: &str, message: &str) -> usize {
    if code.len().saturating_add(message.len()) > PAYLOAD_BUDGET {
        return PAYLOAD_BUDGET + 1;
    }
    code.bytes().chain(message.bytes()).fold(0, |cost, byte| {
        cost + match byte {
            b'"' | b'\\' => 2,
            0..=31 => 6,
            _ => 1,
        }
    })
}

/// Paths and changing numeric observations must not mint a new bucket every
/// tick. Preserve the surrounding words and the event's error code/severity,
/// so a different failure remains a different template. The per-severity
/// ceiling also bounds messages whose varying fields cannot be normalized.
fn message_template(message: &str) -> String {
    let bounded: String = message.chars().take(INSPECT_CHARS).collect();
    let mut normalized = String::new();
    for word in bounded.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        if word.contains('/') || word.contains('\\') {
            if let Some((label, _)) = word.split_once('=') {
                normalized.push_str(label);
                normalized.push('=');
            }
            normalized.push_str("<path>");
        } else {
            let mut in_number = false;
            for ch in word.chars() {
                if ch.is_ascii_digit() {
                    if !in_number {
                        normalized.push('#');
                    }
                    in_number = true;
                } else {
                    normalized.push(ch);
                    in_number = false;
                }
            }
        }
        if normalized.len() >= TEMPLATE_CHARS * 4 {
            break;
        }
    }
    normalized.chars().take(TEMPLATE_CHARS).collect()
}

struct State {
    window_started: Instant,
    last_report: Instant,
    emitted: [usize; 3],
    payload_bytes: [usize; 3],
    templates: HashMap<Key, u8>,
    pending: [u64; 3],
    byte_limited: [u64; 3],
    samples: [String; 3],
}

impl State {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            last_report: now,
            emitted: [0; 3],
            payload_bytes: [0; 3],
            templates: HashMap::new(),
            pending: [0; 3],
            byte_limited: [0; 3],
            samples: std::array::from_fn(|_| String::new()),
        }
    }

    fn admit(&mut self, key: Key, cost: usize, now: Instant) -> bool {
        if now.saturating_duration_since(self.window_started) >= WINDOW {
            self.window_started = now;
            self.emitted = [0; 3];
            self.payload_bytes = [0; 3];
            self.templates.clear();
            // Pending suppression survives rotation until the consumer writes
            // its summary. A delayed logger must not silently lose counts.
        }
        let severity = key.severity;
        let count = self.templates.get(&key).copied().unwrap_or(0);
        let bytes = self.payload_bytes[severity].saturating_add(cost);
        if self.emitted[severity] < PER_SEVERITY && count < PER_TEMPLATE && bytes <= PAYLOAD_BUDGET
        {
            self.emitted[severity] += 1;
            self.payload_bytes[severity] = bytes;
            self.templates.insert(key, count + 1);
            true
        } else {
            self.pending[severity] = self.pending[severity].saturating_add(1);
            if bytes > PAYLOAD_BUDGET {
                self.byte_limited[severity] = self.byte_limited[severity].saturating_add(1);
            }
            if self.samples[severity].is_empty() {
                self.samples[severity] = format!("{} {}", key.code, key.template);
            }
            false
        }
    }
}

pub(super) struct DiagnosticGate {
    state: Mutex<State>,
    /// Contention is also suppression, but must not wait for the lock to be
    /// counted. Separate severity counters keep the summary truthful.
    contended: [AtomicU64; 3],
    suppressed: AtomicU64,
}

impl DiagnosticGate {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            state: Mutex::new(State::new(now)),
            contended: std::array::from_fn(|_| AtomicU64::new(0)),
            suppressed: AtomicU64::new(0),
        }
    }

    pub(super) fn admit(&self, event: &ActivityEvent, now: Instant) -> bool {
        let Some((key, cost)) = Key::for_event(event) else {
            return true;
        };
        let admitted = if let Some(mut state) = self.state.try_lock() {
            state.admit(key, cost, now)
        } else {
            self.contended[key.severity].fetch_add(1, Ordering::Relaxed);
            false
        };
        if !admitted {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    pub(super) fn suppressed(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }

    /// Called only by the logger thread, outside backend I/O. The returned
    /// warning bypasses admission and uses the normal dual-write path, not the
    /// channel. `force` drains the final partial window on shutdown/disconnect.
    pub(super) fn take_report(&self, now: Instant, force: bool) -> Option<ActivityEvent> {
        let mut state = self.state.lock();
        let elapsed = now.saturating_duration_since(state.last_report);
        if !force && elapsed < WINDOW {
            return None;
        }
        let contended = self
            .contended
            .each_ref()
            .map(|counter| counter.swap(0, Ordering::Relaxed));
        let counts: [u64; 3] =
            std::array::from_fn(|i| state.pending[i].saturating_add(contended[i]));
        if counts == [0; 3] {
            return None;
        }
        let message = serde_json::json!({
            "kind": "diagnostic_throttle",
            "interval_secs": elapsed.as_secs(),
            "suppressed_info": counts[0],
            "suppressed_warning": counts[1],
            "suppressed_error": counts[2],
            "byte_limited_info": state.byte_limited[0],
            "byte_limited_warning": state.byte_limited[1],
            "byte_limited_error": state.byte_limited[2],
            "lock_contention": contended.iter().copied().fold(0u64, u64::saturating_add),
            "sample_templates": state.samples,
        })
        .to_string();
        state.pending = [0; 3];
        state.byte_limited = [0; 3];
        for sample in &mut state.samples {
            sample.clear();
        }
        state.last_report = now;
        drop(state);
        Some(ActivityEvent::Warning {
            code: "SBH-LOG-THROTTLED".to_string(),
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::dual::{DualLoggerConfig, spawn_logger};
    use crate::logger::jsonl::JsonlConfig;

    fn error(message: impl Into<String>) -> ActivityEvent {
        ActivityEvent::Error {
            code: "SBH-IO".to_string(),
            message: message.into(),
        }
    }

    fn report(gate: &DiagnosticGate, at: Instant, force: bool) -> serde_json::Value {
        let ActivityEvent::Warning { code, message } = gate.take_report(at, force).unwrap() else {
            panic!("suppression must produce a warning");
        };
        assert_eq!(code, "SBH-LOG-THROTTLED");
        serde_json::from_str(&message).unwrap()
    }

    #[test]
    fn changing_paths_and_measurements_share_a_template() {
        assert_eq!(
            message_template("write failed path=/tmp/agent-7/cache free=12.4% errno=28"),
            message_template("write failed path=/data/other/cache free=9.8% errno=28")
        );
        assert_ne!(
            message_template("write failed"),
            message_template("read failed")
        );
        let huge = "磁".repeat(10_000);
        assert!(message_template(&huge).chars().count() <= TEMPLATE_CHARS);
    }

    #[test]
    fn a_storm_emits_examples_and_accounts_for_every_suppression() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        for i in 0..10_000 {
            assert_eq!(
                gate.admit(
                    &error(format!("write failed path=/tmp/agent-{i} errno=28")),
                    now
                ),
                i < usize::from(PER_TEMPLATE)
            );
        }
        assert_eq!(gate.suppressed(), 9_997);
        let value = report(&gate, now, true);
        assert_eq!(value["suppressed_error"], 9_997);
        assert_eq!(value["suppressed_info"], 0);
        assert!(gate.take_report(now, true).is_none());
    }

    #[test]
    fn new_failure_meanings_and_error_codes_get_their_own_examples() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        for _ in 0..10 {
            gate.admit(&error("read failed"), now);
        }
        assert!(gate.admit(&error("write failed"), now));
        assert!(gate.admit(
            &ActivityEvent::Error {
                code: "SBH-DIFFERENT".to_string(),
                message: "read failed".to_string(),
            },
            now
        ));
    }

    #[test]
    fn informational_floods_do_not_spend_warning_or_error_capacity() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        for _ in 0..10_000 {
            gate.admit(
                &ActivityEvent::Info {
                    message: "retry".to_string(),
                },
                now,
            );
        }
        assert!(gate.admit(
            &ActivityEvent::Warning {
                code: "W".to_string(),
                message: "retry".to_string(),
            },
            now
        ));
        assert!(gate.admit(&error("retry"), now));
        assert_eq!(report(&gate, now, true)["suppressed_info"], 9_997);
    }

    #[test]
    fn high_cardinality_is_bounded_without_evicting_live_buckets() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        for i in 0..10_000 {
            let event = ActivityEvent::Error {
                code: format!("UNIQUE-{i}"),
                message: "failure".to_string(),
            };
            assert_eq!(gate.admit(&event, now), i < PER_SEVERITY);
        }
        assert_eq!(gate.state.lock().templates.len(), PER_SEVERITY);
        assert_eq!(gate.suppressed(), 10_000 - PER_SEVERITY as u64);
        assert!(gate.admit(&error("new minute"), now + WINDOW));
        assert_eq!(gate.state.lock().templates.len(), 1);
    }

    #[test]
    fn expiration_rearms_admission_without_losing_delayed_summary_counts() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        for _ in 0..4 {
            gate.admit(&error("failed"), now);
        }
        let just_inside = (now + WINDOW).checked_sub(Duration::from_nanos(1)).unwrap();
        assert!(!gate.admit(&error("failed"), just_inside));
        assert!(
            gate.take_report(now + Duration::from_secs(59), false)
                .is_none()
        );
        for i in 0..4 {
            assert_eq!(gate.admit(&error("failed"), now + WINDOW), i < 3);
        }
        assert_eq!(report(&gate, now + WINDOW, false)["suppressed_error"], 3);
        assert!(gate.take_report(now + WINDOW, true).is_none());
    }

    #[test]
    fn reporting_does_not_reset_the_rate_limit() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        for _ in 0..4 {
            gate.admit(&error("failed"), now);
        }
        assert_eq!(report(&gate, now, true)["suppressed_error"], 1);
        assert!(!gate.admit(&error("failed"), now));
        assert_eq!(report(&gate, now, true)["suppressed_error"], 1);
    }

    #[test]
    fn lock_contention_is_nonblocking_and_never_filters_audit_or_control() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        let guard = gate.state.lock();
        assert!(!gate.admit(&error("busy"), now));
        for event in [
            ActivityEvent::Shutdown,
            ActivityEvent::MirrorJsonl(true),
            ActivityEvent::Emergency {
                details: "full".to_string(),
                free_pct: 0.0,
            },
            ActivityEvent::ConfigReloaded {
                details: "changed".to_string(),
            },
            ActivityEvent::ArtifactDeletionFailed {
                path: "/tmp/target".to_string(),
                error_code: "SBH-IO".to_string(),
                error_message: "failed".to_string(),
            },
            ActivityEvent::BallastReleased {
                path: "/pool/file".to_string(),
                size_bytes: 4096,
                pressure: "red".to_string(),
                free_pct: 3.0,
            },
            ActivityEvent::PolicyTransition {
                transition: "fallback".to_string(),
                from: "enforce".to_string(),
                to: "fallback_safe".to_string(),
                reason: Some("guard failed".to_string()),
            },
        ] {
            assert!(gate.admit(&event, now), "{event:?}");
        }
        drop(guard);
        let value = report(&gate, now, true);
        assert_eq!(value["lock_contention"], 1);
        assert_eq!(value["suppressed_error"], 1);
        assert_eq!(gate.suppressed(), 1);
    }

    fn config(dir: &std::path::Path) -> DualLoggerConfig {
        DualLoggerConfig {
            sqlite_path: Some(dir.join("activity.db")),
            jsonl_config: JsonlConfig {
                path: dir.join("activity.jsonl"),
                fallback_path: None,
                max_size_bytes: 10 * 1024 * 1024,
                max_rotated_files: 3,
                fsync_interval_secs: 60,
            },
            channel_capacity: 64,
            run_id: Some("throttle-test".to_string()),
        }
    }

    #[test]
    fn cloned_producers_share_limits_and_shutdown_dual_writes_the_final_summary() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, join) = spawn_logger(config(dir.path())).unwrap();
        let other = handle.clone();
        for i in 0..5000 {
            let producer = if i % 2 == 0 { &handle } else { &other };
            producer.send(error(format!("write failed path=/tmp/agent-{i}")));
        }
        // Repeated audit records stay separate: statistics must not count a
        // suppression summary as a failed deletion or lose actual attempts.
        for _ in 0..5 {
            handle.send(ActivityEvent::ArtifactDeletionFailed {
                path: "/tmp/target".to_string(),
                error_code: "SBH-DELETE".to_string(),
                error_message: "permission denied".to_string(),
            });
        }
        handle.send(ActivityEvent::Emergency {
            details: "full".to_string(),
            free_pct: 0.0,
        });
        assert_eq!(handle.suppressed_diagnostics(), 4997);
        assert_eq!(other.suppressed_diagnostics(), 4997);
        assert_eq!(handle.dropped_events(), 0);
        handle.shutdown();
        join.join().unwrap();

        let text = std::fs::read_to_string(dir.path().join("activity.jsonl")).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 10);
        for line in &lines {
            crate::logger::schema::validate_value(line).unwrap();
            assert_eq!(line["run_id"], "throttle-test");
        }
        assert_eq!(
            lines
                .iter()
                .filter(|line| line["event"] == "artifact_delete")
                .count(),
            5
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line["event"] == "emergency")
                .count(),
            1
        );
        let summary = lines
            .iter()
            .find(|line| line["error_code"] == "SBH-LOG-THROTTLED")
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(summary["details"].as_str().unwrap()).unwrap();
        assert_eq!(value["suppressed_error"], 4997);

        #[cfg(feature = "sqlite")]
        {
            let db = rusqlite::Connection::open(dir.path().join("activity.db")).unwrap();
            let message: String = db
                .query_row(
                    "SELECT details FROM activity_log WHERE error_code = 'SBH-LOG-THROTTLED'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&message).unwrap(),
                value
            );
            let failures: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM activity_log WHERE event_type = 'artifact_delete' AND success = 0",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(failures, 5);
        }
    }

    #[test]
    fn disconnect_flushes_suppression_without_an_explicit_shutdown_event() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(dir.path());
        cfg.sqlite_path = None;
        let (handle, join) = spawn_logger(cfg).unwrap();
        for _ in 0..10 {
            handle.send(error("failed"));
        }
        drop(handle);
        join.join().unwrap();
        let text = std::fs::read_to_string(dir.path().join("activity.jsonl")).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 4);
        let details: serde_json::Value =
            serde_json::from_str(lines.last().unwrap()["details"].as_str().unwrap()).unwrap();
        assert_eq!(details["suppressed_error"], 7);
    }

    #[test]
    fn an_oversized_message_cannot_consume_the_queue_or_block_a_small_error() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        assert!(!gate.admit(&error("x".repeat(PAYLOAD_BUDGET + 1)), now));
        assert!(gate.state.lock().templates.is_empty());
        assert!(gate.admit(&error("independent small error"), now));
        let value = report(&gate, now, true);
        assert_eq!(value["suppressed_error"], 1);
        assert_eq!(value["byte_limited_error"], 1);
    }

    #[test]
    fn escaped_payload_budget_is_separate_per_severity_and_rearms_on_expiry() {
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        let event = ActivityEvent::Info {
            // Each quote takes two bytes inside its JSON string.
            message: "\"".repeat(PAYLOAD_BUDGET / 2),
        };
        assert!(gate.admit(&event, now));
        assert_eq!(gate.state.lock().payload_bytes[0], PAYLOAD_BUDGET);
        assert!(!gate.admit(
            &ActivityEvent::Info {
                message: "different template, same byte budget".to_string(),
            },
            now
        ));
        assert!(gate.admit(&error("errors have their own reserve"), now));
        assert!(gate.admit(&event, now + WINDOW));
        let value = report(&gate, now + WINDOW, false);
        assert_eq!(value["byte_limited_info"], 1);
        assert_eq!(value["suppressed_error"], 0);
    }

    #[test]
    fn payload_accounting_bounds_json_escaping_and_does_not_charge_rejected_messages() {
        assert_eq!(payload_cost("code", "quote=\" slash=\\"), 21);
        assert_eq!(payload_cost("", "\0"), 6);
        assert_eq!(payload_cost("", "磁"), "磁".len());
        let now = Instant::now();
        let gate = DiagnosticGate::new(now);
        let event = error("small");
        for _ in 0..100 {
            gate.admit(&event, now);
        }
        assert_eq!(
            gate.state.lock().payload_bytes[2],
            usize::from(PER_TEMPLATE) * payload_cost("SBH-IO", "small")
        );
        assert_eq!(report(&gate, now, true)["byte_limited_error"], 0);
    }
}
