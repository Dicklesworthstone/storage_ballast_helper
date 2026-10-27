//! Journal delivery with an independent service-log fallback.

use std::io::{self, Write};

#[cfg(target_os = "macos")]
const MESSAGE_MAX_BYTES: usize = sbh_mach::UNIFIED_LOG_MESSAGE_MAX_BYTES;
#[cfg(not(target_os = "macos"))]
const MESSAGE_MAX_BYTES: usize = 1024;
const TRUNCATED: &str = " [truncated]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JournalLevel {
    Info,
    Warning,
    Orange,
    Red,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeLevel {
    Info,
    Default,
    Error,
}

impl JournalLevel {
    const fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Orange => "orange",
            Self::Red => "red",
            Self::Critical => "critical",
        }
    }

    const fn priority(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "NOTICE",
            Self::Orange => "WARNING",
            Self::Red => "ERR",
            Self::Critical => "CRIT",
        }
    }

    const fn native_level(self) -> NativeLevel {
        match self {
            Self::Info => NativeLevel::Info,
            Self::Warning | Self::Orange => NativeLevel::Default,
            // Pressure is operational state, not a fault in the program. Avoid
            // the extra diagnostic capture associated with OS_LOG_TYPE_FAULT.
            Self::Red | Self::Critical => NativeLevel::Error,
        }
    }
}

pub(super) fn send(level: JournalLevel, event_type: &str, summary: &str) {
    #[cfg(target_os = "macos")]
    let native_sink = write_unified_log;
    #[cfg(not(target_os = "macos"))]
    let native_sink = |_: NativeLevel, _: &str| Ok(());

    send_with(
        level,
        event_type,
        summary,
        |line| {
            // A closed stderr must not turn an optional notification into a
            // daemon failure. Keep the full existing service-log summary.
            let _ = writeln!(io::stderr().lock(), "{line}");
        },
        native_sink,
    );
}

fn send_with(
    level: JournalLevel,
    event_type: &str,
    summary: &str,
    stderr_sink: impl FnOnce(&str),
    native_sink: impl FnOnce(NativeLevel, &str) -> io::Result<()>,
) {
    // Write the independent fallback first. macOS may filter, truncate or
    // decline native messages, even when submission itself succeeds.
    stderr_sink(&format!("[SBH-NOTIFY] [{}] {summary}", level.priority()));
    let message = native_message(level, event_type, summary);
    let _ = native_sink(level.native_level(), &message);
}

fn native_message(level: JournalLevel, event_type: &str, summary: &str) -> String {
    let mut message = String::with_capacity(MESSAGE_MAX_BYTES);
    let parts = [
        "SBH_EVENT=",
        event_type,
        " SBH_LEVEL=",
        level.name(),
        " ",
        summary,
    ];
    for character in parts.into_iter().flat_map(str::chars) {
        let mut utf8 = [0; 4];
        let escaped_control;
        let text = if character.is_control() || character == '\\' {
            escaped_control = character.escape_debug().to_string();
            escaped_control.as_str()
        } else {
            character.encode_utf8(&mut utf8)
        };
        if message.len() + text.len() > MESSAGE_MAX_BYTES - TRUNCATED.len() {
            message.push_str(TRUNCATED);
            break;
        }
        message.push_str(text);
    }
    message
}

#[cfg(target_os = "macos")]
fn write_unified_log(level: NativeLevel, message: &str) -> io::Result<()> {
    let level = match level {
        NativeLevel::Info => sbh_mach::UnifiedLogLevel::Info,
        NativeLevel::Default => sbh_mach::UnifiedLogLevel::Default,
        NativeLevel::Error => sbh_mach::UnifiedLogLevel::Error,
    };
    sbh_mach::log_notification(level, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_severity_and_structured_fields_follow_pressure() {
        for (level, native_level, priority, name) in [
            (JournalLevel::Info, NativeLevel::Info, "INFO", "info"),
            (
                JournalLevel::Warning,
                NativeLevel::Default,
                "NOTICE",
                "warning",
            ),
            (
                JournalLevel::Orange,
                NativeLevel::Default,
                "WARNING",
                "orange",
            ),
            (JournalLevel::Red, NativeLevel::Error, "ERR", "red"),
            (
                JournalLevel::Critical,
                NativeLevel::Error,
                "CRIT",
                "critical",
            ),
        ] {
            let mut stderr = None;
            let mut native = None;
            send_with(
                level,
                "pressure_changed",
                "disk pressure",
                |line| stderr = Some(line.to_owned()),
                |severity, message| {
                    native = Some((severity, message.to_owned()));
                    Ok(())
                },
            );
            assert_eq!(
                stderr.as_deref(),
                Some(format!("[SBH-NOTIFY] [{priority}] disk pressure").as_str())
            );
            assert_eq!(
                native,
                Some((
                    native_level,
                    format!("SBH_EVENT=pressure_changed SBH_LEVEL={name} disk pressure")
                ))
            );
        }
    }

    #[test]
    fn native_record_escapes_controls_without_treating_data_as_format() {
        let message = native_message(
            JournalLevel::Red,
            "error",
            "disk\0\n\r\t\u{1b}\\路径 100% %{private}s %n",
        );
        assert_eq!(
            message,
            "SBH_EVENT=error SBH_LEVEL=red disk\\0\\n\\r\\t\\u{1b}\\\\路径 100% %{private}s %n"
        );
        assert!(!message.chars().any(char::is_control));
    }

    #[test]
    fn oversized_native_record_is_bounded_at_a_utf8_boundary() {
        let summary = "🦀压力".repeat(1024);
        let message = native_message(JournalLevel::Critical, "behavior_emergency", &summary);
        assert!(message.len() <= MESSAGE_MAX_BYTES);
        assert!(message.ends_with(TRUNCATED));
        assert!(message.starts_with("SBH_EVENT=behavior_emergency SBH_LEVEL=critical "));
        assert!(message.contains("🦀压力"));
        assert!(std::ffi::CString::new(message).is_ok());
    }

    #[test]
    fn native_failure_preserves_the_full_service_log_fallback() {
        let summary = format!("critical disk pressure: {}", "x".repeat(4096));
        let mut stderr = None;
        let mut native_calls = 0;
        send_with(
            JournalLevel::Critical,
            "behavior_emergency",
            &summary,
            |line| stderr = Some(line.to_owned()),
            |level, message| {
                native_calls += 1;
                assert_eq!(level, NativeLevel::Error);
                assert!(message.len() <= MESSAGE_MAX_BYTES);
                assert!(message.ends_with(TRUNCATED));
                Err(io::Error::other("unified logging unavailable"))
            },
        );
        assert_eq!(native_calls, 1);
        assert_eq!(stderr, Some(format!("[SBH-NOTIFY] [CRIT] {summary}")));
    }
}
