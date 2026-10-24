//! In-process delivery to Apple's unified logging system.
//!
//! The public SDK macro is compiled in a small C adapter so argument encoding
//! follows the SDK rather than a hand-maintained private logging ABI.

use std::ffi::CString;
use std::io;

/// Maximum UTF-8 message bytes accepted by the native logging adapter.
pub const UNIFIED_LOG_MESSAGE_MAX_BYTES: usize = 1024;

/// Apple log severity used by operator notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnifiedLogLevel {
    /// Informational messages, shown with `log show --info` when enabled.
    Info = 0,
    /// Warnings and notices that should use the default logging level.
    Default = 1,
    /// Red and Critical pressure, without the extra overhead of fault logging.
    Error = 2,
}

#[allow(unsafe_code)]
unsafe extern "C" {
    fn sbh_unified_log_message(severity: u8, message: *const std::ffi::c_char) -> std::ffi::c_int;
}

/// Submit a bounded notification under the calling process's identity.
///
/// The subsystem is `org.storage-ballast-helper.sbh` and the category is
/// `notifications`. This submits to the OS; filtering and retention remain
/// controlled by macOS, so success is not an acknowledgement of persistence.
/// The caller should retain its ordinary service-log fallback.
#[allow(unsafe_code)]
pub fn log_notification(level: UnifiedLogLevel, message: &str) -> io::Result<()> {
    let message = notification_c_string(message)?;
    // SAFETY: the CString is NUL-terminated, bounded and valid for the whole
    // synchronous call. The C adapter does not retain its pointer. The repr(u8)
    // discriminants match the adapter's private severity switch, not an Apple ABI.
    let status = unsafe { sbh_unified_log_message(level as u8, message.as_ptr()) };
    if status != 0 {
        return Err(io::Error::other("macOS unified log is unavailable"));
    }
    Ok(())
}

fn notification_c_string(message: &str) -> io::Result<CString> {
    if message.len() > UNIFIED_LOG_MESSAGE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unified log message exceeds its byte budget",
        ));
    }
    CString::new(message).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "unified log message contains an interior NUL",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_messages_are_rejected_before_native_delivery() {
        for message in ["bad\0message".to_owned(), "x".repeat(1025)] {
            assert_eq!(
                notification_c_string(&message).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let message = "x".repeat(UNIFIED_LOG_MESSAGE_MAX_BYTES);
        assert_eq!(
            notification_c_string(&message).unwrap().as_bytes(),
            message.as_bytes()
        );
    }
}
