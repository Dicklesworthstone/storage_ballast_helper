//! RAII terminal lifecycle guard backed by ftui-tty.
//!
//! [`TerminalGuard`] enters raw mode and the alternate screen on construction,
//! and restores the terminal on [`Drop`] — even during panics or early error
//! returns. A custom panic hook is installed to ensure terminal restoration
//! happens *before* the default panic message is printed, so the backtrace is
//! readable on a normal terminal.

use std::io::{self, Write};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};

use ftui_tty::TtyBackend;

/// Global flag indicating raw mode is active. Checked by the panic hook to
/// decide whether terminal restoration is needed.
static RAW_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Escape sequences for terminal lifecycle management.
const ALT_SCREEN_LEAVE: &[u8] = b"\x1b[?1049l";
const CURSOR_SHOW: &[u8] = b"\x1b[?25h";

/// RAII guard that manages the terminal lifecycle via ftui-tty.
///
/// On creation: enables raw mode and enters alternate screen via `TtyBackend`.
/// On drop: the backend restores the terminal. A panic hook provides
/// best-effort cleanup even on unwind.
pub struct TerminalGuard {
    /// The ftui-tty backend owns the raw mode guard and terminal state.
    _backend: TtyBackend,
    /// Whether we installed a custom panic hook (so drop knows to remove it).
    hook_installed: bool,
}

impl TerminalGuard {
    /// Enter raw mode and alternate screen, installing a panic-safe cleanup hook.
    ///
    /// # Errors
    /// Returns I/O errors if terminal setup fails. On partial failure the guard
    /// still cleans up whatever was successfully set up.
    pub fn new() -> io::Result<Self> {
        let options = ftui_tty::TtySessionOptions {
            alternate_screen: true,
            ..Default::default()
        };

        let backend = TtyBackend::open(80, 24, options)?;
        RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);

        // Install panic hook that restores terminal before printing the panic.
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            // Best-effort terminal restoration inside the panic hook.
            restore_terminal_best_effort();
            // Then delegate to the previous hook (typically the default one that
            // prints the backtrace).
            prev(info);
        }));

        Ok(Self {
            _backend: backend,
            hook_installed: true,
        })
    }

    /// Terminal dimensions (columns, rows).
    ///
    /// Falls back to (80, 24) if the query fails.
    #[must_use]
    pub fn terminal_size() -> (u16, u16) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if let Ok(tty) = std::fs::File::open("/dev/tty") {
                let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                let ret = unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
                if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
                    return (ws.ws_col, ws.ws_row);
                }
            }
        }
        (80, 24)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        RAW_MODE_ACTIVE.store(false, Ordering::SeqCst);

        if self.hook_installed {
            // Remove our panic hook. The previous hook was moved into the
            // closure so we can't restore it exactly; reset to default.
            // This is safe because the guard's lifetime brackets all TUI usage.
            let _ = panic::take_hook();
        }

        // TtyBackend::drop handles terminal restoration (raw mode, alt screen,
        // cursor, features).
    }
}

/// Best-effort terminal restoration. Safe to call multiple times; uses the
/// atomic flag to avoid redundant work.
fn restore_terminal_best_effort() {
    if RAW_MODE_ACTIVE.swap(false, Ordering::SeqCst) {
        let mut stdout = io::stdout();
        let _ = stdout.write_all(ALT_SCREEN_LEAVE);
        let _ = stdout.write_all(CURSOR_SHOW);
        let _ = stdout.flush();
        // Note: we cannot restore termios from the panic hook because we
        // don't own the RawModeGuard here. TtyBackend::drop will handle it
        // when the guard is dropped after the panic hook runs.
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_mode_flag_starts_false() {
        assert!(!RAW_MODE_ACTIVE.load(Ordering::SeqCst));
    }

    #[test]
    fn restore_terminal_is_idempotent() {
        restore_terminal_best_effort();
        restore_terminal_best_effort();
        assert!(!RAW_MODE_ACTIVE.load(Ordering::SeqCst));
    }

    #[test]
    fn terminal_size_fallback() {
        let (cols, rows) = TerminalGuard::terminal_size();
        assert!(cols > 0);
        assert!(rows > 0);
    }

    #[test]
    fn flag_round_trip_without_terminal() {
        assert!(!RAW_MODE_ACTIVE.load(Ordering::SeqCst));
        RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);
        assert!(RAW_MODE_ACTIVE.load(Ordering::SeqCst));

        // restore_terminal_best_effort clears the flag.
        restore_terminal_best_effort();
        assert!(!RAW_MODE_ACTIVE.load(Ordering::SeqCst));
    }
}
