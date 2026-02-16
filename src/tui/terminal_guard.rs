//! RAII terminal lifecycle guard for panic-safe raw mode and alternate screen.
//!
//! [`TerminalGuard`] enters raw mode and (optionally) the alternate screen on
//! construction, and restores the terminal on [`Drop`] — even during panics or
//! early error returns. A custom panic hook is installed to ensure terminal
//! restoration happens *before* the default panic message is printed, so the
//! backtrace is readable on a normal terminal.

use std::io::{self, Write};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::cursor;
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};

/// Global flag indicating raw mode is active. Checked by the panic hook to
/// decide whether terminal restoration is needed.
static RAW_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// RAII guard that manages the terminal lifecycle.
///
/// On creation: enables raw mode and enters alternate screen.
/// On drop: leaves alternate screen, disables raw mode, and shows the cursor.
///
/// A custom panic hook is installed on creation and removed on drop so that
/// panics always produce readable output on a restored terminal.
pub struct TerminalGuard {
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
        terminal::enable_raw_mode()?;
        RAW_MODE_ACTIVE.store(true, Ordering::SeqCst);

        // Enter alternate screen. If this fails, drop will still disable raw mode.
        let mut stdout = io::stdout();
        let _ = execute!(stdout, EnterAlternateScreen);

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
            hook_installed: true,
        })
    }

    /// Terminal dimensions (columns, rows).
    ///
    /// Falls back to (80, 24) if the query fails.
    #[must_use]
    pub fn terminal_size() -> (u16, u16) {
        terminal::size().unwrap_or((80, 24))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_best_effort();

        if self.hook_installed {
            // Remove our panic hook. The previous hook was moved into the
            // closure so we can't restore it exactly; reset to default.
            // This is safe because the guard's lifetime brackets all TUI usage.
            let _ = panic::take_hook();
        }
    }
}

/// Best-effort terminal restoration. Safe to call multiple times; uses the
/// atomic flag to avoid redundant work.
fn restore_terminal_best_effort() {
    if RAW_MODE_ACTIVE.swap(false, Ordering::SeqCst) {
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
        let _ = execute!(stdout, cursor::Show);
        let _ = terminal::disable_raw_mode();
        let _ = stdout.flush();
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
