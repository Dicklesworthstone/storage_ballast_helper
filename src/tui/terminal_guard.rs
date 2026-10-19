//! The dashboard's terminal session: the one owner of raw mode and the
//! alternate screen for [`super::runtime`], on top of ftui-tty.
//!
//! ftui-tty's backend restores the terminal when it is dropped, and with
//! `panic = "abort"` (the release profile) from a panic hook of its own. Two
//! gaps remain, and this guard closes them:
//!
//! - **Panics with unwinding** (debug and test builds). The default hook would
//!   print the message while the terminal is still raw and on the alternate
//!   screen, and the backend's drop then leaves that screen, taking the message
//!   with it. The guard's hook restores the terminal first (features off,
//!   cursor shown, alternate screen left, the saved terminal settings back), so
//!   the message lands on the normal screen, and the backend is then not
//!   dropped: a second "leave alternate screen" would put the cursor back where
//!   the dashboard started, over the message.
//! - **SIGTERM, SIGHUP, SIGQUIT and SIGINT from another process.** ftui-tty
//!   restores the terminal and waits up to 2 s for the program to acknowledge
//!   before it exits the process. [`TerminalGuard::wait_for_event`] reports the
//!   signal within [`SIGNAL_CHECK_INTERVAL`], so the event loop stops drawing on
//!   the restored screen and tears down normally;
//!   [`TerminalGuard::acknowledge_termination`] then tells ftui-tty not to exit
//!   the process itself.

use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::mem;
use std::panic;
use std::sync::{Mutex, OnceLock};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use ftui::core::shutdown_signal;
use ftui_backend::{BackendEventSource, BackendFeatures};
use ftui_tty::{TtyBackend, TtySessionOptions};
use nix::sys::termios::{self, SetArg, Termios};

/// Longest wait for terminal input before the pending-signal check: well
/// inside ftui-tty's 2 s grace after a termination signal.
pub const SIGNAL_CHECK_INTERVAL: Duration = Duration::from_millis(200);

/// Resets the panic hook writes before ftui-tty's cleanup sequence: the
/// scroll region and the text attributes.
const STATE_RESETS: &[u8] = b"\x1b[r\x1b[0m";

/// What [`TerminalGuard::open`] set up, for the panic hook.
struct Session {
    /// The thread that owns the terminal. Another thread's panic leaves the
    /// dashboard drawing, so it does not restore the terminal under it.
    owner: ThreadId,
    /// The terminal settings before raw mode.
    termios: Termios,
    features: BackendFeatures,
    alternate_screen: bool,
    /// Set by the panic hook once it has restored the terminal.
    restored: bool,
}

fn session_slot() -> &'static Mutex<Option<Session>> {
    static SLOT: OnceLock<Mutex<Option<Session>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// How [`TerminalGuard::wait_for_event`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// Terminal input is ready to read.
    Event,
    /// The timeout passed with no input.
    Timeout,
    /// A termination signal arrived; ftui-tty has already restored the
    /// terminal, so stop drawing.
    Terminated(i32),
}

/// The dashboard stopped because of a termination signal, after a clean
/// teardown. The CLI exits with 128 + the signal, as ftui-tty would have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminatedBySignal(pub i32);

impl fmt::Display for TerminatedBySignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "terminated by signal {}", self.0)
    }
}

impl std::error::Error for TerminatedBySignal {}

impl TerminatedBySignal {
    /// The signal, when `error` carries one.
    #[must_use]
    pub fn in_error(error: &io::Error) -> Option<i32> {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Self>())
            .map(|terminated| terminated.0)
    }
}

/// The open terminal session. Drop restores the terminal.
pub struct TerminalGuard {
    backend: Option<TtyBackend>,
}

impl TerminalGuard {
    /// Enter raw mode (and the alternate screen and features `options` ask
    /// for) on the controlling terminal.
    ///
    /// # Errors
    /// Fails when there is no controlling terminal or it cannot be set up;
    /// ftui-tty undoes whatever it had set up.
    pub fn open(options: TtySessionOptions) -> io::Result<Self> {
        let termios = termios::tcgetattr(File::open("/dev/tty")?).map_err(io::Error::from)?;
        let features = options.features;
        let alternate_screen = options.alternate_screen;
        let backend = TtyBackend::open(80, 24, options)?;
        install_panic_hook();
        *lock_session() = Some(Session {
            owner: thread::current().id(),
            termios,
            features,
            alternate_screen,
            restored: false,
        });
        Ok(Self {
            backend: Some(backend),
        })
    }

    /// The backend, for drawing and reading events.
    pub fn backend(&mut self) -> &mut TtyBackend {
        self.backend
            .as_mut()
            .expect("the backend is present until the guard drops")
    }

    /// Wait up to `timeout` for terminal input, checking for a termination
    /// signal at least every [`SIGNAL_CHECK_INTERVAL`].
    ///
    /// # Errors
    /// Terminal read errors.
    pub fn wait_for_event(&mut self, timeout: Duration) -> io::Result<Wait> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(signal) = shutdown_signal::pending_termination_signal() {
                return Ok(Wait::Terminated(signal));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if self.backend().poll_event(left.min(SIGNAL_CHECK_INTERVAL))? {
                return Ok(Wait::Event);
            }
            if left <= SIGNAL_CHECK_INTERVAL {
                return Ok(Wait::Timeout);
            }
        }
    }

    /// Restore the terminal, then tell ftui-tty the termination signal was
    /// handled, so it does not exit the process itself. Returns the error the
    /// dashboard ends with.
    pub fn acknowledge_termination(self, signal: i32) -> io::Error {
        drop(self);
        shutdown_signal::clear_pending_termination_signal();
        io::Error::other(TerminatedBySignal(signal))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let restored_by_hook = lock_session()
            .take()
            .is_some_and(|session| session.restored);
        if let Some(backend) = self.backend.take() {
            if restored_by_hook {
                // The panic hook already restored the terminal and the message
                // follows it on the normal screen; the backend's own cleanup
                // would move the cursor back over it. The process is ending
                // (nothing in sbh catches an unwind), so nothing is lost.
                mem::forget(backend);
            } else {
                drop(backend);
            }
        }
    }
}

fn lock_session() -> std::sync::MutexGuard<'static, Option<Session>> {
    session_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the restoring panic hook once per process, ahead of the hook that
/// prints the message. With `panic = "abort"` ftui-tty's own hook does this,
/// and a second one would restore the terminal twice.
fn install_panic_hook() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if cfg!(panic = "abort") {
        return;
    }
    INSTALLED.get_or_init(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            restore_for_panic();
            previous(info);
        }));
    });
}

/// Restore the terminal from the panic hook when the panicking thread owns an
/// open session. `try_lock`: a panic while the slot is held must not hang.
fn restore_for_panic() {
    let Ok(mut slot) = session_slot().try_lock() else {
        return;
    };
    let Some(session) = slot.as_mut() else {
        return;
    };
    if session.restored || session.owner != thread::current().id() {
        return;
    }
    let mut stdout = io::stdout().lock();
    let _ = write_restore_sequence(session.features, session.alternate_screen, &mut stdout);
    let _ = stdout.flush();
    drop(stdout);
    if let Ok(tty) = File::open("/dev/tty") {
        let _ = termios::tcsetattr(tty, SetArg::TCSAFLUSH, &session.termios);
    }
    session.restored = true;
}

/// The bytes that return the screen to normal: resets, then ftui-tty's
/// cleanup (features off, cursor shown, alternate screen left).
fn write_restore_sequence(
    features: BackendFeatures,
    alternate_screen: bool,
    writer: &mut impl Write,
) -> io::Result<()> {
    writer.write_all(STATE_RESETS)?;
    ftui_tty::write_cleanup_sequence(&features, alternate_screen, writer)
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[test]
    fn the_restore_sequence_ends_features_and_shows_the_cursor_before_leaving_the_screen() {
        let mut out = Vec::new();
        let features = BackendFeatures {
            mouse_capture: true,
            ..BackendFeatures::default()
        };
        write_restore_sequence(features, true, &mut out).unwrap();
        let resets = position(&out, STATE_RESETS).unwrap();
        let mouse_off = position(&out, b"\x1b[?1000l").unwrap();
        let cursor = position(&out, b"\x1b[?25h").unwrap();
        let leave = position(&out, b"\x1b[?1049l").unwrap();
        assert!(resets < mouse_off && mouse_off < cursor && cursor < leave);

        let mut plain = Vec::new();
        write_restore_sequence(BackendFeatures::default(), false, &mut plain).unwrap();
        assert!(position(&plain, b"\x1b[?1049l").is_none());
        assert!(position(&plain, b"\x1b[?1000l").is_none());
        assert!(position(&plain, b"\x1b[?25h").is_some());
    }

    #[test]
    fn a_termination_error_carries_its_signal() {
        let error = io::Error::other(TerminatedBySignal(15));
        assert_eq!(TerminatedBySignal::in_error(&error), Some(15));
        assert_eq!(error.to_string(), "terminated by signal 15");
        assert_eq!(TerminatedBySignal::in_error(&io::Error::other("x")), None);
    }
}
