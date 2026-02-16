//! Input routing scaffold for the dashboard runtime.

#![allow(missing_docs)]

use crossterm::event::KeyEvent;

use super::model::DashboardMsg;

/// Route a terminal key event into the dashboard message stream.
#[must_use]
pub fn map_key_event(key: KeyEvent) -> DashboardMsg {
    DashboardMsg::Key(key)
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    use super::*;

    #[test]
    fn key_mapping_preserves_event() {
        let event = KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };

        let msg = map_key_event(event);
        match msg {
            DashboardMsg::Key(inner) => {
                assert_eq!(inner.code, KeyCode::Char('q'));
                assert!(inner.modifiers.contains(KeyModifiers::CONTROL));
            }
            _ => panic!("expected key event"),
        }
    }
}
