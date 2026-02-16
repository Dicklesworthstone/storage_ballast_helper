//! Render-surface scaffolding for the new dashboard runtime.

#![allow(missing_docs)]

use super::model::{DashboardModel, Screen};

/// Stable render entrypoint for screen dispatch.
///
/// The implementation here remains intentionally minimal until screen-specific
/// beads (`bd-xzt.3.*`) populate real widgets and layouts.
#[must_use]
pub fn render(model: &DashboardModel) -> String {
    match model.screen {
        Screen::Overview => render_overview_stub(model),
    }
}

#[must_use]
pub fn render_overview_stub(model: &DashboardModel) -> String {
    let mode = if model.degraded { "DEGRADED" } else { "NORMAL" };
    format!(
        "SBH Dashboard ({mode})  tick={}  size={}x{}",
        model.tick, model.terminal_size.0, model.terminal_size.1
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    #[test]
    fn render_includes_mode_and_dimensions() {
        let mut model = DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![PathBuf::from("/tmp")],
            Duration::from_secs(1),
            (120, 42),
        );
        model.tick = 9;
        model.degraded = false;

        let frame = render(&model);
        assert!(frame.contains("NORMAL"));
        assert!(frame.contains("tick=9"));
        assert!(frame.contains("120x42"));
    }
}
