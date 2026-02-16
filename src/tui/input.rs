//! Input routing scaffold for the dashboard runtime.

#![allow(missing_docs)]

use ftui_core::event::{KeyCode, KeyEvent};

use super::model::{DashboardMsg, Overlay, Screen};
use super::preferences::{DensityMode, HintVerbosity, StartScreen};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputContext {
    pub screen: Screen,
    pub active_overlay: Option<Overlay>,
}

impl Default for InputContext {
    fn default() -> Self {
        Self {
            screen: Screen::Overview,
            active_overlay: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAction {
    Quit,
    BackOrQuit,
    CloseOverlay,
    Navigate(Screen),
    NavigatePrev,
    NavigateNext,
    OpenOverlay(Overlay),
    ToggleOverlay(Overlay),
    ForceRefresh,
    JumpBallast,
    SetStartScreen(StartScreen),
    SetDensity(DensityMode),
    SetHintVerbosity(HintVerbosity),
    ResetPreferencesToPersisted,
    RevertPreferencesToDefaults,
    PaletteType(char),
    PaletteBackspace,
    PaletteExecute,
    PaletteCursorUp,
    PaletteCursorDown,
    /// Show incident triage playbook overlay (bd-xzt.3.9).
    IncidentShowPlaybook,
    /// Quick-release ballast: jump to ballast screen with release confirmation.
    IncidentQuickRelease,
    /// Navigate to the playbook entry at the cursor position.
    IncidentPlaybookNavigate,
    /// Move playbook cursor up.
    IncidentPlaybookUp,
    /// Move playbook cursor down.
    IncidentPlaybookDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputResolution {
    pub action: Option<InputAction>,
    pub consumed: bool,
}

impl InputResolution {
    const fn action(action: InputAction) -> Self {
        Self {
            action: Some(action),
            consumed: true,
        }
    }

    const fn consumed_without_action() -> Self {
        Self {
            action: None,
            consumed: true,
        }
    }

    const fn passthrough() -> Self {
        Self {
            action: None,
            consumed: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteAction {
    pub id: &'static str,
    pub title: &'static str,
    pub shortcut: &'static str,
    pub action: InputAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelpBinding {
    pub keys: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextualHelp {
    pub title: &'static str,
    pub screen_hint: &'static str,
    pub bindings: Vec<HelpBinding>,
}

/// Route a terminal key event into the dashboard message stream.
#[must_use]
pub fn map_key_event(key: KeyEvent) -> DashboardMsg {
    DashboardMsg::Key(key)
}

/// Resolve a key event using deterministic precedence rules:
/// overlay keys first, then global keys.
#[must_use]
pub fn resolve_key_event(key: &KeyEvent, context: InputContext) -> InputResolution {
    if let Some(overlay) = context.active_overlay {
        return resolve_overlay_key(key, overlay);
    }
    resolve_global_key(key)
}

/// Stable command-palette catalog with deterministic action IDs.
#[must_use]
pub const fn command_palette_actions() -> &'static [PaletteAction] {
    &PALETTE_ACTIONS
}

/// Resolve a palette action ID to a concrete action.
#[must_use]
pub fn resolve_palette_action(id: &str) -> Option<InputAction> {
    PALETTE_ACTIONS
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.action)
}

/// Search command-palette actions using deterministic ranking.
///
/// Ranking precedence:
/// 1. exact ID match
/// 2. exact title match
/// 3. exact shortcut match
/// 4. ID prefix
/// 5. title prefix
/// 6. ID substring
/// 7. title substring
///
/// Ties are resolved lexicographically by action ID to keep output stable.
#[must_use]
pub fn search_palette_actions(query: &str, limit: usize) -> Vec<&'static PaletteAction> {
    if limit == 0 {
        return Vec::new();
    }

    let query = normalize(query);
    if query.is_empty() {
        return PALETTE_ACTIONS.iter().take(limit).collect();
    }

    let mut matches: Vec<(u8, &PaletteAction)> = PALETTE_ACTIONS
        .iter()
        .filter_map(|action| match_score(action, &query).map(|score| (score, action)))
        .collect();

    matches.sort_unstable_by(|(left_score, left_action), (right_score, right_action)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_action.id.cmp(right_action.id))
    });

    matches
        .into_iter()
        .map(|(_, action)| action)
        .take(limit)
        .collect()
}

/// Route a palette query to the best-matching action.
///
/// Returns `None` for blank or non-matching queries.
#[must_use]
pub fn route_palette_query(query: &str) -> Option<InputAction> {
    if normalize(query).is_empty() {
        return None;
    }
    search_palette_actions(query, 1)
        .first()
        .copied()
        .map(|action| action.action)
}

/// Build contextual help entries for the current screen/overlay state.
#[must_use]
pub fn contextual_help(context: InputContext) -> ContextualHelp {
    context
        .active_overlay
        .map_or_else(|| screen_help(context.screen), overlay_help)
}

fn resolve_overlay_key(key: &KeyEvent, overlay: Overlay) -> InputResolution {
    match key.code {
        KeyCode::Char('c') if key.ctrl() => InputResolution::action(InputAction::Quit),
        KeyCode::Escape => InputResolution::action(InputAction::CloseOverlay),
        KeyCode::Char('?') if overlay == Overlay::Help => {
            InputResolution::action(InputAction::ToggleOverlay(Overlay::Help))
        }
        KeyCode::Char('v') if overlay == Overlay::Voi => {
            InputResolution::action(InputAction::ToggleOverlay(Overlay::Voi))
        }
        KeyCode::Char('p') if key.ctrl() && overlay == Overlay::CommandPalette => {
            InputResolution::action(InputAction::ToggleOverlay(Overlay::CommandPalette))
        }
        KeyCode::Char('!') if overlay == Overlay::IncidentPlaybook => {
            InputResolution::action(InputAction::ToggleOverlay(Overlay::IncidentPlaybook))
        }
        KeyCode::Enter if overlay == Overlay::CommandPalette => {
            InputResolution::action(InputAction::PaletteExecute)
        }
        KeyCode::Backspace if overlay == Overlay::CommandPalette => {
            InputResolution::action(InputAction::PaletteBackspace)
        }
        KeyCode::Up if overlay == Overlay::CommandPalette => {
            InputResolution::action(InputAction::PaletteCursorUp)
        }
        KeyCode::Down if overlay == Overlay::CommandPalette => {
            InputResolution::action(InputAction::PaletteCursorDown)
        }
        KeyCode::Char(c) if overlay == Overlay::CommandPalette => {
            InputResolution::action(InputAction::PaletteType(c))
        }
        // ── Incident playbook overlay (O7) ──
        KeyCode::Up | KeyCode::Char('k') if overlay == Overlay::IncidentPlaybook => {
            InputResolution::action(InputAction::IncidentPlaybookUp)
        }
        KeyCode::Down | KeyCode::Char('j') if overlay == Overlay::IncidentPlaybook => {
            InputResolution::action(InputAction::IncidentPlaybookDown)
        }
        KeyCode::Enter if overlay == Overlay::IncidentPlaybook => {
            InputResolution::action(InputAction::IncidentPlaybookNavigate)
        }
        _ => InputResolution::consumed_without_action(),
    }
}

fn resolve_global_key(key: &KeyEvent) -> InputResolution {
    match key.code {
        KeyCode::Char('c') if key.ctrl() => InputResolution::action(InputAction::Quit),
        KeyCode::Char('q') => InputResolution::action(InputAction::Quit),
        KeyCode::Escape => InputResolution::action(InputAction::BackOrQuit),
        KeyCode::Char(c @ '1'..='7') => Screen::from_number(c as u8 - b'0')
            .map_or_else(InputResolution::passthrough, |screen| {
                InputResolution::action(InputAction::Navigate(screen))
            }),
        KeyCode::Char('[') => InputResolution::action(InputAction::NavigatePrev),
        KeyCode::Char(']') => InputResolution::action(InputAction::NavigateNext),
        KeyCode::Char('?') => InputResolution::action(InputAction::OpenOverlay(Overlay::Help)),
        KeyCode::Char('v') => InputResolution::action(InputAction::OpenOverlay(Overlay::Voi)),
        KeyCode::Char('p') if key.ctrl() => {
            InputResolution::action(InputAction::OpenOverlay(Overlay::CommandPalette))
        }
        KeyCode::Char(':') => {
            InputResolution::action(InputAction::OpenOverlay(Overlay::CommandPalette))
        }
        KeyCode::Char('b') => InputResolution::action(InputAction::JumpBallast),
        KeyCode::Char('r') => InputResolution::action(InputAction::ForceRefresh),
        KeyCode::Char('!') => InputResolution::action(InputAction::IncidentShowPlaybook),
        KeyCode::Char('x') => InputResolution::action(InputAction::IncidentQuickRelease),
        _ => InputResolution::passthrough(),
    }
}

fn match_score(action: &PaletteAction, query: &str) -> Option<u8> {
    let id = normalize(action.id);
    let title = normalize(action.title);
    let shortcut = normalize(action.shortcut);

    if id == query {
        return Some(70);
    }
    if title == query {
        return Some(60);
    }
    if shortcut == query {
        return Some(50);
    }
    if id.starts_with(query) {
        return Some(40);
    }
    if title.starts_with(query) {
        return Some(30);
    }
    if id.contains(query) {
        return Some(20);
    }
    if title.contains(query) {
        return Some(10);
    }
    if is_fuzzy_subsequence(&id, query) || is_fuzzy_subsequence(&title, query) {
        return Some(5);
    }

    None
}

fn normalize(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn is_fuzzy_subsequence(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let mut needle_chars = needle.chars();
    let Some(mut wanted) = needle_chars.next() else {
        return true;
    };

    for ch in haystack.chars() {
        if ch == wanted {
            match needle_chars.next() {
                Some(next) => wanted = next,
                None => return true,
            }
        }
    }

    false
}

fn overlay_help(overlay: Overlay) -> ContextualHelp {
    match overlay {
        Overlay::CommandPalette => ContextualHelp {
            title: "Command Palette",
            screen_hint: "Type to filter actions by ID/title.",
            bindings: vec![
                HelpBinding {
                    keys: "Esc",
                    description: "Close command palette",
                },
                HelpBinding {
                    keys: "Ctrl-P",
                    description: "Toggle command palette",
                },
                HelpBinding {
                    keys: "Enter",
                    description: "Execute highlighted action",
                },
            ],
        },
        Overlay::Help => ContextualHelp {
            title: "Help Overlay",
            screen_hint: "Shows global and contextual bindings.",
            bindings: vec![
                HelpBinding {
                    keys: "Esc",
                    description: "Close help overlay",
                },
                HelpBinding {
                    keys: "?",
                    description: "Toggle help overlay",
                },
            ],
        },
        Overlay::Voi => ContextualHelp {
            title: "VOI Overlay",
            screen_hint: "Value-of-information scheduler details.",
            bindings: vec![
                HelpBinding {
                    keys: "Esc",
                    description: "Close VOI overlay",
                },
                HelpBinding {
                    keys: "v",
                    description: "Toggle VOI overlay",
                },
            ],
        },
        Overlay::Confirmation(_) => ContextualHelp {
            title: "Confirmation Overlay",
            screen_hint: "Mutating actions require explicit confirmation.",
            bindings: vec![
                HelpBinding {
                    keys: "Esc",
                    description: "Cancel confirmation",
                },
                HelpBinding {
                    keys: "Enter",
                    description: "Confirm action",
                },
            ],
        },
        Overlay::IncidentPlaybook => ContextualHelp {
            title: "Incident Playbook",
            screen_hint: "Guided triage steps ordered by urgency.",
            bindings: vec![
                HelpBinding {
                    keys: "j/k or Up/Down",
                    description: "Navigate playbook steps",
                },
                HelpBinding {
                    keys: "Enter",
                    description: "Jump to selected step's screen",
                },
                HelpBinding {
                    keys: "Esc",
                    description: "Close playbook",
                },
                HelpBinding {
                    keys: "!",
                    description: "Toggle playbook",
                },
            ],
        },
    }
}

fn screen_help(screen: Screen) -> ContextualHelp {
    let mut bindings = Vec::with_capacity(GLOBAL_HELP_BINDINGS.len() + 1);
    bindings.extend_from_slice(&GLOBAL_HELP_BINDINGS);
    bindings.push(HelpBinding {
        keys: "screen",
        description: screen_hint(screen),
    });

    ContextualHelp {
        title: "Global Navigation",
        screen_hint: screen_hint(screen),
        bindings,
    }
}

const GLOBAL_HELP_BINDINGS: [HelpBinding; 13] = [
    HelpBinding {
        keys: "1..7",
        description: "Jump directly to screen",
    },
    HelpBinding {
        keys: "[ / ]",
        description: "Navigate previous/next screen",
    },
    HelpBinding {
        keys: "Esc",
        description: "Back (or quit when history is empty)",
    },
    HelpBinding {
        keys: "q",
        description: "Quit dashboard",
    },
    HelpBinding {
        keys: "Ctrl-C",
        description: "Immediate quit",
    },
    HelpBinding {
        keys: "Ctrl-P or :",
        description: "Open command palette",
    },
    HelpBinding {
        keys: "?",
        description: "Open help overlay",
    },
    HelpBinding {
        keys: "v",
        description: "Toggle VOI overlay",
    },
    HelpBinding {
        keys: "b",
        description: "Jump to Ballast screen",
    },
    HelpBinding {
        keys: "r",
        description: "Force data refresh",
    },
    HelpBinding {
        keys: "!",
        description: "Show incident triage playbook",
    },
    HelpBinding {
        keys: "x",
        description: "Quick-release ballast (incident shortcut)",
    },
    HelpBinding {
        keys: "status",
        description: "Overlay keys consume input before screen keys",
    },
];

const PALETTE_ACTIONS: [PaletteAction; 33] = [
    PaletteAction {
        id: "nav.overview",
        title: "Go to Overview",
        shortcut: "1",
        action: InputAction::Navigate(Screen::Overview),
    },
    PaletteAction {
        id: "nav.timeline",
        title: "Go to Timeline",
        shortcut: "2",
        action: InputAction::Navigate(Screen::Timeline),
    },
    PaletteAction {
        id: "nav.explainability",
        title: "Go to Explainability",
        shortcut: "3",
        action: InputAction::Navigate(Screen::Explainability),
    },
    PaletteAction {
        id: "nav.candidates",
        title: "Go to Candidates",
        shortcut: "4",
        action: InputAction::Navigate(Screen::Candidates),
    },
    PaletteAction {
        id: "nav.ballast",
        title: "Go to Ballast",
        shortcut: "5",
        action: InputAction::Navigate(Screen::Ballast),
    },
    PaletteAction {
        id: "nav.logs",
        title: "Go to Log Search",
        shortcut: "6",
        action: InputAction::Navigate(Screen::LogSearch),
    },
    PaletteAction {
        id: "nav.diagnostics",
        title: "Go to Diagnostics",
        shortcut: "7",
        action: InputAction::Navigate(Screen::Diagnostics),
    },
    PaletteAction {
        id: "nav.prev",
        title: "Previous screen",
        shortcut: "[",
        action: InputAction::NavigatePrev,
    },
    PaletteAction {
        id: "nav.next",
        title: "Next screen",
        shortcut: "]",
        action: InputAction::NavigateNext,
    },
    PaletteAction {
        id: "overlay.help",
        title: "Open help overlay",
        shortcut: "?",
        action: InputAction::OpenOverlay(Overlay::Help),
    },
    PaletteAction {
        id: "overlay.voi",
        title: "Open VOI overlay",
        shortcut: "v",
        action: InputAction::OpenOverlay(Overlay::Voi),
    },
    PaletteAction {
        id: "overlay.palette",
        title: "Open command palette",
        shortcut: "Ctrl-P / :",
        action: InputAction::OpenOverlay(Overlay::CommandPalette),
    },
    PaletteAction {
        id: "action.refresh",
        title: "Force refresh",
        shortcut: "r",
        action: InputAction::ForceRefresh,
    },
    PaletteAction {
        id: "action.jump_ballast",
        title: "Jump to ballast quick-actions",
        shortcut: "b",
        action: InputAction::JumpBallast,
    },
    PaletteAction {
        id: "action.quit",
        title: "Quit dashboard",
        shortcut: "q",
        action: InputAction::Quit,
    },
    PaletteAction {
        id: "pref.start.overview",
        title: "Set default start screen: Overview",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::Overview),
    },
    PaletteAction {
        id: "pref.start.timeline",
        title: "Set default start screen: Timeline",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::Timeline),
    },
    PaletteAction {
        id: "pref.start.explainability",
        title: "Set default start screen: Explainability",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::Explainability),
    },
    PaletteAction {
        id: "pref.start.candidates",
        title: "Set default start screen: Candidates",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::Candidates),
    },
    PaletteAction {
        id: "pref.start.ballast",
        title: "Set default start screen: Ballast",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::Ballast),
    },
    PaletteAction {
        id: "pref.start.logs",
        title: "Set default start screen: Log Search",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::LogSearch),
    },
    PaletteAction {
        id: "pref.start.diagnostics",
        title: "Set default start screen: Diagnostics",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::Diagnostics),
    },
    PaletteAction {
        id: "pref.start.remember",
        title: "Set default start screen: Remember Last",
        shortcut: "prefs",
        action: InputAction::SetStartScreen(StartScreen::Remember),
    },
    PaletteAction {
        id: "pref.density.compact",
        title: "Set density: Compact",
        shortcut: "prefs",
        action: InputAction::SetDensity(DensityMode::Compact),
    },
    PaletteAction {
        id: "pref.density.comfortable",
        title: "Set density: Comfortable",
        shortcut: "prefs",
        action: InputAction::SetDensity(DensityMode::Comfortable),
    },
    PaletteAction {
        id: "pref.hints.full",
        title: "Set hints: Full",
        shortcut: "prefs",
        action: InputAction::SetHintVerbosity(HintVerbosity::Full),
    },
    PaletteAction {
        id: "pref.hints.minimal",
        title: "Set hints: Minimal",
        shortcut: "prefs",
        action: InputAction::SetHintVerbosity(HintVerbosity::Minimal),
    },
    PaletteAction {
        id: "pref.hints.off",
        title: "Set hints: Off",
        shortcut: "prefs",
        action: InputAction::SetHintVerbosity(HintVerbosity::Off),
    },
    PaletteAction {
        id: "pref.reset.persisted",
        title: "Reset session to persisted preferences",
        shortcut: "prefs",
        action: InputAction::ResetPreferencesToPersisted,
    },
    PaletteAction {
        id: "pref.reset.defaults",
        title: "Revert preferences to defaults",
        shortcut: "prefs",
        action: InputAction::RevertPreferencesToDefaults,
    },
    // ── Incident workflow shortcuts (bd-xzt.3.9) ──
    PaletteAction {
        id: "incident.playbook",
        title: "Show incident triage playbook",
        shortcut: "!",
        action: InputAction::IncidentShowPlaybook,
    },
    PaletteAction {
        id: "incident.quick-release",
        title: "Quick-release ballast (incident)",
        shortcut: "x",
        action: InputAction::IncidentQuickRelease,
    },
    PaletteAction {
        id: "incident.triage",
        title: "Start incident triage (overview)",
        shortcut: "!",
        action: InputAction::IncidentShowPlaybook,
    },
];

fn screen_hint(screen: Screen) -> &'static str {
    match screen {
        Screen::Overview => "Overview: pressure, trends, ballast, and counters",
        Screen::Timeline => "Timeline: event stream, filters, and event details",
        Screen::Explainability => "Explainability: policy rationale, vetoes, and evidence",
        Screen::Candidates => "Candidates: ranked reclaim targets and score factors",
        Screen::Ballast => "Ballast: inventory, release, and replenish controls",
        Screen::LogSearch => "Log Search: query JSONL/SQLite event records",
        Screen::Diagnostics => "Diagnostics: frame health and adapter/runtime telemetry",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use ftui_core::event::{KeyCode, KeyEvent, KeyEventKind, Modifiers};

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Press,
        }
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: Modifiers::CTRL,
            kind: KeyEventKind::Press,
        }
    }

    #[test]
    fn key_mapping_preserves_event() {
        let event = ctrl(KeyCode::Char('q'));

        let msg = map_key_event(event);
        match msg {
            DashboardMsg::Key(inner) => {
                assert_eq!(inner.code, KeyCode::Char('q'));
                assert!(inner.ctrl());
            }
            _ => panic!("expected key event"),
        }
    }

    #[test]
    fn global_keys_resolve_to_actions() {
        let ctx = InputContext::default();
        let nav = resolve_key_event(&key(KeyCode::Char('5')), ctx);
        let refresh = resolve_key_event(&key(KeyCode::Char('r')), ctx);
        let unknown = resolve_key_event(&key(KeyCode::Char('z')), ctx);

        assert_eq!(nav.action, Some(InputAction::Navigate(Screen::Ballast)));
        assert_eq!(refresh.action, Some(InputAction::ForceRefresh));
        assert!(!unknown.consumed);
        assert!(unknown.action.is_none());
    }

    #[test]
    fn overlay_precedence_consumes_unmapped_keys() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::Help),
        };
        let action = resolve_key_event(&key(KeyCode::Char('3')), ctx);
        assert!(action.consumed);
        assert!(action.action.is_none());
    }

    #[test]
    fn overlay_toggle_keys_resolve_when_same_overlay_active() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let action = resolve_key_event(&ctrl(KeyCode::Char('p')), ctx);
        assert_eq!(
            action.action,
            Some(InputAction::ToggleOverlay(Overlay::CommandPalette))
        );
    }

    #[test]
    fn command_palette_catalog_has_unique_ids() {
        let actions = command_palette_actions();
        let mut ids = HashSet::new();
        for action in actions {
            assert!(ids.insert(action.id), "duplicate action id: {}", action.id);
            assert!(resolve_palette_action(action.id).is_some());
        }
    }

    #[test]
    fn command_palette_search_empty_query_returns_catalog_prefix() {
        let top = search_palette_actions("", 4);
        assert_eq!(top.len(), 4);
        assert_eq!(top[0].id, "nav.overview");
        assert_eq!(top[1].id, "nav.timeline");
        assert_eq!(top[2].id, "nav.explainability");
        assert_eq!(top[3].id, "nav.candidates");
    }

    #[test]
    fn command_palette_search_prefers_exact_id_then_prefix() {
        let exact = search_palette_actions("nav.ballast", 3);
        assert_eq!(exact[0].id, "nav.ballast");

        let prefix = search_palette_actions("nav.", 3);
        assert_eq!(prefix[0].id, "nav.ballast");
        assert_eq!(prefix[1].id, "nav.candidates");
        assert_eq!(prefix[2].id, "nav.diagnostics");
    }

    #[test]
    fn command_palette_search_is_case_insensitive_and_stable() {
        let upper = search_palette_actions("OVERVIEW", 2);
        let mixed = search_palette_actions("OvErViEw", 2);

        assert!(!upper.is_empty());
        assert_eq!(upper[0].id, "nav.overview");
        assert_eq!(upper, mixed);
    }

    #[test]
    fn command_palette_search_respects_limit_and_zero_limit_is_empty() {
        let limited = search_palette_actions("nav", 2);
        assert_eq!(limited.len(), 2);

        let none = search_palette_actions("nav", 0);
        assert!(none.is_empty());
    }

    #[test]
    fn route_palette_query_returns_best_action() {
        assert_eq!(
            route_palette_query("nav.ballast"),
            Some(InputAction::Navigate(Screen::Ballast))
        );
        assert_eq!(route_palette_query("   "), None);
        assert_eq!(route_palette_query("definitely-unknown"), None);
    }

    #[test]
    fn route_palette_query_supports_fuzzy_subsequence() {
        assert_eq!(route_palette_query("jbal"), Some(InputAction::JumpBallast));
    }

    #[test]
    fn route_palette_query_matches_preference_actions() {
        assert_eq!(
            route_palette_query("pref.density.compact"),
            Some(InputAction::SetDensity(DensityMode::Compact))
        );
        assert_eq!(
            route_palette_query("pref.reset.defaults"),
            Some(InputAction::RevertPreferencesToDefaults)
        );
    }

    #[test]
    fn contextual_help_reflects_overlay_and_screen_context() {
        let help = contextual_help(InputContext {
            screen: Screen::Diagnostics,
            active_overlay: None,
        });
        assert_eq!(help.title, "Global Navigation");
        assert!(help.screen_hint.contains("frame health"));
        assert!(help.bindings.iter().any(|line| line.keys == "Ctrl-P or :"));

        let overlay_help = contextual_help(InputContext {
            screen: Screen::Diagnostics,
            active_overlay: Some(Overlay::Help),
        });
        assert_eq!(overlay_help.title, "Help Overlay");
        assert!(
            overlay_help
                .bindings
                .iter()
                .any(|line| line.description.contains("Close help overlay"))
        );
    }

    // ── Command palette key resolution tests ──

    #[test]
    fn palette_enter_resolves_to_execute() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let res = resolve_key_event(&key(KeyCode::Enter), ctx);
        assert_eq!(res.action, Some(InputAction::PaletteExecute));
        assert!(res.consumed);
    }

    #[test]
    fn palette_backspace_resolves_to_backspace() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let res = resolve_key_event(&key(KeyCode::Backspace), ctx);
        assert_eq!(res.action, Some(InputAction::PaletteBackspace));
    }

    #[test]
    fn palette_up_down_resolve_to_cursor() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let up = resolve_key_event(&key(KeyCode::Up), ctx);
        let down = resolve_key_event(&key(KeyCode::Down), ctx);
        assert_eq!(up.action, Some(InputAction::PaletteCursorUp));
        assert_eq!(down.action, Some(InputAction::PaletteCursorDown));
    }

    #[test]
    fn palette_char_resolves_to_type() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let res = resolve_key_event(&key(KeyCode::Char('n')), ctx);
        assert_eq!(res.action, Some(InputAction::PaletteType('n')));
        assert!(res.consumed);
    }

    #[test]
    fn palette_q_does_not_quit() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let res = resolve_key_event(&key(KeyCode::Char('q')), ctx);
        assert_eq!(res.action, Some(InputAction::PaletteType('q')));
    }

    #[test]
    fn palette_esc_still_closes() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let res = resolve_key_event(&key(KeyCode::Escape), ctx);
        assert_eq!(res.action, Some(InputAction::CloseOverlay));
    }

    #[test]
    fn palette_ctrl_c_still_quits() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::CommandPalette),
        };
        let res = resolve_key_event(&ctrl(KeyCode::Char('c')), ctx);
        assert_eq!(res.action, Some(InputAction::Quit));
    }

    // ── Confirmation overlay resolution ──

    #[test]
    fn confirmation_overlay_esc_closes() {
        let ctx = InputContext {
            screen: Screen::Ballast,
            active_overlay: Some(Overlay::Confirmation(
                crate::tui::model::ConfirmAction::BallastRelease,
            )),
        };
        let res = resolve_key_event(&key(KeyCode::Escape), ctx);
        assert_eq!(res.action, Some(InputAction::CloseOverlay));
        assert!(res.consumed);
    }

    #[test]
    fn confirmation_overlay_ctrl_c_quits() {
        let ctx = InputContext {
            screen: Screen::Ballast,
            active_overlay: Some(Overlay::Confirmation(
                crate::tui::model::ConfirmAction::BallastReleaseAll,
            )),
        };
        let res = resolve_key_event(&ctrl(KeyCode::Char('c')), ctx);
        assert_eq!(res.action, Some(InputAction::Quit));
    }

    #[test]
    fn confirmation_overlay_consumes_unmapped_keys() {
        let ctx = InputContext {
            screen: Screen::Ballast,
            active_overlay: Some(Overlay::Confirmation(
                crate::tui::model::ConfirmAction::BallastRelease,
            )),
        };
        let res = resolve_key_event(&key(KeyCode::Char('q')), ctx);
        assert!(res.consumed);
        assert!(res.action.is_none()); // consumed but no action
    }

    // ── Voi overlay resolution ──

    #[test]
    fn voi_overlay_v_toggles() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::Voi),
        };
        let res = resolve_key_event(&key(KeyCode::Char('v')), ctx);
        assert_eq!(res.action, Some(InputAction::ToggleOverlay(Overlay::Voi)));
    }

    #[test]
    fn voi_overlay_consumes_unmapped_keys() {
        let ctx = InputContext {
            screen: Screen::Overview,
            active_overlay: Some(Overlay::Voi),
        };
        let res = resolve_key_event(&key(KeyCode::Char('j')), ctx);
        assert!(res.consumed);
        assert!(res.action.is_none());
    }

    // ── All screen helps ──

    #[test]
    fn screen_help_covers_all_screens() {
        let screens = [
            Screen::Overview,
            Screen::Timeline,
            Screen::Explainability,
            Screen::Candidates,
            Screen::Ballast,
            Screen::LogSearch,
            Screen::Diagnostics,
        ];
        for screen in screens {
            let help = contextual_help(InputContext {
                screen,
                active_overlay: None,
            });
            assert_eq!(help.title, "Global Navigation");
            assert!(!help.screen_hint.is_empty());
            assert!(!help.bindings.is_empty());
        }
    }

    #[test]
    fn overlay_help_covers_all_overlays() {
        let overlays = [
            Overlay::CommandPalette,
            Overlay::Help,
            Overlay::Voi,
            Overlay::Confirmation(crate::tui::model::ConfirmAction::BallastRelease),
        ];
        for overlay in overlays {
            let help = contextual_help(InputContext {
                screen: Screen::Overview,
                active_overlay: Some(overlay),
            });
            assert!(!help.title.is_empty());
            assert!(!help.bindings.is_empty());
        }
    }

    // ── normalize edge cases ──

    #[test]
    fn normalize_trims_and_lowercases() {
        assert_eq!(super::normalize("  FoO  "), "foo");
        assert_eq!(super::normalize(""), "");
        assert_eq!(super::normalize("   "), "");
        assert_eq!(super::normalize("ALL_CAPS"), "all_caps");
    }

    // ── Fuzzy subsequence matching ──

    #[test]
    fn fuzzy_subsequence_empty_needle_matches() {
        assert!(super::is_fuzzy_subsequence("anything", ""));
    }

    #[test]
    fn fuzzy_subsequence_exact_match() {
        assert!(super::is_fuzzy_subsequence("hello", "hello"));
    }

    #[test]
    fn fuzzy_subsequence_partial_match() {
        assert!(super::is_fuzzy_subsequence("nav.ballast", "nbl"));
        assert!(super::is_fuzzy_subsequence("nav.diagnostics", "ndi"));
    }

    #[test]
    fn fuzzy_subsequence_no_match() {
        assert!(!super::is_fuzzy_subsequence("abc", "abd"));
        assert!(!super::is_fuzzy_subsequence("short", "shortx"));
    }

    // ── match_score tiers ──

    #[test]
    fn match_score_exact_id_is_highest() {
        let action = &super::PALETTE_ACTIONS[0]; // nav.overview
        let score = super::match_score(action, "nav.overview").unwrap();
        assert_eq!(score, 70);
    }

    #[test]
    fn match_score_exact_title() {
        let action = &super::PALETTE_ACTIONS[0]; // title: "Go to Overview"
        let score = super::match_score(action, "go to overview").unwrap();
        assert_eq!(score, 60);
    }

    #[test]
    fn match_score_exact_shortcut() {
        let action = &super::PALETTE_ACTIONS[0]; // shortcut: "1"
        let score = super::match_score(action, "1").unwrap();
        assert_eq!(score, 50);
    }

    #[test]
    fn match_score_id_prefix() {
        let action = &super::PALETTE_ACTIONS[0]; // nav.overview
        let score = super::match_score(action, "nav.").unwrap();
        assert_eq!(score, 40);
    }

    #[test]
    fn match_score_title_prefix() {
        let action = &super::PALETTE_ACTIONS[0]; // "Go to Overview"
        let score = super::match_score(action, "go to").unwrap();
        assert_eq!(score, 30);
    }

    #[test]
    fn match_score_id_substring() {
        let action = &super::PALETTE_ACTIONS[0]; // nav.overview
        let score = super::match_score(action, "overview").unwrap();
        // "overview" is id substring (20) AND title substring (10). ID sub wins.
        assert_eq!(score, 20);
    }

    #[test]
    fn match_score_title_substring() {
        let action = &super::PALETTE_ACTIONS[14]; // action.quit, title: "Quit dashboard"
        let score = super::match_score(action, "dashboard").unwrap();
        assert_eq!(score, 10);
    }

    #[test]
    fn match_score_fuzzy_subsequence() {
        let action = &super::PALETTE_ACTIONS[0]; // nav.overview
        let score = super::match_score(action, "nvo").unwrap();
        assert_eq!(score, 5);
    }

    #[test]
    fn match_score_no_match_returns_none() {
        let action = &super::PALETTE_ACTIONS[0];
        assert!(super::match_score(action, "zzzzz").is_none());
    }

    // ── Global key coverage ──

    #[test]
    fn bracket_keys_navigate_prev_next() {
        let ctx = InputContext::default();
        let prev = resolve_key_event(&key(KeyCode::Char('[')), ctx);
        let next = resolve_key_event(&key(KeyCode::Char(']')), ctx);
        assert_eq!(prev.action, Some(InputAction::NavigatePrev));
        assert_eq!(next.action, Some(InputAction::NavigateNext));
    }

    #[test]
    fn b_key_jumps_to_ballast() {
        let ctx = InputContext::default();
        let res = resolve_key_event(&key(KeyCode::Char('b')), ctx);
        assert_eq!(res.action, Some(InputAction::JumpBallast));
    }

    #[test]
    fn colon_opens_palette() {
        let ctx = InputContext::default();
        let res = resolve_key_event(&key(KeyCode::Char(':')), ctx);
        assert_eq!(
            res.action,
            Some(InputAction::OpenOverlay(Overlay::CommandPalette))
        );
    }

    #[test]
    fn question_mark_opens_help() {
        let ctx = InputContext::default();
        let res = resolve_key_event(&key(KeyCode::Char('?')), ctx);
        assert_eq!(res.action, Some(InputAction::OpenOverlay(Overlay::Help)));
    }

    #[test]
    fn number_keys_navigate_to_all_screens() {
        let ctx = InputContext::default();
        for (n, screen) in [
            ('1', Screen::Overview),
            ('2', Screen::Timeline),
            ('3', Screen::Explainability),
            ('4', Screen::Candidates),
            ('5', Screen::Ballast),
            ('6', Screen::LogSearch),
            ('7', Screen::Diagnostics),
        ] {
            let res = resolve_key_event(&key(KeyCode::Char(n)), ctx);
            assert_eq!(res.action, Some(InputAction::Navigate(screen)));
        }
    }

    #[test]
    fn unknown_key_is_passthrough() {
        let ctx = InputContext::default();
        let res = resolve_key_event(&key(KeyCode::Char('z')), ctx);
        assert!(!res.consumed);
        assert!(res.action.is_none());
    }

    // ── Palette search stable ordering ──

    #[test]
    fn palette_search_results_are_deterministic() {
        let first = search_palette_actions("nav", 15);
        let second = search_palette_actions("nav", 15);
        assert_eq!(
            first.iter().map(|a| a.id).collect::<Vec<_>>(),
            second.iter().map(|a| a.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn palette_search_with_no_match_returns_empty() {
        let results = search_palette_actions("xyzzy123", 10);
        assert!(results.is_empty());
    }
}
