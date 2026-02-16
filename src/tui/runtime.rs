//! Canonical runtime entrypoint for dashboard execution.
//!
//! The new cockpit path uses ftui-tty's [`TtyBackend`] for panic-safe terminal
//! lifecycle management and native event polling. The legacy fallback retains
//! its own cleanup logic.

#![allow(missing_docs)]

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ftui_backend::BackendEventSource;
use ftui_core::event::{Event, KeyEventKind};
use ftui_tty::{TtyBackend, TtySessionOptions};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::model::{
    DashboardCmd, DashboardModel, DashboardMsg, NotificationLevel, Overlay, PreferenceAction,
    PreferenceProfileMode, Screen,
};
use super::preferences::{self, ResolvedPreferences, UserPreferences};
use super::telemetry::{NullTelemetryHook, TelemetryHook, TelemetrySample};
use super::theme::AccessibilityProfile;
use super::{input, render, update};
use crate::cli::dashboard::{self, DashboardConfig as LegacyDashboardConfig};
use crate::daemon::self_monitor::DaemonState;

/// ANSI escape sequences for screen control.
const CLEAR_SCREEN: &[u8] = b"\x1b[2J";
const CURSOR_HOME: &[u8] = b"\x1b[H";

/// Which runtime path to execute.
///
/// `NewCockpit` is the canonical modern entrypoint. During the migration it can
/// intentionally delegate to legacy rendering while we wire model/update/view
/// internals behind the same external contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DashboardRuntimeMode {
    #[default]
    NewCockpit,
    LegacyFallback,
}

/// Runtime configuration shared by both new and legacy dashboard executors.
#[derive(Debug, Clone)]
pub struct DashboardRuntimeConfig {
    pub state_file: PathBuf,
    pub refresh: Duration,
    pub monitor_paths: Vec<PathBuf>,
    pub mode: DashboardRuntimeMode,
}

impl DashboardRuntimeConfig {
    /// Build the underlying legacy dashboard config.
    #[must_use]
    pub fn as_legacy_config(&self) -> LegacyDashboardConfig {
        LegacyDashboardConfig {
            state_file: self.state_file.clone(),
            refresh: self.refresh,
            monitor_paths: self.monitor_paths.clone(),
        }
    }
}

/// Runtime-owned preference profile state.
struct PreferenceRuntimeState {
    path: Option<PathBuf>,
    prefs: UserPreferences,
    profile_mode: PreferenceProfileMode,
    env_accessibility: AccessibilityProfile,
    telemetry_hook: Box<dyn TelemetryHook + Send>,
}

impl PreferenceRuntimeState {
    fn load() -> (Self, Option<String>) {
        Self::load_with_hook(Box::<NullTelemetryHook>::default())
    }

    fn load_with_hook(telemetry_hook: Box<dyn TelemetryHook + Send>) -> (Self, Option<String>) {
        Self::load_from_path_with_hook(preferences::default_preferences_path(), telemetry_hook)
    }

    fn load_from_path_with_hook(
        path: Option<PathBuf>,
        telemetry_hook: Box<dyn TelemetryHook + Send>,
    ) -> (Self, Option<String>) {
        let env_accessibility = AccessibilityProfile::from_environment();
        let mut warning = None;
        let (prefs, profile_mode) = path.as_deref().map_or_else(
            || (UserPreferences::default(), PreferenceProfileMode::Defaults),
            |path| match preferences::load(path) {
                preferences::LoadOutcome::Loaded { prefs, report } => {
                    if !report.is_clean() {
                        warning = Some("preferences loaded with validation warnings".to_string());
                    }
                    (prefs, PreferenceProfileMode::Persisted)
                }
                preferences::LoadOutcome::Missing => {
                    (UserPreferences::default(), PreferenceProfileMode::Defaults)
                }
                preferences::LoadOutcome::Corrupt { details, .. } => {
                    warning = Some(format!("preferences corrupted; using defaults: {details}"));
                    (UserPreferences::default(), PreferenceProfileMode::Defaults)
                }
                preferences::LoadOutcome::IoError { details, .. } => {
                    warning = Some(format!(
                        "preferences read failed; using defaults: {details}"
                    ));
                    (UserPreferences::default(), PreferenceProfileMode::Defaults)
                }
            },
        );
        (
            Self {
                path,
                prefs,
                profile_mode,
                env_accessibility,
                telemetry_hook,
            },
            warning,
        )
    }

    fn resolved(&self, last_screen: Option<Screen>) -> ResolvedPreferences {
        ResolvedPreferences::resolve(
            &self.prefs,
            self.env_accessibility.contrast,
            self.env_accessibility.motion,
            last_screen,
        )
    }

    fn apply_to_model(
        &self,
        model: &mut DashboardModel,
        apply_start_screen: bool,
        apply_help_overlay: bool,
    ) {
        let resolved = self.resolved(Some(model.screen));
        model.set_preference_profile(
            self.prefs.start_screen,
            resolved.density,
            resolved.hint_verbosity,
            self.profile_mode,
        );
        if apply_start_screen {
            model.screen = resolved.start_screen;
            model.screen_history.clear();
        }
        if apply_help_overlay && resolved.show_help_on_start && model.active_overlay.is_none() {
            model.active_overlay = Some(Overlay::Help);
        }
    }

    fn persist(&self) -> io::Result<()> {
        self.path.as_deref().map_or(Ok(()), |path| {
            preferences::save(&self.prefs, path).map(|_| ())
        })
    }

    fn execute_action(
        &mut self,
        action: PreferenceAction,
        model: &mut DashboardModel,
    ) -> io::Result<String> {
        let message = match action {
            PreferenceAction::SetStartScreen(start_screen) => {
                self.prefs.start_screen = start_screen;
                self.profile_mode = PreferenceProfileMode::SessionOverride;
                self.persist()?;
                self.apply_to_model(model, true, false);
                format!(
                    "default start screen set to {}",
                    start_screen_label(start_screen)
                )
            }
            PreferenceAction::SetDensity(density) => {
                self.prefs.density = density;
                self.profile_mode = PreferenceProfileMode::SessionOverride;
                self.persist()?;
                self.apply_to_model(model, false, false);
                format!("density set to {density}")
            }
            PreferenceAction::SetHintVerbosity(hint_verbosity) => {
                self.prefs.hint_verbosity = hint_verbosity;
                self.profile_mode = PreferenceProfileMode::SessionOverride;
                self.persist()?;
                self.apply_to_model(model, false, false);
                format!("hint verbosity set to {hint_verbosity}")
            }
            PreferenceAction::ResetToPersisted => {
                if let Some(path) = self.path.as_deref() {
                    match preferences::load(path) {
                        preferences::LoadOutcome::Loaded { prefs, .. } => {
                            self.prefs = prefs;
                            self.profile_mode = PreferenceProfileMode::Persisted;
                            self.apply_to_model(model, true, false);
                            "reloaded persisted preferences".to_string()
                        }
                        preferences::LoadOutcome::Missing => {
                            self.prefs = UserPreferences::default();
                            self.profile_mode = PreferenceProfileMode::Defaults;
                            self.apply_to_model(model, true, false);
                            "no persisted preferences found; defaults applied".to_string()
                        }
                        preferences::LoadOutcome::Corrupt { details, .. } => {
                            self.prefs = UserPreferences::default();
                            self.profile_mode = PreferenceProfileMode::Defaults;
                            self.apply_to_model(model, true, false);
                            format!("persisted preferences corrupted; defaults applied: {details}")
                        }
                        preferences::LoadOutcome::IoError { details, .. } => {
                            self.prefs = UserPreferences::default();
                            self.profile_mode = PreferenceProfileMode::Defaults;
                            self.apply_to_model(model, true, false);
                            format!("preferences read failed; defaults applied: {details}")
                        }
                    }
                } else {
                    self.prefs = UserPreferences::default();
                    self.profile_mode = PreferenceProfileMode::Defaults;
                    self.apply_to_model(model, true, false);
                    "preferences path unavailable; defaults applied".to_string()
                }
            }
            PreferenceAction::RevertToDefaults => {
                self.prefs = UserPreferences::default();
                self.profile_mode = PreferenceProfileMode::Defaults;
                self.persist()?;
                self.apply_to_model(model, true, false);
                "reverted preferences to defaults".to_string()
            }
        };
        self.record_action_outcome(action, "ok", None);
        Ok(message)
    }

    fn record_action_failure(&mut self, action: PreferenceAction, err: &io::Error) {
        let error = err.to_string();
        self.record_action_outcome(action, "error", Some(error.as_str()));
    }

    fn record_action_outcome(
        &mut self,
        action: PreferenceAction,
        result: &str,
        error: Option<&str>,
    ) {
        let profile_hash =
            preference_profile_hash(&self.prefs).unwrap_or_else(|_| String::from("unavailable"));
        let detail = json!({
            "actor": "tui-dashboard",
            "action": preference_action_kind(action),
            "target": preference_action_target(action),
            "result": result,
            "profile_mode": preference_profile_mode_label(self.profile_mode),
            "schema_version": self.prefs.schema_version,
            "profile_hash": profile_hash,
            "error": error,
        })
        .to_string();
        self.telemetry_hook.record(TelemetrySample::new(
            "dashboard.preferences",
            preference_action_kind(action),
            detail,
        ));
    }
}

fn start_screen_label(start_screen: preferences::StartScreen) -> &'static str {
    match start_screen {
        preferences::StartScreen::Overview => "overview",
        preferences::StartScreen::Timeline => "timeline",
        preferences::StartScreen::Explainability => "explainability",
        preferences::StartScreen::Candidates => "candidates",
        preferences::StartScreen::Ballast => "ballast",
        preferences::StartScreen::LogSearch => "log_search",
        preferences::StartScreen::Diagnostics => "diagnostics",
        preferences::StartScreen::Remember => "remember",
    }
}

fn preference_profile_mode_label(mode: PreferenceProfileMode) -> &'static str {
    match mode {
        PreferenceProfileMode::Defaults => "defaults",
        PreferenceProfileMode::Persisted => "persisted",
        PreferenceProfileMode::SessionOverride => "session_override",
    }
}

fn preference_action_kind(action: PreferenceAction) -> &'static str {
    match action {
        PreferenceAction::SetStartScreen(_) => "set_start_screen",
        PreferenceAction::SetDensity(_) => "set_density",
        PreferenceAction::SetHintVerbosity(_) => "set_hint_verbosity",
        PreferenceAction::ResetToPersisted => "reset_to_persisted",
        PreferenceAction::RevertToDefaults => "revert_to_defaults",
    }
}

fn preference_action_target(action: PreferenceAction) -> String {
    match action {
        PreferenceAction::SetStartScreen(start_screen) => {
            format!("start_screen={}", start_screen_label(start_screen))
        }
        PreferenceAction::SetDensity(density) => format!("density={density}"),
        PreferenceAction::SetHintVerbosity(hint_verbosity) => {
            format!("hint_verbosity={hint_verbosity}")
        }
        PreferenceAction::ResetToPersisted => String::from("profile=persisted"),
        PreferenceAction::RevertToDefaults => String::from("profile=defaults"),
    }
}

fn preference_profile_hash(prefs: &UserPreferences) -> Result<String, serde_json::Error> {
    let encoded = serde_json::to_vec(prefs)?;
    let digest = Sha256::digest(encoded);
    Ok(format!("{digest:x}"))
}

/// Run dashboard runtime via one canonical entrypoint.
///
/// All `sbh dashboard` invocations should flow through this function while the
/// migration is in progress so runtime selection stays deterministic and testable.
///
/// # Errors
/// Returns I/O errors from terminal/event/renderer layers.
pub fn run_dashboard(config: &DashboardRuntimeConfig) -> io::Result<()> {
    match config.mode {
        DashboardRuntimeMode::NewCockpit => run_new_cockpit(config),
        DashboardRuntimeMode::LegacyFallback => run_legacy_fallback(config),
    }
}

fn run_new_cockpit(config: &DashboardRuntimeConfig) -> io::Result<()> {
    // TtyBackend handles raw mode + alternate screen with RAII cleanup.
    // Drop restores the terminal even on panic or early return.
    let options = TtySessionOptions {
        alternate_screen: true,
        ..Default::default()
    };
    let mut backend = TtyBackend::open(80, 24, options)?;

    let (cols, rows) = backend.size()?;
    let mut model = DashboardModel::new(
        config.state_file.clone(),
        config.monitor_paths.clone(),
        config.refresh,
        (cols, rows),
    );
    let (mut preference_state, preference_warning) = PreferenceRuntimeState::load();
    preference_state.apply_to_model(&mut model, true, true);

    // Pending notification auto-dismiss timers: (notification_id, expires_at).
    let mut notification_timers: Vec<(u64, Instant)> = Vec::new();
    if let Some(warning) = preference_warning {
        let id = model.push_notification(NotificationLevel::Warning, warning);
        notification_timers.push((id, Instant::now() + Duration::from_secs(8)));
    }

    // Initial data fetch.
    let initial = read_state_file(&config.state_file);
    update::update(&mut model, DashboardMsg::DataUpdate(initial));

    let mut stdout = io::stdout();

    loop {
        // Render current frame.
        let frame = render::render(&model);
        stdout.write_all(CLEAR_SCREEN)?;
        stdout.write_all(CURSOR_HOME)?;
        stdout.write_all(frame.as_bytes())?;
        stdout.flush()?;

        // Check for expired notification timers.
        let now = Instant::now();
        let expired: Vec<u64> = notification_timers
            .iter()
            .filter(|(_, deadline)| now >= *deadline)
            .map(|(id, _)| *id)
            .collect();
        notification_timers.retain(|(_, deadline)| now < *deadline);
        for id in expired {
            update::update(&mut model, DashboardMsg::NotificationExpired(id));
        }

        // Poll for terminal events (timeout = refresh interval).
        let poll_timeout = model.refresh;
        if backend.poll_event(poll_timeout)? {
            // Drain all available events.
            while let Some(event) = backend.read_event()? {
                let cmd = match event {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        update::update(&mut model, input::map_key_event(key))
                    }
                    Event::Resize { width, height } => update::update(
                        &mut model,
                        DashboardMsg::Resize {
                            cols: width,
                            rows: height,
                        },
                    ),
                    _ => DashboardCmd::None,
                };
                execute_cmd(
                    &mut model,
                    &config.state_file,
                    cmd,
                    &mut notification_timers,
                    &mut preference_state,
                );

                if model.quit {
                    break;
                }
            }
        } else {
            // Timeout = tick (periodic refresh).
            let cmd = update::update(&mut model, DashboardMsg::Tick);
            execute_cmd(
                &mut model,
                &config.state_file,
                cmd,
                &mut notification_timers,
                &mut preference_state,
            );
        }

        if model.quit {
            break;
        }
    }

    // TtyBackend Drop handles cleanup.
    Ok(())
}

/// Execute a command returned by the update function.
///
/// This is the bridge between the pure state machine and the I/O world.
fn execute_cmd(
    model: &mut DashboardModel,
    state_file: &Path,
    cmd: DashboardCmd,
    timers: &mut Vec<(u64, Instant)>,
    preference_state: &mut PreferenceRuntimeState,
) {
    match cmd {
        DashboardCmd::None | DashboardCmd::ScheduleTick(_) | DashboardCmd::FetchTelemetry => {}
        DashboardCmd::FetchData => {
            let state = read_state_file(state_file);
            let inner_cmd = update::update(model, DashboardMsg::DataUpdate(state));
            execute_cmd(model, state_file, inner_cmd, timers, preference_state);
        }
        DashboardCmd::Quit => {
            model.quit = true;
        }
        DashboardCmd::Batch(cmds) => {
            for c in cmds {
                execute_cmd(model, state_file, c, timers, preference_state);
            }
        }
        DashboardCmd::ScheduleNotificationExpiry { id, after } => {
            timers.push((id, Instant::now() + after));
        }
        DashboardCmd::ExecutePreferenceAction(action) => {
            match preference_state.execute_action(action, model) {
                Ok(message) => {
                    let id = model.push_notification(NotificationLevel::Info, message);
                    timers.push((id, Instant::now() + Duration::from_secs(8)));
                }
                Err(err) => {
                    preference_state.record_action_failure(action, &err);
                    let id = model.push_notification(
                        NotificationLevel::Error,
                        format!("preference update failed: {err}"),
                    );
                    timers.push((id, Instant::now() + Duration::from_secs(10)));
                }
            }
        }
    }
}

/// Read and parse the daemon state file. Returns `None` on any error.
fn read_state_file(path: &Path) -> Option<Box<DaemonState>> {
    let content = std::fs::read_to_string(path).ok()?;
    let state: DaemonState = serde_json::from_str(&content).ok()?;
    Some(Box::new(state))
}

fn run_legacy_fallback(config: &DashboardRuntimeConfig) -> io::Result<()> {
    dashboard::run(&config.as_legacy_config())
}

#[cfg(test)]
mod tests {
    use super::super::preferences::{DensityMode, HintVerbosity, StartScreen, UserPreferences};
    use super::super::telemetry::{DataSource, NullTelemetryHook, TelemetryHook, TelemetrySample};
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn test_model() -> DashboardModel {
        DashboardModel::new(
            PathBuf::from("/tmp/state.json"),
            vec![],
            Duration::from_secs(1),
            (120, 40),
        )
    }

    #[derive(Debug)]
    struct CapturingTelemetryHook {
        samples: Arc<Mutex<Vec<TelemetrySample>>>,
    }

    impl TelemetryHook for CapturingTelemetryHook {
        fn record(&mut self, sample: TelemetrySample) {
            self.samples
                .lock()
                .expect("capture telemetry sample")
                .push(sample);
        }
    }

    fn capture_hook() -> (
        Box<dyn TelemetryHook + Send>,
        Arc<Mutex<Vec<TelemetrySample>>>,
    ) {
        let samples = Arc::new(Mutex::new(Vec::new()));
        let hook = CapturingTelemetryHook {
            samples: Arc::clone(&samples),
        };
        (Box::new(hook), samples)
    }

    #[test]
    fn runtime_mode_defaults_to_new_cockpit() {
        assert_eq!(
            DashboardRuntimeMode::default(),
            DashboardRuntimeMode::NewCockpit
        );
    }

    #[test]
    fn runtime_config_maps_to_legacy_config() {
        let cfg = DashboardRuntimeConfig {
            state_file: PathBuf::from("/tmp/state.json"),
            refresh: Duration::from_millis(750),
            monitor_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/data/projects")],
            mode: DashboardRuntimeMode::LegacyFallback,
        };

        let legacy = cfg.as_legacy_config();
        assert_eq!(legacy.state_file, PathBuf::from("/tmp/state.json"));
        assert_eq!(legacy.refresh, Duration::from_millis(750));
        assert_eq!(legacy.monitor_paths.len(), 2);
    }

    #[test]
    fn preference_state_loads_persisted_profile_and_applies_startup_screen() {
        let dir = TempDir::new().expect("temp dir");
        let pref_path = dir.path().join("preferences.json");
        let persisted = UserPreferences {
            start_screen: StartScreen::Ballast,
            density: DensityMode::Compact,
            hint_verbosity: HintVerbosity::Off,
            ..UserPreferences::default()
        };
        preferences::save(&persisted, &pref_path).expect("save prefs");

        let (state, warning) = PreferenceRuntimeState::load_from_path_with_hook(
            Some(pref_path),
            Box::<NullTelemetryHook>::default(),
        );
        assert!(warning.is_none());
        assert_eq!(state.profile_mode, PreferenceProfileMode::Persisted);

        let mut model = test_model();
        assert_eq!(model.screen, Screen::Overview);
        state.apply_to_model(&mut model, true, false);
        assert_eq!(model.screen, Screen::Ballast);
        assert_eq!(model.density, DensityMode::Compact);
        assert_eq!(model.hint_verbosity, HintVerbosity::Off);
    }

    #[test]
    fn preference_action_revert_to_defaults_resets_model_profile() {
        let dir = TempDir::new().expect("temp dir");
        let pref_path = dir.path().join("preferences.json");
        let mut state = PreferenceRuntimeState {
            path: Some(pref_path),
            prefs: UserPreferences {
                start_screen: StartScreen::Diagnostics,
                density: DensityMode::Compact,
                hint_verbosity: HintVerbosity::Minimal,
                ..UserPreferences::default()
            },
            profile_mode: PreferenceProfileMode::SessionOverride,
            env_accessibility: AccessibilityProfile::default(),
            telemetry_hook: Box::<NullTelemetryHook>::default(),
        };
        let mut model = test_model();
        model.screen = Screen::Diagnostics;
        model.preference_profile_mode = PreferenceProfileMode::SessionOverride;
        model.candidates_source = DataSource::Sqlite;

        let msg = state
            .execute_action(PreferenceAction::RevertToDefaults, &mut model)
            .expect("revert defaults");
        assert!(msg.contains("defaults"));
        assert_eq!(model.preferred_start_screen, StartScreen::Overview);
        assert_eq!(model.density, DensityMode::Comfortable);
        assert_eq!(model.hint_verbosity, HintVerbosity::Full);
        assert_eq!(
            model.preference_profile_mode,
            PreferenceProfileMode::Defaults
        );
    }

    #[test]
    fn preference_action_emits_structured_telemetry() {
        let (telemetry_hook, samples) = capture_hook();
        let (mut state, warning) =
            PreferenceRuntimeState::load_from_path_with_hook(None, telemetry_hook);
        assert!(warning.is_none());
        let mut model = test_model();

        state
            .execute_action(
                PreferenceAction::SetDensity(DensityMode::Compact),
                &mut model,
            )
            .expect("set density");

        let captured = samples.lock().expect("read captured samples").clone();
        assert_eq!(captured.len(), 1);
        let sample = &captured[0];
        assert_eq!(sample.source, "dashboard.preferences");
        assert_eq!(sample.kind, "set_density");

        let detail_json = sample.detail.clone();
        let detail: serde_json::Value =
            serde_json::from_str(&detail_json).expect("detail json payload");
        assert_eq!(detail["actor"], "tui-dashboard");
        assert_eq!(detail["action"], "set_density");
        assert_eq!(detail["target"], "density=compact");
        assert_eq!(detail["result"], "ok");
        assert_eq!(detail["profile_mode"], "session_override");
        assert_eq!(detail["schema_version"], 1);
        assert!(detail["profile_hash"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        assert!(detail["error"].is_null());
    }
}
