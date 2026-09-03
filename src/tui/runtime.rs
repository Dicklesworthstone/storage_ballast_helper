//! Canonical runtime entrypoint for dashboard execution.
//!
//! The new cockpit path uses ftui-tty's [`TtyBackend`] for panic-safe terminal
//! lifecycle management and native event polling. The legacy fallback retains
//! its own cleanup logic.

#![allow(missing_docs)]

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ftui::{Buffer, BufferDiff, Event, Frame, GraphemePool, KeyEventKind};
use ftui_backend::{Backend, BackendEventSource, BackendFeatures, BackendPresenter};
use ftui_tty::{TtyBackend, TtySessionOptions};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::model::{
    DashboardCmd, DashboardModel, DashboardMsg, NotificationLevel, Overlay, PreferenceAction,
    PreferenceProfileMode, Screen,
};
use super::preferences::{self, ResolvedPreferences, StartScreen, UserPreferences};
use super::telemetry::{
    CompositeTelemetryAdapter, NullTelemetryHook, TelemetryHook, TelemetryQueryAdapter,
    TelemetrySample,
};
use super::theme::AccessibilityProfile;
use super::{input, render, update};
use crate::ballast::manager::BallastManager;
#[cfg(feature = "legacy-crossterm-dashboard")]
use crate::cli::dashboard::{self, DashboardConfig as LegacyDashboardConfig};
use crate::core::config::BallastConfig;
use crate::core::hex_lower;
use crate::daemon::control;
use crate::daemon::self_monitor::{DaemonLockProbe, DaemonState, probe_daemon_lock};

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
    pub sqlite_db: Option<PathBuf>,
    pub jsonl_log: Option<PathBuf>,
    /// `--start-screen`: the screen to open on for this session, beating the
    /// persisted preference without touching it.
    pub start_screen: Option<StartScreen>,
    /// What a confirmed ballast action uses when no daemon holds the pool;
    /// `None` makes such an action a typed refusal.
    pub ballast: Option<BallastFallback>,
}

/// The `[ballast]` settings and provisioning floor the cockpit needs to
/// change a pool itself, the way `sbh ballast release`/`replenish` do.
#[derive(Debug, Clone)]
pub struct BallastFallback {
    pub config: BallastConfig,
    pub provision_floor_pct: f64,
}

impl DashboardRuntimeConfig {
    /// Build the underlying legacy dashboard config.
    #[cfg(feature = "legacy-crossterm-dashboard")]
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
    Ok(hex_lower(digest))
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

#[allow(clippy::too_many_lines)] // TUI event loop is a natural single flow
fn run_new_cockpit(config: &DashboardRuntimeConfig) -> io::Result<()> {
    // TtyBackend handles raw mode + alternate screen with RAII cleanup.
    // Drop restores the terminal even on panic or early return.
    let options = TtySessionOptions {
        alternate_screen: true,
        intercept_signals: true,
        features: BackendFeatures {
            mouse_capture: true,
            ..Default::default()
        },
    };
    let mut backend = TtyBackend::open(80, 24, options)?;

    let (raw_cols, raw_rows) = backend.size()?;
    let (cols, rows) = (raw_cols.max(1), raw_rows.max(1));
    let mut model = DashboardModel::new(
        config.state_file.clone(),
        config.monitor_paths.clone(),
        config.refresh,
        (cols, rows),
    );
    let (mut preference_state, preference_warning) = PreferenceRuntimeState::load();
    preference_state.apply_to_model(&mut model, true, true);
    apply_start_screen_override(&mut model, config.start_screen);

    // Initialize telemetry adapter.
    let telemetry_adapter =
        CompositeTelemetryAdapter::new(config.sqlite_db.as_deref(), config.jsonl_log.as_deref());

    // Pending notification auto-dismiss timers: (notification_id, expires_at).
    let mut notification_timers: Vec<(u64, Instant)> = Vec::new();
    if let Some(warning) = preference_warning {
        let id = model.push_notification(NotificationLevel::Warning, warning);
        notification_timers.push((id, Instant::now() + Duration::from_secs(8)));
    }

    // Initial data fetch.
    let initial = read_state_file(&config.state_file);
    update::update(&mut model, DashboardMsg::DataUpdate(initial));

    let mut pool = GraphemePool::new();
    let mut prev_buffer = Buffer::new(cols, rows);
    let mut first_frame = true;

    loop {
        // Render current frame via Frame-based widget pipeline.
        // Clamp to 1×1 minimum: Buffer/Frame panic on zero dimensions.
        let render_cols = model.terminal_size.0.max(1);
        let render_rows = model.terminal_size.1.max(1);
        let mut frame = Frame::new(render_cols, render_rows, &mut pool);
        render::render_frame(&model, &mut frame);

        // Compute diff and present. Force full repaint on size change or first frame.
        let size_changed =
            prev_buffer.width() != render_cols || prev_buffer.height() != render_rows;
        let full_repaint = first_frame || size_changed;
        let diff = if full_repaint {
            BufferDiff::full(render_cols, render_rows)
        } else {
            BufferDiff::compute(&prev_buffer, &frame.buffer)
        };
        backend
            .presenter()
            .present_ui(&frame.buffer, Some(&diff), full_repaint)?;
        first_frame = false;
        prev_buffer = std::mem::replace(&mut frame.buffer, Buffer::new(1, 1));

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
                    Event::Mouse(mouse) => update::update(&mut model, DashboardMsg::Mouse(mouse)),
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
                    &telemetry_adapter,
                    config.ballast.as_ref(),
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
                &telemetry_adapter,
                config.ballast.as_ref(),
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
    telemetry: &dyn TelemetryQueryAdapter,
    ballast: Option<&BallastFallback>,
) {
    match cmd {
        DashboardCmd::None | DashboardCmd::ScheduleTick(_) => {}
        DashboardCmd::FetchData => {
            let state = read_state_file(state_file);
            let inner_cmd = update::update(model, DashboardMsg::DataUpdate(state));
            execute_cmd(
                model,
                state_file,
                inner_cmd,
                timers,
                preference_state,
                telemetry,
                ballast,
            );
        }
        DashboardCmd::FetchTelemetry => {
            let inner_cmd = fetch_telemetry_for_screen(model, telemetry);
            execute_cmd(
                model,
                state_file,
                inner_cmd,
                timers,
                preference_state,
                telemetry,
                ballast,
            );
        }
        DashboardCmd::Quit => {
            model.quit = true;
        }
        DashboardCmd::Batch(cmds) => {
            for c in cmds {
                execute_cmd(
                    model,
                    state_file,
                    c,
                    timers,
                    preference_state,
                    telemetry,
                    ballast,
                );
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
        DashboardCmd::ReleaseBallast {
            mount,
            ballast_dir,
            count,
        } => {
            let outcome = release_ballast(state_file, ballast, &mount, &ballast_dir, count);
            settle_ballast_outcome(
                model,
                state_file,
                timers,
                preference_state,
                telemetry,
                ballast,
                outcome,
            );
        }
        DashboardCmd::ReplenishBallast { mount, ballast_dir } => {
            let outcome = replenish_ballast(state_file, ballast, &mount, &ballast_dir);
            settle_ballast_outcome(
                model,
                state_file,
                timers,
                preference_state,
                telemetry,
                ballast,
                outcome,
            );
        }
    }
}

/// The telemetry the current screen needs, delivered through `update` so
/// the follow-up command (if any) can be executed by the caller.
fn fetch_telemetry_for_screen(
    model: &mut DashboardModel,
    telemetry: &dyn TelemetryQueryAdapter,
) -> DashboardCmd {
    match model.screen {
        Screen::Overview => {
            let events =
                telemetry.recent_events(80, &crate::tui::telemetry::EventFilter::default());
            let decisions = telemetry.recent_decisions(40);
            let candidates = crate::tui::telemetry::TelemetryResult {
                data: decisions.data.clone(),
                source: decisions.source,
                partial: decisions.partial,
                diagnostics: decisions.diagnostics.clone(),
            };
            let cmds = vec![
                update::update(model, DashboardMsg::TelemetryTimeline(events)),
                update::update(model, DashboardMsg::TelemetryDecisions(decisions)),
                update::update(model, DashboardMsg::TelemetryCandidates(candidates)),
            ];
            DashboardCmd::Batch(cmds)
        }
        Screen::Timeline => {
            let result = telemetry.recent_events(50, &model.timeline_filter.to_event_filter());
            update::update(model, DashboardMsg::TelemetryTimeline(result))
        }
        Screen::Explainability => {
            let result = telemetry.recent_decisions(20);
            update::update(model, DashboardMsg::TelemetryDecisions(result))
        }
        Screen::Candidates => {
            // Candidate ranking derived from recent decision evidence.
            let result = telemetry.recent_decisions(40);
            update::update(model, DashboardMsg::TelemetryCandidates(result))
        }
        Screen::LogSearch => {
            let result = telemetry.search_events(&model.log_search.to_query());
            update::update(model, DashboardMsg::TelemetryLogSearch(result))
        }
        // Ballast inventory arrives with the daemon state (FetchData);
        // Diagnostics has no telemetry query of its own.
        Screen::Ballast | Screen::Diagnostics => DashboardCmd::None,
    }
}

/// After a confirmed ballast action: show the outcome and refetch the
/// state, because the pool changed (or the operator needs to see that it
/// did not).
fn settle_ballast_outcome(
    model: &mut DashboardModel,
    state_file: &Path,
    timers: &mut Vec<(u64, Instant)>,
    preference_state: &mut PreferenceRuntimeState,
    telemetry: &dyn TelemetryQueryAdapter,
    ballast: Option<&BallastFallback>,
    outcome: Result<String, String>,
) {
    notify_release_outcome(model, timers, outcome);
    execute_cmd(
        model,
        state_file,
        DashboardCmd::FetchData,
        timers,
        preference_state,
        telemetry,
        ballast,
    );
}

/// `--start-screen` for this session: `Remember` keeps whatever the
/// preferences chose, any other value replaces it and clears the back
/// history so Backspace does not lead to a screen the operator never saw.
fn apply_start_screen_override(model: &mut DashboardModel, start_screen: Option<StartScreen>) {
    if let Some(start) = start_screen
        && start != StartScreen::Remember
    {
        model.screen = start.resolve(Some(model.screen));
        model.screen_history.clear();
    }
}

/// Surface a release outcome as a notification: successes fade after 8 s,
/// refusals stay a little longer so the reason can be read.
fn notify_release_outcome(
    model: &mut DashboardModel,
    timers: &mut Vec<(u64, Instant)>,
    outcome: Result<String, String>,
) {
    let (level, message, hold) = match outcome {
        Ok(message) => (NotificationLevel::Info, message, 8),
        Err(message) => (NotificationLevel::Error, message, 12),
    };
    let id = model.push_notification(level, message);
    timers.push((id, Instant::now() + Duration::from_secs(hold)));
}

/// Who performs a confirmed ballast action.
enum BallastRoute {
    /// A daemon holds the pool: go through its control socket.
    Daemon(control::ControlEndpoint),
    /// No daemon: change the pool directly, as the CLI does.
    Direct,
}

/// A running daemon owns its pools, so the action must go through it; a
/// daemon without a control socket (a lock written by an older build) is
/// a refusal rather than a race; only a free or absent lock allows the
/// direct route.
fn ballast_route(state_file: &Path) -> Result<BallastRoute, String> {
    if let Some(endpoint) = control::read_endpoint(state_file) {
        return Ok(BallastRoute::Daemon(endpoint));
    }
    match probe_daemon_lock(state_file) {
        DaemonLockProbe::Free | DaemonLockProbe::Absent => Ok(BallastRoute::Direct),
        DaemonLockProbe::Held(_) => Err(
            "a daemon is running without a control socket; use `sbh ballast release` on the host"
                .to_string(),
        ),
        DaemonLockProbe::Unreadable(detail) => {
            Err(format!("cannot tell whether a daemon is running: {detail}"))
        }
    }
}

/// The pool manager for the direct route, or the refusal when the cockpit
/// was not given the pool settings.
fn direct_pool(
    fallback: Option<&BallastFallback>,
    ballast_dir: &str,
) -> Result<BallastManager, String> {
    let fallback = fallback.ok_or_else(|| {
        "no running daemon and no pool settings; start sbh or use `sbh ballast release`".to_string()
    })?;
    let mut manager = BallastManager::new(PathBuf::from(ballast_dir), fallback.config.clone())
        .map_err(|err| format!("ballast pool {ballast_dir}: {err}"))?;
    manager.set_provision_floor(fallback.provision_floor_pct);
    Ok(manager)
}

/// Release `count` ballast files on `mount`, through the daemon beside
/// `state_file` when one runs, else directly on `ballast_dir`. The Ok/Err
/// strings are the operator-facing notification.
fn release_ballast(
    state_file: &Path,
    fallback: Option<&BallastFallback>,
    mount: &str,
    ballast_dir: &str,
    count: usize,
) -> Result<String, String> {
    match ballast_route(state_file)? {
        BallastRoute::Daemon(endpoint) => release_ballast_at(&endpoint, mount, count),
        BallastRoute::Direct => {
            let mut manager = direct_pool(fallback, ballast_dir)?;
            if manager.available_count() == 0 {
                return Err(format!("ballast release on {mount}: no file available"));
            }
            let report = manager
                .release(count)
                .map_err(|err| format!("ballast release on {mount} failed: {err}"))?;
            if report.files_released == 0 {
                return Err(format!("ballast release on {mount}: nothing released"));
            }
            Ok(format!(
                "released {} ballast file(s) on {mount} directly (no daemon), {} freed",
                report.files_released,
                super::widgets::human_bytes(report.bytes_freed)
            ))
        }
    }
}

/// Recreate the released ballast files on `mount`, through the daemon or
/// directly (see [`release_ballast`]).
fn replenish_ballast(
    state_file: &Path,
    fallback: Option<&BallastFallback>,
    mount: &str,
    ballast_dir: &str,
) -> Result<String, String> {
    match ballast_route(state_file)? {
        BallastRoute::Daemon(endpoint) => replenish_ballast_at(&endpoint, mount),
        BallastRoute::Direct => {
            let mut manager = direct_pool(fallback, ballast_dir)?;
            let report = manager
                .replenish(None)
                .map_err(|err| format!("ballast replenish on {mount} failed: {err}"))?;
            summarise_replenish(
                mount,
                report.files_created,
                report.skipped_for_floor,
                report.total_bytes,
                " directly (no daemon)",
            )
        }
    }
}

/// One `ballast` request with `replenish = true` scoped to `mount`.
fn replenish_ballast_at(
    endpoint: &control::ControlEndpoint,
    mount: &str,
) -> Result<String, String> {
    let args = serde_json::json!({ "replenish": true, "mount": mount });
    let response = control::request(&endpoint.socket, &endpoint.token, "ballast", &args)
        .map_err(|err| format!("ballast replenish failed: {err}"))?;
    if !response.ok {
        let detail = response
            .error
            .map_or_else(|| "daemon refused".to_string(), |err| err.message);
        return Err(format!("ballast replenish refused: {detail}"));
    }
    let pools = response.result["pools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let sum = |key: &str| -> u64 { pools.iter().filter_map(|pool| pool[key].as_u64()).sum() };
    let created = usize::try_from(sum("created")).unwrap_or(usize::MAX);
    let skipped_for_floor = usize::try_from(sum("skipped_for_floor")).unwrap_or(usize::MAX);
    summarise_replenish(mount, created, skipped_for_floor, sum("bytes"), "")
}

/// The replenish notification: created files are a success, a floor-limited
/// pool says so, and nothing created with nothing skipped means it was full.
fn summarise_replenish(
    mount: &str,
    created: usize,
    skipped_for_floor: usize,
    bytes: u64,
    suffix: &str,
) -> Result<String, String> {
    if created > 0 {
        let floor = if skipped_for_floor > 0 {
            format!(", {skipped_for_floor} held back by the free-space floor")
        } else {
            String::new()
        };
        return Ok(format!(
            "recreated {created} ballast file(s) on {mount}{suffix} ({}{floor})",
            super::widgets::human_bytes(bytes)
        ));
    }
    if skipped_for_floor > 0 {
        return Err(format!(
            "ballast replenish on {mount}: {skipped_for_floor} file(s) held back by the free-space floor"
        ));
    }
    Err(format!("ballast replenish on {mount}: pool already full"))
}

/// The control-socket half of [`release_ballast`]: one `ballast` request
/// with `release = count` scoped to `mount`, summarised from the daemon's
/// per-pool report.
fn release_ballast_at(
    endpoint: &control::ControlEndpoint,
    mount: &str,
    count: usize,
) -> Result<String, String> {
    let args = serde_json::json!({ "release": count, "mount": mount });
    let response = control::request(&endpoint.socket, &endpoint.token, "ballast", &args)
        .map_err(|err| format!("ballast release failed: {err}"))?;
    if !response.ok {
        let detail = response
            .error
            .map_or_else(|| "daemon refused".to_string(), |err| err.message);
        return Err(format!("ballast release refused: {detail}"));
    }
    let pools = response.result["pools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let released: u64 = pools
        .iter()
        .filter_map(|pool| pool["released"].as_u64())
        .sum();
    let bytes_freed: u64 = pools
        .iter()
        .filter_map(|pool| pool["bytes_freed"].as_u64())
        .sum();
    if released == 0 {
        let note = pools
            .iter()
            .find_map(|pool| pool["note"].as_str().map(str::to_string))
            .unwrap_or_else(|| "no ballast file was available".to_string());
        return Err(format!(
            "ballast release on {mount}: nothing released ({note})"
        ));
    }
    Ok(format!(
        "released {released} ballast file(s) on {mount}, {} freed",
        super::widgets::human_bytes(bytes_freed)
    ))
}

/// Read and parse the daemon state file. Returns `None` on any error.
fn read_state_file(path: &Path) -> Option<Box<DaemonState>> {
    let content = std::fs::read_to_string(path).ok()?;
    let state: DaemonState = serde_json::from_str(&content).ok()?;
    Some(Box::new(state))
}

#[cfg(feature = "legacy-crossterm-dashboard")]
fn run_legacy_fallback(config: &DashboardRuntimeConfig) -> io::Result<()> {
    dashboard::run(&config.as_legacy_config())
}

/// Without the `legacy-crossterm-dashboard` feature the fallback mode is a
/// typed refusal: the CLI never selects it (its `--legacy-dashboard` is the
/// live status view), so reaching here means a caller asked for a renderer
/// this binary does not carry.
#[cfg(not(feature = "legacy-crossterm-dashboard"))]
fn run_legacy_fallback(_config: &DashboardRuntimeConfig) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the legacy crossterm dashboard is not compiled into this binary (feature \
         legacy-crossterm-dashboard); use `sbh dashboard --legacy-dashboard` for the live status view",
    ))
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
    fn start_screen_override_replaces_the_preference_screen() {
        let mut model = test_model();
        model.screen = Screen::Timeline;
        model.screen_history.push(Screen::Overview);

        // Remember keeps what the preferences chose.
        apply_start_screen_override(&mut model, Some(StartScreen::Remember));
        assert_eq!(model.screen, Screen::Timeline);
        assert_eq!(model.screen_history, vec![Screen::Overview]);

        // None is the plain launch.
        apply_start_screen_override(&mut model, None);
        assert_eq!(model.screen, Screen::Timeline);

        // A concrete screen replaces it and clears the back history.
        apply_start_screen_override(&mut model, Some(StartScreen::Candidates));
        assert_eq!(model.screen, Screen::Candidates);
        assert!(model.screen_history.is_empty());
    }

    #[test]
    fn release_without_a_daemon_or_pool_settings_is_a_typed_refusal() {
        let temp = TempDir::new().unwrap();
        let state = temp.path().join("state.json");
        let dir = temp.path().join("ballast").display().to_string();
        let err = release_ballast(&state, None, "/data", &dir, 1).unwrap_err();
        assert!(err.contains("no running daemon"), "{err}");
        let err = replenish_ballast(&state, None, "/data", &dir).unwrap_err();
        assert!(err.contains("no running daemon"), "{err}");
    }

    #[test]
    fn without_a_daemon_the_cockpit_changes_the_pool_directly() {
        let temp = TempDir::new().unwrap();
        let state = temp.path().join("state.json");
        let dir = temp.path().join("ballast");
        let config = BallastConfig {
            file_count: 2,
            file_size_bytes: 4096,
            ..BallastConfig::default()
        };
        let mut manager = BallastManager::new(dir.clone(), config.clone()).unwrap();
        manager.provision(None).unwrap();
        assert_eq!(manager.available_count(), 2);
        drop(manager);
        let fallback = BallastFallback {
            config,
            provision_floor_pct: 0.0,
        };
        let dir_text = dir.display().to_string();

        let ok = release_ballast(&state, Some(&fallback), "/data", &dir_text, 1).unwrap();
        assert!(
            ok.contains("released 1 ballast file(s) on /data directly"),
            "{ok}"
        );
        let left = BallastManager::new(dir.clone(), fallback.config.clone()).unwrap();
        assert_eq!(left.available_count(), 1, "one file is gone from disk");

        let ok = replenish_ballast(&state, Some(&fallback), "/data", &dir_text).unwrap();
        assert!(
            ok.contains("recreated 1 ballast file(s) on /data directly"),
            "{ok}"
        );
        let full = BallastManager::new(dir, fallback.config.clone()).unwrap();
        assert_eq!(full.available_count(), 2);

        let err = replenish_ballast(&state, Some(&fallback), "/data", &dir_text).unwrap_err();
        assert!(err.contains("already full"), "{err}");

        // Release everything, then a further release has nothing to give.
        release_ballast(&state, Some(&fallback), "/data", &dir_text, 2).unwrap();
        let err = release_ballast(&state, Some(&fallback), "/data", &dir_text, 1).unwrap_err();
        assert!(err.contains("no file available"), "{err}");
    }

    #[test]
    fn release_over_the_control_socket_summarises_the_daemon_report() {
        use crate::daemon::control::{
            BallastAction, ControlBackend, ControlCommand, ControlEndpoint, ControlResponse,
            ControlServer, Peer, control_socket_path,
        };

        /// Answers a scoped release with the daemon's per-pool document
        /// shape and refuses everything else.
        struct PoolBackend;
        impl ControlBackend for PoolBackend {
            fn handle(&self, command: ControlCommand, _peer: Option<Peer>) -> ControlResponse {
                match command {
                    ControlCommand::Ballast(BallastAction::Release { count, mount }) => {
                        let mount = mount.map(|m| m.display().to_string()).unwrap_or_default();
                        if mount == "/empty" {
                            return ControlResponse::success(serde_json::json!({
                                "pools": [{ "mount": mount, "released": 0, "bytes_freed": 0,
                                            "note": "no pool or no available file" }]
                            }));
                        }
                        ControlResponse::success(serde_json::json!({
                            "pools": [{ "mount": mount, "released": count,
                                        "bytes_freed": count as u64 * 1_073_741_824 }]
                        }))
                    }
                    ControlCommand::Ballast(BallastAction::Replenish { mount }) => {
                        let mount = mount.map(|m| m.display().to_string()).unwrap_or_default();
                        let (created, floor) = if mount == "/floor" { (0, 2) } else { (2, 0) };
                        ControlResponse::success(serde_json::json!({
                            "pools": [{ "mount": mount, "created": created,
                                        "skipped_for_floor": floor,
                                        "bytes": created * 1_048_576 }]
                        }))
                    }
                    _ => ControlResponse::failure("bad_request", "not a ballast action"),
                }
            }
        }

        let temp = TempDir::new().unwrap();
        let state = temp.path().join("state.json");
        let socket = control_socket_path(&state);
        let server = ControlServer::start(&socket, "secret", Arc::new(PoolBackend)).unwrap();
        let endpoint = ControlEndpoint {
            socket: socket.clone(),
            token: "secret".to_string(),
        };

        let ok = release_ballast_at(&endpoint, "/data", 2).unwrap();
        assert!(ok.contains("released 2 ballast file(s) on /data"), "{ok}");
        assert!(ok.contains("2.0 GB freed"), "{ok}");

        let nothing = release_ballast_at(&endpoint, "/empty", 1).unwrap_err();
        assert!(nothing.contains("nothing released"), "{nothing}");
        assert!(
            nothing.contains("no pool or no available file"),
            "{nothing}"
        );

        let replenished = replenish_ballast_at(&endpoint, "/data").unwrap();
        assert!(
            replenished.contains("recreated 2 ballast file(s) on /data"),
            "{replenished}"
        );
        assert!(replenished.contains("2.0 MB"), "{replenished}");
        let floored = replenish_ballast_at(&endpoint, "/floor").unwrap_err();
        assert!(
            floored.contains("held back by the free-space floor"),
            "{floored}"
        );

        // No lock beside a state file means the direct route; a live daemon
        // (its lock carries the token) is always routed through the socket.
        let temp_state = temp.path().join("state.json");
        std::fs::write(&temp_state, "{}").unwrap();
        assert!(
            matches!(ballast_route(&temp_state), Ok(BallastRoute::Direct)),
            "no lock beside the state file means the direct route"
        );

        let wrong_token = ControlEndpoint {
            socket,
            token: "wrong".to_string(),
        };
        let refused = release_ballast_at(&wrong_token, "/data", 1).unwrap_err();
        assert!(refused.contains("refused"), "{refused}");
        server.stop();
    }

    #[cfg(feature = "legacy-crossterm-dashboard")]
    #[test]
    fn runtime_config_maps_to_legacy_config() {
        let cfg = DashboardRuntimeConfig {
            state_file: PathBuf::from("/tmp/state.json"),
            refresh: Duration::from_millis(750),
            monitor_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/data/projects")],
            mode: DashboardRuntimeMode::LegacyFallback,
            sqlite_db: None,
            jsonl_log: None,
            start_screen: None,
            ballast: None,
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
        assert!(
            detail["profile_hash"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert!(detail["error"].is_null());
    }
}
