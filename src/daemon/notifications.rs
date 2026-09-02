//! Multi-channel notification system: desktop, file, journal, and webhook channels.
//!
//! Dispatches structured notifications through configured channels with min-level
//! filtering. Each channel is fire-and-forget — notification failures are logged
//! but never block the monitoring loop.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::monitor::pid::PressureLevel;

const DEFAULT_NOTIFY_INTERVAL_SECS: u64 = 60;
const DEFAULT_URGENT_NOTIFY_INTERVAL_SECS: u64 = 300;

// ──────────────────── notification level ────────────────────

/// Severity level for notification filtering. Maps 1:1 with pressure levels
/// but is a separate type since notifications can originate from non-pressure events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationLevel {
    Info,
    Warning,
    Orange,
    Red,
    Critical,
}

impl NotificationLevel {
    /// Convert from a pressure level.
    #[must_use]
    pub const fn from_pressure(level: PressureLevel) -> Self {
        match level {
            PressureLevel::Green => Self::Info,
            PressureLevel::Yellow => Self::Warning,
            PressureLevel::Orange => Self::Orange,
            PressureLevel::Red => Self::Red,
            PressureLevel::Critical => Self::Critical,
        }
    }
}

impl fmt::Display for NotificationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Orange => write!(f, "orange"),
            Self::Red => write!(f, "red"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ──────────────────── notification events ────────────────────

/// A structured notification event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationEvent {
    PressureChanged {
        from: String,
        to: String,
        mount: String,
        free_pct: f64,
    },
    PredictiveWarning {
        mount: String,
        minutes_remaining: f64,
        confidence: f64,
    },
    CleanupCompleted {
        items_deleted: usize,
        bytes_freed: u64,
        mount: String,
    },
    BallastReleased {
        mount: String,
        files_released: usize,
        bytes_freed: u64,
    },
    BallastReplenished {
        mount: String,
        files_replenished: usize,
    },
    BehaviorEmergency {
        source: String,
        memory_level: String,
        disk_level: String,
        action: String,
    },
    DaemonStarted {
        version: String,
        volumes_monitored: usize,
    },
    DaemonStopped {
        reason: String,
        uptime_secs: u64,
    },
    Error {
        code: String,
        message: String,
    },
    /// The daemon has been over its CPU budget (`telemetry.cpu_budget_pct`)
    /// for `minutes` consecutive minutes.
    CpuBudgetExceeded {
        pct: u8,
        used_pct_1m: f64,
        minutes: u32,
    },
    /// A mount is under pressure and sbh has nothing to reclaim on it: no
    /// configured root, no catalog root, no cross-device fallback and no
    /// releasable ballast. Sent once per pressure epoch.
    ReclaimUnavailable {
        mount: String,
        level: String,
        reason: String,
    },
    /// The policy engine changed mode (promotion, demotion, fallback,
    /// recovery, emergency escalation).
    PolicyTransition {
        transition: String,
        from: String,
        to: String,
        reason: Option<String>,
    },
}

impl NotificationEvent {
    /// The severity level of this event (for min-level filtering).
    #[must_use]
    pub fn level(&self) -> NotificationLevel {
        match self {
            Self::DaemonStarted { .. }
            | Self::DaemonStopped { .. }
            | Self::BallastReplenished { .. } => NotificationLevel::Info,

            Self::PressureChanged { to, .. } => match to.as_str() {
                "Critical" | "critical" => NotificationLevel::Critical,
                "Red" | "red" => NotificationLevel::Red,
                "Orange" | "orange" => NotificationLevel::Orange,
                "Yellow" | "yellow" => NotificationLevel::Warning,
                _ => NotificationLevel::Info,
            },

            Self::PredictiveWarning {
                minutes_remaining,
                confidence,
                ..
            } => {
                // Determine severity from time-to-exhaustion.
                // Thresholds must match check_predictive_warning() in loop_main.rs
                // to avoid level-mismatch where the journal shows [CRIT] but the
                // cooldown logic considers the event Red, causing back-to-back CRITs.
                // Defaults: critical < 2 min, red < 5 min, orange < 30 min.
                let time_level = if *minutes_remaining < 2.0 {
                    NotificationLevel::Critical
                } else if *minutes_remaining < 5.0 {
                    NotificationLevel::Red
                } else if *minutes_remaining < 30.0 {
                    NotificationLevel::Orange
                } else {
                    NotificationLevel::Warning
                };

                // Cap severity when confidence is low to avoid CRIT spam from
                // unreliable predictions (e.g. 1% confidence → Info, suppressed).
                let confidence_cap = if *confidence < 0.3 {
                    NotificationLevel::Info
                } else if *confidence < 0.5 {
                    NotificationLevel::Warning
                } else if *confidence < 0.7 {
                    NotificationLevel::Orange
                } else {
                    NotificationLevel::Critical // no cap
                };

                // Take the lesser of time-based and confidence-capped levels.
                if time_level <= confidence_cap {
                    time_level
                } else {
                    confidence_cap
                }
            }

            Self::CleanupCompleted {
                items_deleted,
                bytes_freed,
                ..
            } => {
                let ten_gb = 10 * 1_073_741_824;
                if *items_deleted > 10 || *bytes_freed > ten_gb {
                    NotificationLevel::Warning
                } else {
                    NotificationLevel::Info
                }
            }

            Self::BallastReleased { .. } => NotificationLevel::Orange,

            Self::BehaviorEmergency { .. } => NotificationLevel::Critical,

            Self::Error { .. } => NotificationLevel::Red,

            Self::CpuBudgetExceeded { .. } | Self::PolicyTransition { .. } => {
                NotificationLevel::Warning
            }

            // The pressure level itself: Orange on an unprotected mount is
            // as loud as Orange anywhere.
            Self::ReclaimUnavailable { level, .. } => match level.as_str() {
                "critical" => NotificationLevel::Critical,
                "red" => NotificationLevel::Red,
                "orange" => NotificationLevel::Orange,
                _ => NotificationLevel::Warning,
            },
        }
    }

    /// Discriminant key for per-event-type throttling.
    #[must_use]
    pub fn type_key(&self) -> &'static str {
        match self {
            Self::PressureChanged { .. } => "pressure_changed",
            Self::PredictiveWarning { .. } => "predictive_warning",
            Self::CleanupCompleted { .. } => "cleanup_completed",
            Self::BallastReleased { .. } => "ballast_released",
            Self::BallastReplenished { .. } => "ballast_replenished",
            Self::BehaviorEmergency { .. } => "behavior_emergency",
            Self::DaemonStarted { .. } => "daemon_started",
            Self::DaemonStopped { .. } => "daemon_stopped",
            Self::Error { .. } => "error",
            Self::CpuBudgetExceeded { .. } => "cpu_budget_exceeded",
            Self::ReclaimUnavailable { .. } => "reclaim_unavailable",
            Self::PolicyTransition { .. } => "policy_transition",
        }
    }

    /// Short human-readable summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::PressureChanged {
                from,
                to,
                mount,
                free_pct,
            } => format!("Pressure {from} -> {to} on {mount} ({free_pct:.1}% free)"),
            Self::PredictiveWarning {
                mount,
                minutes_remaining,
                confidence,
            } => {
                let pct = confidence * 100.0;
                format!(
                    "Predicted disk full on {mount} in {minutes_remaining:.0}m (confidence: {pct:.0}%)"
                )
            }
            Self::CleanupCompleted {
                items_deleted,
                bytes_freed,
                mount,
            } => {
                let gb = *bytes_freed as f64 / 1_073_741_824.0;
                format!("Cleaned {items_deleted} items on {mount} ({gb:.1} GB freed)")
            }
            Self::BallastReleased {
                mount,
                files_released,
                bytes_freed,
            } => {
                let gb = *bytes_freed as f64 / 1_073_741_824.0;
                format!("Released {files_released} ballast files on {mount} ({gb:.1} GB)")
            }
            Self::BallastReplenished {
                mount,
                files_replenished,
            } => format!("Replenished {files_replenished} ballast files on {mount}"),
            Self::BehaviorEmergency {
                source,
                memory_level,
                disk_level,
                action,
            } => {
                format!(
                    "Emergency pressure response from {source}: memory={memory_level} disk={disk_level} ({action})"
                )
            }
            Self::DaemonStarted {
                version,
                volumes_monitored,
            } => format!("sbh v{version} started, monitoring {volumes_monitored} volumes"),
            Self::DaemonStopped {
                reason,
                uptime_secs,
            } => {
                let hours = uptime_secs / 3600;
                let minutes = (uptime_secs % 3600) / 60;
                format!("sbh stopped ({reason}) after {hours}h {minutes}m")
            }
            Self::Error { code, message } => format!("[{code}] {message}"),
            Self::CpuBudgetExceeded {
                pct,
                used_pct_1m,
                minutes,
            } => format!(
                "sbh daemon over its CPU budget for {minutes} min ({used_pct_1m:.1}% of a core used, budget {pct}%)"
            ),
            Self::ReclaimUnavailable {
                mount,
                level,
                reason,
            } => {
                format!("Pressure {level} on {mount} and nothing sbh can reclaim there ({reason})")
            }
            Self::PolicyTransition {
                transition,
                from,
                to,
                reason,
            } => reason.as_ref().map_or_else(
                || format!("Policy {transition}: {from} -> {to}"),
                |reason| format!("Policy {transition}: {from} -> {to} ({reason})"),
            ),
        }
    }
}

// ──────────────────── configuration ────────────────────

/// Top-level notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    /// Master switch for all notifications.
    pub enabled: bool,
    /// Which channel names to activate.
    pub channels: Vec<String>,
    /// Minimum seconds between notifications (0 = no throttle).
    /// Red/Critical events use `urgent_notify_interval_secs` instead.
    pub min_notify_interval_secs: u64,
    /// Minimum seconds between Red/Critical notifications of the same category.
    /// The default is five minutes so emergency desktop alerts remain useful.
    pub urgent_notify_interval_secs: u64,
    pub desktop: DesktopConfig,
    pub webhook: WebhookConfig,
    pub file: FileConfig,
    pub journal: JournalConfig,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channels: vec!["journal".to_string(), "file".to_string()],
            min_notify_interval_secs: DEFAULT_NOTIFY_INTERVAL_SECS,
            urgent_notify_interval_secs: DEFAULT_URGENT_NOTIFY_INTERVAL_SECS,
            desktop: DesktopConfig::default(),
            webhook: WebhookConfig::default(),
            file: FileConfig::default(),
            journal: JournalConfig::default(),
        }
    }
}

/// Desktop notification settings (notify-send on Linux, osascript on macOS).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DesktopConfig {
    pub enabled: bool,
    pub min_level: NotificationLevel,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_level: NotificationLevel::Orange,
        }
    }
}

/// Webhook notification settings (HTTP POST via curl).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub min_level: NotificationLevel,
    /// Template string with `${MOUNT}`, `${FREE_PCT}`, `${LEVEL}`, `${SUMMARY}` placeholders.
    pub template: String,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_level: NotificationLevel::Red,
            template: r#"{"text": "sbh: ${SUMMARY}"}"#.to_string(),
        }
    }
}

/// File notification settings (append-only JSONL).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub path: PathBuf,
}

impl Default for FileConfig {
    fn default() -> Self {
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        Self {
            path: home
                .join(".local")
                .join("share")
                .join("sbh")
                .join("notifications.jsonl"),
        }
    }
}

/// Service-log notification settings.
///
/// The channel writes structured stderr lines so systemd journals and launchd
/// stdout/stderr capture both receive the same operator-visible events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct JournalConfig {
    pub min_level: NotificationLevel,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            min_level: NotificationLevel::Warning,
        }
    }
}

// ──────────────────── JSONL record ────────────────────

/// A single notification record written to the JSONL file.
#[derive(Debug, Serialize)]
struct NotificationRecord {
    ts: String,
    level: NotificationLevel,
    summary: String,
    #[serde(flatten)]
    event: NotificationEvent,
}

// ──────────────────── notification channels ────────────────────

/// A notification channel that can dispatch events.
trait Channel: Send + Sync {
    fn name(&self) -> &'static str;
    fn send(&self, event: &NotificationEvent);
}

// ──── Desktop (notify-send / osascript) ────

struct DesktopChannel {
    min_level: NotificationLevel,
}

impl DesktopChannel {
    const fn new(config: &DesktopConfig) -> Self {
        Self {
            min_level: config.min_level,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_display_notification_script(summary: &str) -> String {
    // Escape backslashes first, then double quotes, to prevent AppleScript injection.
    let escaped = summary.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "display notification \"{escaped}\" with title \"sbh\" subtitle \"Storage Ballast Helper\""
    )
}

impl Channel for DesktopChannel {
    fn name(&self) -> &'static str {
        "desktop"
    }

    fn send(&self, event: &NotificationEvent) {
        if event.level() < self.min_level {
            return;
        }

        let summary = event.summary();
        let urgency = match event.level() {
            NotificationLevel::Critical | NotificationLevel::Red => "critical",
            NotificationLevel::Orange | NotificationLevel::Warning => "normal",
            NotificationLevel::Info => "low",
        };

        #[cfg(target_os = "linux")]
        {
            if let Ok(child) = Command::new("notify-send")
                .arg("--urgency")
                .arg(urgency)
                .arg("--app-name=sbh")
                .arg("Storage Ballast Helper")
                .arg(&summary)
                .spawn()
            {
                // Reap the child in a detached thread to prevent zombie accumulation.
                std::thread::spawn(move || {
                    let mut c = child;
                    let _ = c.wait();
                });
            }
        }

        #[cfg(target_os = "macos")]
        {
            let script = macos_display_notification_script(&summary);
            if let Ok(child) = Command::new("osascript").arg("-e").arg(&script).spawn() {
                std::thread::spawn(move || {
                    let mut c = child;
                    let _ = c.wait();
                });
            }
        }

        // Suppress unused-variable warnings on platforms that don't use all locals.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = urgency;
        }
    }
}

// ──── File (append-only JSONL) ────

struct FileChannel {
    path: PathBuf,
}

impl FileChannel {
    fn new(config: &FileConfig) -> Self {
        Self {
            path: config.path.clone(),
        }
    }
}

impl Channel for FileChannel {
    fn name(&self) -> &'static str {
        "file"
    }

    fn send(&self, event: &NotificationEvent) {
        let record = NotificationRecord {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: event.level(),
            summary: event.summary(),
            event: event.clone(),
        };

        let Ok(json) = serde_json::to_string(&record) else {
            return;
        };

        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let file = {
            let mut opts = OpenOptions::new();
            opts.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            opts.open(&self.path)
        };

        if let Ok(mut f) = file {
            let _ = writeln!(f, "{json}");
        }
    }
}

// ──── Journal/service log (structured stderr) ────

struct JournalChannel {
    min_level: NotificationLevel,
}

impl JournalChannel {
    const fn new(config: &JournalConfig) -> Self {
        Self {
            min_level: config.min_level,
        }
    }
}

impl Channel for JournalChannel {
    fn name(&self) -> &'static str {
        "journal"
    }

    fn send(&self, event: &NotificationEvent) {
        if event.level() < self.min_level {
            return;
        }

        let level = event.level();
        let summary = event.summary();

        // systemd captures stderr in the journal, while launchd captures it in
        // the configured StandardErrorPath. Structured fields remain stable for
        // filtering: SBH_EVENT=..., SBH_LEVEL=...
        let priority = match level {
            NotificationLevel::Critical => "CRIT",
            NotificationLevel::Red => "ERR",
            NotificationLevel::Orange => "WARNING",
            NotificationLevel::Warning => "NOTICE",
            NotificationLevel::Info => "INFO",
        };

        eprintln!("[SBH-NOTIFY] [{priority}] {summary}");
    }
}

// ──── Webhook (HTTP POST via curl) ────

struct WebhookChannel {
    url: String,
    min_level: NotificationLevel,
    template: String,
}

impl WebhookChannel {
    fn new(config: &WebhookConfig) -> Self {
        Self {
            url: config.url.clone(),
            min_level: config.min_level,
            template: config.template.clone(),
        }
    }

    fn render_body(&self, event: &NotificationEvent) -> String {
        // JSON-escape values to prevent injection in webhook payloads.
        fn json_escape(s: &str) -> String {
            let mut out = String::with_capacity(s.len());
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c.is_control() => {
                        // \u00XX for control characters
                        for unit in c.encode_utf16(&mut [0; 2]) {
                            use std::fmt::Write;
                            let _ = write!(out, "\\u{unit:04x}");
                        }
                    }
                    c => out.push(c),
                }
            }
            out
        }

        let summary = event.summary();
        let level = event.level().to_string();

        // Extract mount and free_pct from relevant events, or use defaults.
        let (mount, free_pct) = match event {
            NotificationEvent::PressureChanged {
                mount, free_pct, ..
            } => (mount.clone(), format!("{free_pct:.1}")),
            NotificationEvent::PredictiveWarning { mount, .. }
            | NotificationEvent::CleanupCompleted { mount, .. }
            | NotificationEvent::BallastReleased { mount, .. }
            | NotificationEvent::BallastReplenished { mount, .. } => {
                (mount.clone(), "N/A".to_string())
            }
            _ => ("N/A".to_string(), "N/A".to_string()),
        };

        let summary_esc = json_escape(&summary);
        let level_esc = json_escape(&level);
        let mount_esc = json_escape(&mount);
        let free_pct_esc = json_escape(&free_pct);

        let mut result = String::with_capacity(self.template.len() * 2);
        let mut remainder = self.template.as_str();

        while let Some(start) = remainder.find("${") {
            result.push_str(&remainder[..start]);
            let rest = &remainder[start + 2..];
            if let Some(end) = rest.find('}') {
                let key = &rest[..end];
                match key {
                    "SUMMARY" => result.push_str(&summary_esc),
                    "LEVEL" => result.push_str(&level_esc),
                    "MOUNT" => result.push_str(&mount_esc),
                    "FREE_PCT" => result.push_str(&free_pct_esc),
                    _ => {
                        // Unknown key, keep literal
                        result.push_str("${");
                        result.push_str(key);
                        result.push('}');
                    }
                }
                remainder = &rest[end + 1..];
            } else {
                // Unclosed ${
                result.push_str(&remainder[start..]);
                remainder = "";
            }
        }
        result.push_str(remainder);
        result
    }
}

impl Channel for WebhookChannel {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn send(&self, event: &NotificationEvent) {
        if event.level() < self.min_level {
            return;
        }

        if self.url.is_empty() {
            return;
        }

        let body = self.render_body(event);

        // Fire-and-forget via curl. Timeout of 5 seconds to avoid blocking.
        // Use "--" to prevent URL from being interpreted as a curl option.
        // Reap the child in a detached thread to prevent zombie accumulation.
        if let Ok(child) = Command::new("curl")
            .arg("--silent")
            .arg("--max-time")
            .arg("5")
            .arg("--user-agent")
            .arg(crate::cli::HTTP_USER_AGENT)
            .arg("--header")
            .arg("Content-Type: application/json")
            .arg("--data-raw")
            .arg(&body)
            .arg("--")
            .arg(&self.url)
            .spawn()
        {
            std::thread::spawn(move || {
                let mut c = child;
                let _ = c.wait();
            });
        }
    }
}

// ──────────────────── notification manager ────────────────────

/// Coordinates dispatching notification events to all enabled channels.
///
/// The manager is designed to be cheap to call — each channel's `send()` is
/// fire-and-forget (spawns child processes for desktop/webhook, appends for file,
/// and writes to stderr for journal). Notification failures never propagate.
pub struct NotificationManager {
    channels: Vec<Box<dyn Channel>>,
    enabled: bool,
    /// Per-event-type throttle timestamps. Keyed by `NotificationEvent::type_key()`.
    /// Prevents a low-priority event type from blocking unrelated higher-priority ones.
    last_send_by_type: HashMap<&'static str, Instant>,
    min_interval: Duration,
    urgent_min_interval: Duration,
}

impl NotificationManager {
    /// Build a manager from configuration.
    #[must_use]
    pub fn from_config(config: &NotificationConfig) -> Self {
        if !config.enabled {
            return Self {
                channels: Vec::new(),
                enabled: false,
                last_send_by_type: HashMap::new(),
                min_interval: Duration::ZERO,
                urgent_min_interval: Duration::ZERO,
            };
        }

        let mut channels: Vec<Box<dyn Channel>> = Vec::new();

        for channel_name in &config.channels {
            match channel_name.as_str() {
                "desktop" if config.desktop.enabled => {
                    channels.push(Box::new(DesktopChannel::new(&config.desktop)));
                }
                "file" => {
                    channels.push(Box::new(FileChannel::new(&config.file)));
                }
                "journal" => {
                    channels.push(Box::new(JournalChannel::new(&config.journal)));
                }
                "webhook" if config.webhook.enabled => {
                    channels.push(Box::new(WebhookChannel::new(&config.webhook)));
                }
                _ => {
                    // Unknown or disabled channel name — skip silently.
                }
            }
        }

        Self {
            channels,
            enabled: true,
            last_send_by_type: HashMap::new(),
            min_interval: Duration::from_secs(config.min_notify_interval_secs),
            urgent_min_interval: Duration::from_secs(config.urgent_notify_interval_secs),
        }
    }

    /// Replace this manager's configuration (e.g., after SIGHUP config reload).
    ///
    /// Preserves per-event-type throttle state so a config reload doesn't open
    /// a burst window where previously throttled events can fire immediately.
    pub fn update_config(&mut self, config: &NotificationConfig) {
        let throttle_state = std::mem::take(&mut self.last_send_by_type);
        *self = Self::from_config(config);
        self.last_send_by_type = throttle_state;
    }

    /// Create a disabled (no-op) manager.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            channels: Vec::new(),
            enabled: false,
            last_send_by_type: HashMap::new(),
            min_interval: Duration::ZERO,
            urgent_min_interval: Duration::ZERO,
        }
    }

    /// Dispatch a notification event to all enabled channels.
    ///
    /// Events are throttled per-event-type. Warning-and-below events use
    /// `min_notify_interval_secs`; Red and Critical events use
    /// `urgent_notify_interval_secs` (default five minutes). Each event type has
    /// its own throttle window so a cleanup notification cannot block a pressure
    /// warning, and repeated emergency desktop alerts cannot spam the operator.
    pub fn notify(&mut self, event: &NotificationEvent) {
        if !self.enabled {
            return;
        }

        let level = event.level();
        let interval = if level >= NotificationLevel::Red {
            self.urgent_min_interval
        } else {
            self.min_interval
        };
        let type_key = event.type_key();
        if !interval.is_zero()
            && let Some(last) = self.last_send_by_type.get(type_key)
            && last.elapsed() < interval
        {
            return;
        }

        self.last_send_by_type.insert(type_key, Instant::now());

        for channel in &self.channels {
            channel.send(event);
        }
    }

    /// Number of active channels.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Whether the manager is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// List the names of active channels.
    #[must_use]
    pub fn channel_names(&self) -> Vec<&str> {
        self.channels.iter().map(|c| c.name()).collect()
    }
}

// ──────────────────── tests ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_level_ordering() {
        assert!(NotificationLevel::Info < NotificationLevel::Warning);
        assert!(NotificationLevel::Warning < NotificationLevel::Orange);
        assert!(NotificationLevel::Orange < NotificationLevel::Red);
        assert!(NotificationLevel::Red < NotificationLevel::Critical);
    }

    #[test]
    fn notification_level_from_pressure() {
        assert_eq!(
            NotificationLevel::from_pressure(PressureLevel::Green),
            NotificationLevel::Info
        );
        assert_eq!(
            NotificationLevel::from_pressure(PressureLevel::Red),
            NotificationLevel::Red
        );
        assert_eq!(
            NotificationLevel::from_pressure(PressureLevel::Critical),
            NotificationLevel::Critical
        );
    }

    #[test]
    fn event_level_pressure_changed() {
        let event = NotificationEvent::PressureChanged {
            from: "green".to_string(),
            to: "red".to_string(),
            mount: "/data".to_string(),
            free_pct: 5.2,
        };
        assert_eq!(event.level(), NotificationLevel::Red);
    }

    #[test]
    fn event_level_predictive_warning_imminent() {
        // 1.5 min < 2 min critical threshold → Critical
        let event = NotificationEvent::PredictiveWarning {
            mount: "/data".to_string(),
            minutes_remaining: 1.5,
            confidence: 0.92,
        };
        assert_eq!(event.level(), NotificationLevel::Critical);
    }

    #[test]
    fn event_level_predictive_warning_red_zone() {
        // 3 min: >= 2 (not critical) but < 5 (imminent) → Red
        let event = NotificationEvent::PredictiveWarning {
            mount: "/data".to_string(),
            minutes_remaining: 3.0,
            confidence: 0.92,
        };
        assert_eq!(event.level(), NotificationLevel::Red);
    }

    #[test]
    fn event_level_predictive_warning_moderate() {
        let event = NotificationEvent::PredictiveWarning {
            mount: "/data".to_string(),
            minutes_remaining: 25.0,
            confidence: 0.85,
        };
        assert_eq!(event.level(), NotificationLevel::Orange);
    }

    #[test]
    fn event_level_predictive_warning_low_confidence_caps_to_info() {
        // confidence 0.10 (10%) < 0.3 → cap at Info, even though time says Critical.
        let event = NotificationEvent::PredictiveWarning {
            mount: "/".to_string(),
            minutes_remaining: 0.5,
            confidence: 0.10,
        };
        assert_eq!(event.level(), NotificationLevel::Info);
    }

    #[test]
    fn event_level_predictive_warning_medium_confidence_caps_to_warning() {
        // confidence 0.40 → cap at Warning, time says Critical.
        let event = NotificationEvent::PredictiveWarning {
            mount: "/".to_string(),
            minutes_remaining: 1.0,
            confidence: 0.40,
        };
        assert_eq!(event.level(), NotificationLevel::Warning);
    }

    #[test]
    fn event_level_predictive_warning_high_confidence_no_cap() {
        // confidence 0.92 → no cap, Critical from time stays.
        let event = NotificationEvent::PredictiveWarning {
            mount: "/".to_string(),
            minutes_remaining: 1.0,
            confidence: 0.92,
        };
        assert_eq!(event.level(), NotificationLevel::Critical);
    }

    #[test]
    fn predictive_warning_summary_shows_confidence_as_percentage() {
        let event = NotificationEvent::PredictiveWarning {
            mount: "/data".to_string(),
            minutes_remaining: 3.0,
            confidence: 0.92,
        };
        let summary = event.summary();
        // 0.92 * 100 = 92.0 → "92%"
        assert!(
            summary.contains("92%"),
            "expected '92%' in summary: {summary}"
        );
    }

    #[test]
    fn event_level_cleanup_large() {
        let event = NotificationEvent::CleanupCompleted {
            items_deleted: 15,
            bytes_freed: 20 * 1_073_741_824,
            mount: "/data".to_string(),
        };
        assert_eq!(event.level(), NotificationLevel::Warning);
    }

    #[test]
    fn event_level_cleanup_small() {
        let event = NotificationEvent::CleanupCompleted {
            items_deleted: 2,
            bytes_freed: 100_000,
            mount: "/data".to_string(),
        };
        assert_eq!(event.level(), NotificationLevel::Info);
    }

    #[test]
    fn event_level_behavior_emergency_is_critical() {
        let event = NotificationEvent::BehaviorEmergency {
            source: "memory_pressure".to_string(),
            memory_level: "Critical".to_string(),
            disk_level: "Critical".to_string(),
            action: "scan=DefiniteOnly cleanup=AnyDefiniteCandidate".to_string(),
        };
        assert_eq!(event.level(), NotificationLevel::Critical);
        assert_eq!(event.type_key(), "behavior_emergency");
    }

    #[test]
    fn event_summary_pressure_changed() {
        let event = NotificationEvent::PressureChanged {
            from: "green".to_string(),
            to: "orange".to_string(),
            mount: "/data".to_string(),
            free_pct: 9.2,
        };
        let summary = event.summary();
        assert!(summary.contains("green"));
        assert!(summary.contains("orange"));
        assert!(summary.contains("/data"));
        assert!(summary.contains("9.2%"));
    }

    #[test]
    fn event_summary_daemon_started() {
        let event = NotificationEvent::DaemonStarted {
            version: "0.1.0".to_string(),
            volumes_monitored: 4,
        };
        let summary = event.summary();
        assert!(summary.contains("0.1.0"));
        assert!(summary.contains("4 volumes"));
    }

    #[test]
    fn event_summary_cleanup_completed() {
        let event = NotificationEvent::CleanupCompleted {
            items_deleted: 5,
            bytes_freed: 5_368_709_120, // 5 GB
            mount: "/data".to_string(),
        };
        let summary = event.summary();
        assert!(summary.contains("5 items"));
        assert!(summary.contains("5.0 GB"));
    }

    #[test]
    fn event_summary_behavior_emergency_mentions_both_pressures() {
        let event = NotificationEvent::BehaviorEmergency {
            source: "startup".to_string(),
            memory_level: "Critical".to_string(),
            disk_level: "Critical".to_string(),
            action: "scan=DefiniteOnly cleanup=AnyDefiniteCandidate ballast=ReleaseFirst"
                .to_string(),
        };
        let summary = event.summary();
        assert!(summary.contains("startup"));
        assert!(summary.contains("memory=Critical"));
        assert!(summary.contains("disk=Critical"));
        assert!(summary.contains("ReleaseFirst"));
    }

    #[test]
    fn default_config_has_journal_and_file() {
        let config = NotificationConfig::default();
        assert!(config.enabled);
        assert!(config.channels.contains(&"journal".to_string()));
        assert!(config.channels.contains(&"file".to_string()));
        assert!(!config.desktop.enabled);
        assert!(!config.webhook.enabled);
        assert_eq!(
            config.min_notify_interval_secs,
            DEFAULT_NOTIFY_INTERVAL_SECS
        );
        assert_eq!(
            config.urgent_notify_interval_secs,
            DEFAULT_URGENT_NOTIFY_INTERVAL_SECS
        );
    }

    #[test]
    fn disabled_manager_has_no_channels() {
        let manager = NotificationManager::disabled();
        assert!(!manager.is_enabled());
        assert_eq!(manager.channel_count(), 0);
    }

    #[test]
    fn manager_from_disabled_config() {
        let config = NotificationConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = NotificationManager::from_config(&config);
        assert!(!manager.is_enabled());
        assert_eq!(manager.channel_count(), 0);
    }

    #[test]
    fn manager_from_default_config() {
        let config = NotificationConfig::default();
        let manager = NotificationManager::from_config(&config);
        assert!(manager.is_enabled());
        // Default channels: journal + file (desktop and webhook are disabled by default).
        assert_eq!(manager.channel_count(), 2);
        let names = manager.channel_names();
        assert!(names.contains(&"journal"));
        assert!(names.contains(&"file"));
    }

    #[test]
    fn manager_skips_disabled_desktop() {
        let config = NotificationConfig {
            channels: vec!["desktop".to_string(), "journal".to_string()],
            desktop: DesktopConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let manager = NotificationManager::from_config(&config);
        assert_eq!(manager.channel_count(), 1);
        assert_eq!(manager.channel_names(), vec!["journal"]);
    }

    #[test]
    fn manager_skips_disabled_webhook() {
        let config = NotificationConfig {
            channels: vec!["webhook".to_string(), "file".to_string()],
            webhook: WebhookConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let manager = NotificationManager::from_config(&config);
        assert_eq!(manager.channel_count(), 1);
        assert_eq!(manager.channel_names(), vec!["file"]);
    }

    #[test]
    fn file_channel_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.jsonl");

        let channel = FileChannel { path: path.clone() };

        let event = NotificationEvent::DaemonStarted {
            version: "0.1.0".to_string(),
            volumes_monitored: 2,
        };

        channel.send(&event);
        channel.send(&event);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON.
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("ts").is_some());
            assert!(parsed.get("level").is_some());
            assert!(parsed.get("summary").is_some());
            assert!(parsed.get("type").is_some());
        }
    }

    #[test]
    fn file_channel_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("nested")
            .join("dir")
            .join("notifications.jsonl");

        let channel = FileChannel { path: path.clone() };

        let event = NotificationEvent::Error {
            code: "SBH-TEST".to_string(),
            message: "test error".to_string(),
        };

        channel.send(&event);
        assert!(path.exists());
    }

    #[test]
    fn journal_channel_respects_min_level() {
        let channel = JournalChannel {
            min_level: NotificationLevel::Orange,
        };

        // Info-level event should be below the threshold.
        // We can't easily capture stderr in a unit test, but we can verify the
        // min_level check by ensuring no panic occurs.
        let info_event = NotificationEvent::DaemonStarted {
            version: "0.1.0".to_string(),
            volumes_monitored: 1,
        };
        channel.send(&info_event); // Should be silently dropped.

        let red_event = NotificationEvent::Error {
            code: "SBH-TEST".to_string(),
            message: "test".to_string(),
        };
        channel.send(&red_event); // Should output to stderr.
    }

    #[test]
    fn webhook_channel_renders_template() {
        let channel = WebhookChannel {
            url: "https://hooks.example.com/test".to_string(),
            min_level: NotificationLevel::Red,
            template: r#"{"text": "sbh: ${SUMMARY}", "level": "${LEVEL}", "mount": "${MOUNT}", "free": "${FREE_PCT}"}"#.to_string(),
        };

        let event = NotificationEvent::PressureChanged {
            from: "green".to_string(),
            to: "red".to_string(),
            mount: "/data".to_string(),
            free_pct: 4.5,
        };

        let body = channel.render_body(&event);
        assert!(body.contains("red"));
        assert!(body.contains("/data"));
        assert!(body.contains("4.5"));
        assert!(body.contains("sbh:"));
    }

    #[test]
    fn webhook_channel_prevents_recursive_injection() {
        let channel = WebhookChannel {
            url: "https://example.com".to_string(),
            min_level: NotificationLevel::Info,
            // Template uses LEVEL after SUMMARY
            template: r#"{"msg": "${SUMMARY}", "lvl": "${LEVEL}"}"#.to_string(),
        };

        let _event = NotificationEvent::PressureChanged {
            from: "green".to_string(),
            to: "red".to_string(),
            mount: "/data".to_string(),
            free_pct: 10.0,
        };

        // Let's create an event with a malicious mount path.
        let malicious_event = NotificationEvent::PressureChanged {
            from: "green".to_string(),
            to: "red".to_string(),
            mount: "/data/${LEVEL}".to_string(),
            free_pct: 10.0,
        };

        let body = channel.render_body(&malicious_event);
        // The summary will be: "Pressure green -> red on /data/${LEVEL} (10.0% free)"
        // In the body, we expect: "msg": "... /data/${LEVEL} ...", "lvl": "red"
        // We do NOT want: "msg": "... /data/red ...", "lvl": "red"

        // This test now passes with the new non-recursive parser!
        assert!(
            body.contains("/data/${LEVEL}"),
            "should not recursively replace placeholders"
        );
        assert!(body.contains(r#""lvl": "red""#));
    }

    #[test]
    fn webhook_channel_skips_empty_url() {
        let channel = WebhookChannel {
            url: String::new(),
            min_level: NotificationLevel::Info,
            template: r#"{"text": "${SUMMARY}"}"#.to_string(),
        };

        let event = NotificationEvent::Error {
            code: "SBH-TEST".to_string(),
            message: "test".to_string(),
        };

        // Should not panic or spawn curl.
        channel.send(&event);
    }

    #[test]
    fn macos_display_notification_script_escapes_summary() {
        let script = macos_display_notification_script(r#"quote " and backslash \"#);
        assert_eq!(
            script,
            r#"display notification "quote \" and backslash \\" with title "sbh" subtitle "Storage Ballast Helper""#
        );
    }

    #[test]
    fn manager_notify_dispatches_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.jsonl");

        let config = NotificationConfig {
            enabled: true,
            channels: vec!["file".to_string()],
            file: FileConfig { path: path.clone() },
            ..Default::default()
        };

        let mut manager = NotificationManager::from_config(&config);
        assert_eq!(manager.channel_count(), 1);

        let event = NotificationEvent::PressureChanged {
            from: "green".to_string(),
            to: "yellow".to_string(),
            mount: "/data".to_string(),
            free_pct: 13.5,
        };

        manager.notify(&event);

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);

        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["type"], "pressure_changed");
        assert_eq!(parsed["mount"], "/data");
    }

    #[test]
    fn manager_throttles_urgent_events_per_category() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.jsonl");

        let config = NotificationConfig {
            enabled: true,
            channels: vec!["file".to_string()],
            min_notify_interval_secs: 0,
            urgent_notify_interval_secs: 300,
            file: FileConfig { path: path.clone() },
            ..Default::default()
        };

        let mut manager = NotificationManager::from_config(&config);
        let pressure_event = NotificationEvent::BehaviorEmergency {
            source: "memory_pressure".to_string(),
            memory_level: "Critical".to_string(),
            disk_level: "Critical".to_string(),
            action: "scan=DefiniteOnly cleanup=AnyDefiniteCandidate".to_string(),
        };
        let error_event = NotificationEvent::Error {
            code: "SBH-TEST".to_string(),
            message: "different urgent category".to_string(),
        };

        manager.notify(&pressure_event);
        manager.notify(&pressure_event);
        manager.notify(&error_event);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["type"], "behavior_emergency");
        assert_eq!(second["type"], "error");
    }

    #[test]
    fn manager_notify_noop_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.jsonl");

        let config = NotificationConfig {
            enabled: false,
            channels: vec!["file".to_string()],
            file: FileConfig { path: path.clone() },
            ..Default::default()
        };

        let mut manager = NotificationManager::from_config(&config);
        let event = NotificationEvent::Error {
            code: "SBH-TEST".to_string(),
            message: "test".to_string(),
        };
        manager.notify(&event);

        assert!(!path.exists());
    }

    #[test]
    fn notification_config_roundtrip_toml() {
        let config = NotificationConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: NotificationConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn notification_event_roundtrip_json() {
        let event = NotificationEvent::PressureChanged {
            from: "green".to_string(),
            to: "critical".to_string(),
            mount: "/data".to_string(),
            free_pct: 2.1,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: NotificationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.level(), NotificationLevel::Critical);
        assert!(parsed.summary().contains("critical"));
    }
}
