//! Daemon control socket (bd-rc-master-ajg1.4.9).
//!
//! A Unix domain socket beside `state.json` (`control.sock`, mode `0600`)
//! that answers one JSON request per connection with one JSON response:
//!
//! ```text
//! {"cmd": "ping", "args": {}, "token": "<32 hex>"}
//! {"ok": true, "result": {...}}
//! {"ok": false, "result": null, "error": {"code": "unauthorized", "message": "..."}}
//! ```
//!
//! The token is minted per boot by [`crate::daemon::self_monitor::DaemonLock`]
//! and written into `daemon.lock`; a client that can read the lock file can
//! talk. The socket's mode is the real access control, the token guards
//! against a stale or foreign client talking to a daemon that restarted.
//!
//! The listener thread accepts, a short-lived thread per connection reads
//! one line (bounded), checks the token, applies a token-bucket rate limit
//! and a concurrency bound, and hands the parsed [`ControlCommand`] to the
//! daemon's [`ControlBackend`]. Everything the daemon has to execute on its
//! own thread (a fresh state write, ballast release) goes through the
//! backend's channel to the main loop; `ping`, `explain` and the signal-flag
//! commands are answered by the connection thread itself.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::errors::{Result, SbhError};
use crate::daemon::self_monitor::{DaemonLockProbe, probe_daemon_lock};

/// File name of the socket, a sibling of `state.json`.
pub const CONTROL_SOCKET_FILE_NAME: &str = "control.sock";
/// Connections handled at the same time; the rest get `busy`.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 8;
/// Sustained request rate the socket accepts before answering `rate_limited`.
pub const MAX_REQUESTS_PER_SECOND: f64 = 10.0;
/// Longest request line accepted; longer ones are rejected unread.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Read and write deadline for one connection, both directions.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the listener thread checks the shutdown flag while idle.
const ACCEPT_POLL: Duration = Duration::from_millis(100);

/// Longest socket path the daemon will try to bind. `sockaddr_un` holds 108
/// bytes including the terminator; a few are kept in reserve.
pub const MAX_SOCKET_PATH_BYTES: usize = 100;

/// The preferred socket path for a given `state.json` path: a sibling.
#[must_use]
pub fn control_socket_path(state_file: &Path) -> PathBuf {
    state_file.with_file_name(CONTROL_SOCKET_FILE_NAME)
}

/// Where the daemon actually binds.
///
/// The sibling of `state.json` unless that path is too long for a Unix
/// socket address, in which case a short path under the temp directory
/// named by a hash of the preferred path. The chosen path is written into
/// `daemon.lock`, so clients never derive it.
#[must_use]
pub fn resolve_control_socket_path(state_file: &Path) -> PathBuf {
    use std::hash::{Hash as _, Hasher as _};

    let preferred = control_socket_path(state_file);
    if preferred.as_os_str().len() <= MAX_SOCKET_PATH_BYTES {
        return preferred;
    }
    let mut hasher = std::hash::DefaultHasher::new();
    preferred.hash(&mut hasher);
    std::env::temp_dir().join(format!("sbh-control-{:016x}.sock", hasher.finish()))
}

/// What a client needs to talk to the running daemon: the socket it bound
/// and this boot's token, both from `daemon.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEndpoint {
    /// The socket the daemon bound (see [`resolve_control_socket_path`]).
    pub socket: PathBuf,
    /// The per-boot token every request must carry.
    pub token: String,
}

/// The endpoint of the daemon holding the lock beside `state_file`, if
/// there is one and its lock file carries a token. A lock written before
/// the socket path was recorded falls back to the sibling path.
#[must_use]
pub fn read_endpoint(state_file: &Path) -> Option<ControlEndpoint> {
    match probe_daemon_lock(state_file) {
        DaemonLockProbe::Held(info) if !info.token.is_empty() => Some(ControlEndpoint {
            socket: if info.control_socket.is_empty() {
                control_socket_path(state_file)
            } else {
                PathBuf::from(info.control_socket)
            },
            token: info.token,
        }),
        _ => None,
    }
}

/// One request line.
#[derive(Debug, Clone, Deserialize)]
pub struct ControlRequest {
    /// Command name: `ping`, `status`, `scan-now`, `reload`, `policy`,
    /// `explain`, `ballast` or `shutdown`.
    pub cmd: String,
    /// Command arguments; an object, or absent.
    #[serde(default)]
    pub args: Value,
    /// The daemon's per-boot token from `daemon.lock`.
    #[serde(default)]
    pub token: String,
}

/// A failed request: a stable code plus a human sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlError {
    /// `unauthorized`, `bad_request`, `unknown_command`, `rate_limited`,
    /// `busy`, `not_found`, `unavailable`, `timeout` or `failed`.
    pub code: String,
    /// What went wrong, for a person.
    pub message: String,
}

/// One response line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    /// Whether the command ran.
    pub ok: bool,
    /// The command's result document (null on failure).
    #[serde(default)]
    pub result: Value,
    /// Why the command did not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ControlError>,
}

impl ControlResponse {
    /// A successful response carrying `result`.
    #[must_use]
    pub fn success(result: Value) -> Self {
        Self {
            ok: true,
            result,
            error: None,
        }
    }

    /// A refused or failed response with a stable `code`.
    #[must_use]
    pub fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: Value::Null,
            error: Some(ControlError {
                code: code.to_string(),
                message: message.into(),
            }),
        }
    }
}

/// `policy` sub-actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// observe -> canary, canary -> enforce.
    Promote,
    /// enforce -> canary, canary -> observe.
    Demote,
    /// Report the active mode.
    Status,
}

impl PolicyAction {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Demote => "demote",
            Self::Status => "status",
        }
    }
}

/// `ballast` sub-actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BallastAction {
    /// Release up to `count` ballast files on `mount` (every pool when
    /// `None`).
    Release {
        /// Files to release, at least one.
        count: usize,
        /// The pool's mount point, or every pool.
        mount: Option<PathBuf>,
    },
    /// Rebuild one released file per pool (or on `mount`).
    Replenish {
        /// The pool's mount point, or every pool.
        mount: Option<PathBuf>,
    },
}

/// A parsed, validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    /// Liveness and identity of the daemon.
    Ping,
    /// A fresh `state.json`, written on request.
    Status,
    /// Queue a forced scan on the next tick.
    ScanNow {
        /// Roots to scan; empty means the configured roots.
        paths: Vec<PathBuf>,
        /// Ignore the rescan cooldown.
        force: bool,
    },
    /// Re-read the configuration (the SIGHUP path).
    Reload,
    /// Show or move the policy engine's mode.
    Policy(PolicyAction),
    /// Look a decision up in the ledger by its stable id.
    Explain {
        /// The decision id (12 hex characters).
        id: String,
    },
    /// Release or replenish ballast.
    Ballast(BallastAction),
    /// Stop the daemon cleanly.
    Shutdown,
}

impl ControlCommand {
    /// Parse a request; unknown commands and malformed arguments are errors
    /// the client sees verbatim.
    pub fn parse(request: &ControlRequest) -> std::result::Result<Self, ControlError> {
        let args = &request.args;
        let bad = |message: String| ControlError {
            code: "bad_request".to_string(),
            message,
        };
        match request.cmd.as_str() {
            "ping" => Ok(Self::Ping),
            "status" => Ok(Self::Status),
            "scan-now" | "scan_now" => {
                let paths = match args.get("paths") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| {
                            item.as_str().map(PathBuf::from).ok_or_else(|| {
                                bad("scan-now: every path must be a string".to_string())
                            })
                        })
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                    Some(other) => {
                        return Err(bad(format!(
                            "scan-now: paths must be an array of strings, got {other}"
                        )));
                    }
                };
                let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
                Ok(Self::ScanNow { paths, force })
            }
            "reload" => Ok(Self::Reload),
            "policy" => {
                let action = args
                    .get("action")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("policy: args.action is required".to_string()))?;
                match action {
                    "promote" => Ok(Self::Policy(PolicyAction::Promote)),
                    "demote" => Ok(Self::Policy(PolicyAction::Demote)),
                    "status" => Ok(Self::Policy(PolicyAction::Status)),
                    other => Err(bad(format!(
                        "policy: action must be promote, demote or status, got {other:?}"
                    ))),
                }
            }
            "explain" => {
                let id = args
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| bad("explain: args.id is required".to_string()))?;
                Ok(Self::Explain { id: id.to_string() })
            }
            "ballast" => {
                let mount = args.get("mount").and_then(Value::as_str).map(PathBuf::from);
                if let Some(count) = args.get("release") {
                    let count = count.as_u64().filter(|count| *count > 0).ok_or_else(|| {
                        bad("ballast: release must be a positive integer".to_string())
                    })?;
                    let count = usize::try_from(count)
                        .map_err(|_| bad("ballast: release count is too large".to_string()))?;
                    return Ok(Self::Ballast(BallastAction::Release { count, mount }));
                }
                if args.get("replenish").and_then(Value::as_bool) == Some(true) {
                    return Ok(Self::Ballast(BallastAction::Replenish { mount }));
                }
                Err(bad(
                    "ballast: give release = <count> or replenish = true".to_string()
                ))
            }
            "shutdown" => Ok(Self::Shutdown),
            other => Err(ControlError {
                code: "unknown_command".to_string(),
                message: format!(
                    "unknown command {other:?}; known: ping, status, scan-now, reload, policy, explain, ballast, shutdown"
                ),
            }),
        }
    }

    /// The wire name of the command.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::ScanNow { .. } => "scan-now",
            Self::Reload => "reload",
            Self::Policy(_) => "policy",
            Self::Explain { .. } => "explain",
            Self::Ballast(_) => "ballast",
            Self::Shutdown => "shutdown",
        }
    }

    /// Whether the command changes daemon state (logged with the caller's
    /// uid) rather than reading it.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        match self {
            Self::Ping | Self::Status | Self::Explain { .. } => false,
            Self::Policy(action) => !matches!(action, PolicyAction::Status),
            Self::ScanNow { .. } | Self::Reload | Self::Ballast(_) | Self::Shutdown => true,
        }
    }
}

/// Who connected, from `SO_PEERCRED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// Effective user id of the client process.
    pub uid: u32,
    /// Effective group id of the client process.
    pub gid: u32,
    /// Process id of the client.
    pub pid: i32,
}

impl Peer {
    fn of(stream: &UnixStream) -> Option<Self> {
        // Linux: SO_PEERCRED gives uid/gid/pid. Other platforms have no
        // safe (forbid(unsafe_code)) peer-credential API in nix; `peer` is
        // audit-log-only, so None ("?") is honest there. The macOS socket
        // is a user-scoped LaunchAgent socket (same user), and mutating
        // commands are not gated on the uid.
        #[cfg(target_os = "linux")]
        {
            let creds =
                nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
                    .ok()?;
            Some(Self {
                uid: creds.uid(),
                gid: creds.gid(),
                pid: creds.pid(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            None
        }
    }
}

/// What the daemon does with a parsed command.
pub trait ControlBackend: Send + Sync {
    /// Run `command` for `peer` (`None` when the peer credentials could not
    /// be read) and produce the response line.
    fn handle(&self, command: ControlCommand, peer: Option<Peer>) -> ControlResponse;
}

/// Token bucket: `MAX_REQUESTS_PER_SECOND` sustained, a burst of the same
/// size.
struct RateLimiter {
    tokens: f64,
    last: Instant,
    per_second: f64,
}

impl RateLimiter {
    fn new(per_second: f64) -> Self {
        Self {
            tokens: per_second,
            last: Instant::now(),
            per_second,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = elapsed
            .mul_add(self.per_second, self.tokens)
            .min(self.per_second);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A counted slot; dropping it frees the slot.
struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn acquire(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let mut current = active.load(Ordering::Acquire);
        loop {
            if current >= limit {
                return None;
            }
            match active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(Arc::clone(active))),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Shared {
    token: String,
    backend: Arc<dyn ControlBackend>,
    limiter: Mutex<RateLimiter>,
    active: Arc<AtomicUsize>,
}

/// The running listener. Dropping it (or calling [`Self::stop`]) unlinks
/// the socket.
pub struct ControlServer {
    path: PathBuf,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl ControlServer {
    /// Bind `path` (a stale socket file is unlinked first), restrict it to
    /// the owner, and start serving. `token` is the per-boot secret every
    /// request must carry.
    pub fn start(path: &Path, token: &str, backend: Arc<dyn ControlBackend>) -> Result<Self> {
        if path.exists() {
            std::fs::remove_file(path).map_err(|source| SbhError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| SbhError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let listener = UnixListener::bind(path).map_err(|source| SbhError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |source| SbhError::Io {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        }
        listener
            .set_nonblocking(true)
            .map_err(|source| SbhError::Io {
                path: path.to_path_buf(),
                source,
            })?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            token: token.to_string(),
            backend,
            limiter: Mutex::new(RateLimiter::new(MAX_REQUESTS_PER_SECOND)),
            active: Arc::new(AtomicUsize::new(0)),
        });
        let accept_shutdown = Arc::clone(&shutdown);
        let join = thread::Builder::new()
            .name("sbh-control".to_string())
            .spawn(move || accept_loop(&listener, &accept_shutdown, &shared))
            .map_err(|source| SbhError::Runtime {
                details: format!("failed to spawn control socket thread: {source}"),
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            shutdown,
            join: Some(join),
        })
    }

    /// Where the socket lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop accepting, join the listener, unlink the socket.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn accept_loop(listener: &UnixListener, shutdown: &AtomicBool, shared: &Arc<Shared>) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let shared = Arc::clone(shared);
                let spawned = thread::Builder::new()
                    .name("sbh-control-conn".to_string())
                    .spawn(move || serve_connection(&stream, &shared));
                if let Err(error) = spawned {
                    eprintln!("[SBH-CONTROL] could not spawn a connection thread: {error}");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) => {
                eprintln!("[SBH-CONTROL] accept failed: {error}");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

fn serve_connection(stream: &UnixStream, shared: &Shared) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let response = respond(stream, shared);
    let mut writer = stream;
    if let Ok(mut line) = serde_json::to_string(&response) {
        line.push('\n');
        let _ = writer.write_all(line.as_bytes());
        let _ = writer.flush();
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn respond(stream: &UnixStream, shared: &Shared) -> ControlResponse {
    let Some(_slot) = ConnectionSlot::acquire(&shared.active, MAX_CONCURRENT_CONNECTIONS) else {
        return ControlResponse::failure(
            "busy",
            format!("{MAX_CONCURRENT_CONNECTIONS} control connections are already open"),
        );
    };
    if !shared.limiter.lock().allow(Instant::now()) {
        return ControlResponse::failure(
            "rate_limited",
            format!("more than {MAX_REQUESTS_PER_SECOND} requests per second"),
        );
    }
    let mut line = String::new();
    let mut reader = BufReader::new(stream).take(MAX_LINE_BYTES as u64 + 1);
    match reader.read_line(&mut line) {
        Ok(0) => return ControlResponse::failure("bad_request", "empty request"),
        Ok(_) => {}
        Err(error) => {
            return ControlResponse::failure(
                "bad_request",
                format!("could not read request: {error}"),
            );
        }
    }
    if line.len() > MAX_LINE_BYTES {
        return ControlResponse::failure(
            "bad_request",
            format!("request longer than {MAX_LINE_BYTES} bytes"),
        );
    }
    let request: ControlRequest = match serde_json::from_str(line.trim_end()) {
        Ok(request) => request,
        Err(error) => {
            return ControlResponse::failure("bad_request", format!("not a request: {error}"));
        }
    };
    if request.token != shared.token {
        return ControlResponse::failure(
            "unauthorized",
            "token does not match the running daemon's lock file",
        );
    }
    let command = match ControlCommand::parse(&request) {
        Ok(command) => command,
        Err(error) => {
            return ControlResponse {
                ok: false,
                result: Value::Null,
                error: Some(error),
            };
        }
    };
    let peer = Peer::of(stream);
    shared.backend.handle(command, peer)
}

/// Send one request and read one response. `token` is the daemon's current
/// token (see [`read_endpoint`]).
pub fn request(
    socket_path: &Path,
    token: &str,
    cmd: &str,
    args: &Value,
) -> Result<ControlResponse> {
    let stream = UnixStream::connect(socket_path).map_err(|source| SbhError::Io {
        path: socket_path.to_path_buf(),
        source,
    })?;
    let io = |source: std::io::Error| SbhError::Io {
        path: socket_path.to_path_buf(),
        source,
    };
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    let mut line = json!({ "cmd": cmd, "args": args, "token": token }).to_string();
    line.push('\n');
    let mut writer = &stream;
    writer.write_all(line.as_bytes()).map_err(io)?;
    writer.flush().map_err(io)?;
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply).map_err(io)?;
    if reply.trim().is_empty() {
        return Err(SbhError::Runtime {
            details: format!(
                "{}: the daemon closed the connection without answering",
                socket_path.display()
            ),
        });
    }
    serde_json::from_str(reply.trim_end()).map_err(|error| SbhError::Serialization {
        context: "control response",
        details: error.to_string(),
    })
}

/// Persist `[policy] initial_mode = <mode>` so a promotion survives restarts.
///
/// The existing file is copied to `<config>.bak-<stamp>` first, the
/// rewritten file must still load, and the backup path comes back (`None`
/// when no config file existed yet).
pub fn persist_policy_mode(config_path: &Path, mode: &str) -> Result<Option<PathBuf>> {
    let io = |path: &Path, source: std::io::Error| SbhError::Io {
        path: path.to_path_buf(),
        source,
    };
    let (mut document, backup) = if config_path.exists() {
        let raw = std::fs::read_to_string(config_path).map_err(|e| io(config_path, e))?;
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let backup = config_path.with_file_name(format!(
            "{}.bak-{stamp}",
            config_path.file_name().map_or_else(
                || "config.toml".to_string(),
                |name| name.to_string_lossy().into_owned()
            )
        ));
        std::fs::write(&backup, &raw).map_err(|e| io(&backup, e))?;
        let document: toml::Value = toml::from_str(&raw).map_err(|e| SbhError::Serialization {
            context: "config",
            details: e.to_string(),
        })?;
        (document, Some(backup))
    } else {
        (toml::Value::Table(toml::map::Map::new()), None)
    };
    let table = document
        .as_table_mut()
        .ok_or_else(|| SbhError::Serialization {
            context: "config",
            details: "config root is not a table".to_string(),
        })?;
    let policy = table
        .entry("policy")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let policy = policy
        .as_table_mut()
        .ok_or_else(|| SbhError::Serialization {
            context: "config",
            details: "[policy] is not a table".to_string(),
        })?;
    policy.insert(
        "initial_mode".to_string(),
        toml::Value::String(mode.to_string()),
    );
    let rendered = toml::to_string_pretty(&document).map_err(|e| SbhError::Serialization {
        context: "config",
        details: e.to_string(),
    })?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    let temp = config_path.with_extension("toml.tmp");
    std::fs::write(&temp, &rendered).map_err(|e| io(&temp, e))?;
    if let Err(error) = crate::core::config::Config::load(Some(&temp)) {
        let _ = std::fs::remove_file(&temp);
        return Err(SbhError::Runtime {
            details: format!("refusing to write a config that does not load: {error}"),
        });
    }
    std::fs::rename(&temp, config_path).map_err(|e| io(config_path, e))?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoBackend;

    impl ControlBackend for EchoBackend {
        fn handle(&self, command: ControlCommand, peer: Option<Peer>) -> ControlResponse {
            ControlResponse::success(json!({
                "command": command.name(),
                "mutating": command.is_mutating(),
                "peer_uid": peer.map(|p| p.uid),
            }))
        }
    }

    struct SlowBackend(Duration);

    impl ControlBackend for SlowBackend {
        fn handle(&self, command: ControlCommand, _peer: Option<Peer>) -> ControlResponse {
            thread::sleep(self.0);
            ControlResponse::success(json!({ "command": command.name() }))
        }
    }

    fn req(cmd: &str, args: Value) -> ControlRequest {
        ControlRequest {
            cmd: cmd.to_string(),
            args,
            token: String::new(),
        }
    }

    #[test]
    fn parse_accepts_every_documented_command_and_rejects_the_rest() {
        assert_eq!(
            ControlCommand::parse(&req("ping", Value::Null)).unwrap(),
            ControlCommand::Ping
        );
        assert_eq!(
            ControlCommand::parse(&req(
                "scan-now",
                json!({"paths": ["/a", "/b"], "force": true})
            ))
            .unwrap(),
            ControlCommand::ScanNow {
                paths: vec![PathBuf::from("/a"), PathBuf::from("/b")],
                force: true
            }
        );
        assert_eq!(
            ControlCommand::parse(&req("policy", json!({"action": "promote"}))).unwrap(),
            ControlCommand::Policy(PolicyAction::Promote)
        );
        assert_eq!(
            ControlCommand::parse(&req("explain", json!({"id": "41d4fafc918d"}))).unwrap(),
            ControlCommand::Explain {
                id: "41d4fafc918d".to_string()
            }
        );
        assert_eq!(
            ControlCommand::parse(&req("ballast", json!({"release": 2, "mount": "/data"})))
                .unwrap(),
            ControlCommand::Ballast(BallastAction::Release {
                count: 2,
                mount: Some(PathBuf::from("/data"))
            })
        );
        assert_eq!(
            ControlCommand::parse(&req("ballast", json!({"replenish": true}))).unwrap(),
            ControlCommand::Ballast(BallastAction::Replenish { mount: None })
        );
        assert_eq!(
            ControlCommand::parse(&req("shutdown", Value::Null)).unwrap(),
            ControlCommand::Shutdown
        );

        let unknown = ControlCommand::parse(&req("reboot", Value::Null)).unwrap_err();
        assert_eq!(unknown.code, "unknown_command");
        let bad_policy =
            ControlCommand::parse(&req("policy", json!({"action": "yolo"}))).unwrap_err();
        assert_eq!(bad_policy.code, "bad_request");
        let bad_paths =
            ControlCommand::parse(&req("scan-now", json!({"paths": "/a"}))).unwrap_err();
        assert_eq!(bad_paths.code, "bad_request");
        let no_id = ControlCommand::parse(&req("explain", json!({}))).unwrap_err();
        assert_eq!(no_id.code, "bad_request");
        let zero = ControlCommand::parse(&req("ballast", json!({"release": 0}))).unwrap_err();
        assert_eq!(zero.code, "bad_request");
    }

    #[test]
    fn mutating_commands_are_the_ones_that_change_state() {
        assert!(!ControlCommand::Ping.is_mutating());
        assert!(!ControlCommand::Status.is_mutating());
        assert!(!ControlCommand::Policy(PolicyAction::Status).is_mutating());
        assert!(ControlCommand::Policy(PolicyAction::Promote).is_mutating());
        assert!(ControlCommand::Reload.is_mutating());
        assert!(ControlCommand::Shutdown.is_mutating());
    }

    #[test]
    fn rate_limiter_allows_a_burst_then_refills_at_the_rate() {
        let mut limiter = RateLimiter::new(10.0);
        let start = Instant::now();
        let allowed = (0..15).filter(|_| limiter.allow(start)).count();
        assert_eq!(allowed, 10, "burst of one second's worth");
        assert!(!limiter.allow(start + Duration::from_millis(50)));
        assert!(limiter.allow(start + Duration::from_millis(200)));
    }

    #[test]
    fn connection_slots_are_bounded_and_released_on_drop() {
        let active = Arc::new(AtomicUsize::new(0));
        let held: Vec<ConnectionSlot> = (0..3)
            .map(|_| ConnectionSlot::acquire(&active, 3).unwrap())
            .collect();
        assert!(ConnectionSlot::acquire(&active, 3).is_none());
        drop(held);
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert!(ConnectionSlot::acquire(&active, 3).is_some());
    }

    #[test]
    fn server_replaces_a_stale_socket_answers_with_the_token_and_refuses_without_it() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state.json");
        let socket = control_socket_path(&state);
        std::fs::write(&socket, b"stale").unwrap();

        let server = ControlServer::start(&socket, "secret", Arc::new(EchoBackend)).unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "socket mode");
        }

        let started = Instant::now();
        let reply = request(&socket, "secret", "ping", &json!({})).unwrap();
        let latency = started.elapsed();
        assert!(reply.ok, "{reply:?}");
        assert_eq!(reply.result["command"], "ping");
        assert_eq!(reply.result["mutating"], false);
        assert_eq!(
            reply.result["peer_uid"],
            json!(nix::unistd::getuid().as_raw()),
            "SO_PEERCRED reports the client"
        );
        assert!(
            latency < Duration::from_millis(500),
            "ping took {latency:?}; the design target is 50 ms on an idle host"
        );
        eprintln!("control socket ping latency: {latency:?}");

        let refused = request(&socket, "wrong", "shutdown", &json!({})).unwrap();
        assert!(!refused.ok);
        assert_eq!(refused.error.unwrap().code, "unauthorized");

        let unknown = request(&socket, "secret", "reboot", &json!({})).unwrap();
        assert_eq!(unknown.error.unwrap().code, "unknown_command");

        server.stop();
        assert!(!socket.exists(), "stop unlinks the socket");
    }

    // The intermediate Vec is the point: every thread must be spawned before
    // any is joined, or the requests would run one at a time.
    #[allow(clippy::needless_collect)]
    #[test]
    fn server_rate_limits_a_flood_and_bounds_concurrent_connections() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let server = ControlServer::start(
            &socket,
            "secret",
            Arc::new(SlowBackend(Duration::from_millis(300))),
        )
        .unwrap();

        // Twelve connections at once against an 8-slot server that holds
        // each for 300 ms: at least one is turned away as busy, and the
        // token bucket (10/s) refuses at least one more.
        let handles: Vec<_> = (0..12)
            .map(|_| {
                let socket = socket.clone();
                thread::spawn(move || request(&socket, "secret", "ping", &json!({})).unwrap())
            })
            .collect();
        let replies: Vec<ControlResponse> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        let codes: Vec<String> = replies
            .iter()
            .filter_map(|r| r.error.as_ref().map(|e| e.code.clone()))
            .collect();
        let ok = replies.iter().filter(|r| r.ok).count();
        assert!(ok >= 1, "{codes:?}");
        assert!(
            codes.iter().any(|c| c == "busy" || c == "rate_limited"),
            "12 simultaneous requests must trip a limit: ok={ok} codes={codes:?}"
        );
        assert!(ok <= MAX_CONCURRENT_CONNECTIONS, "ok={ok}");
        server.stop();
    }

    #[test]
    fn socket_path_falls_back_to_a_short_temp_path_when_the_sibling_is_too_long() {
        let short = PathBuf::from("/var/lib/sbh/state.json");
        assert_eq!(
            resolve_control_socket_path(&short),
            PathBuf::from("/var/lib/sbh/control.sock")
        );

        let long = PathBuf::from(format!("/{}/state.json", "d".repeat(120)));
        let resolved = resolve_control_socket_path(&long);
        assert!(
            resolved.as_os_str().len() <= MAX_SOCKET_PATH_BYTES,
            "{}",
            resolved.display()
        );
        assert!(
            resolved.starts_with(std::env::temp_dir()),
            "{}",
            resolved.display()
        );
        assert_eq!(
            resolved,
            resolve_control_socket_path(&long),
            "deterministic for the same state file"
        );
        assert_ne!(
            resolved,
            resolve_control_socket_path(&PathBuf::from(format!("/{}/state.json", "e".repeat(120))))
        );
    }

    #[test]
    fn persist_policy_mode_backs_up_and_rewrites_only_the_policy_table() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config.toml");
        std::fs::write(
            &config,
            "[scanner]\nroot_paths = [\"/data/projects\"]\n\n[policy]\ninitial_mode = \"observe\"\n",
        )
        .unwrap();
        let backup = persist_policy_mode(&config, "canary").unwrap().unwrap();
        assert!(backup.exists());
        assert!(
            std::fs::read_to_string(&backup)
                .unwrap()
                .contains("initial_mode = \"observe\"")
        );
        let rewritten = std::fs::read_to_string(&config).unwrap();
        assert!(
            rewritten.contains("initial_mode = \"canary\""),
            "{rewritten}"
        );
        assert!(rewritten.contains("root_paths"), "{rewritten}");
        let loaded = crate::core::config::Config::load(Some(&config)).unwrap();
        assert_eq!(
            loaded.policy.initial_mode,
            crate::daemon::policy::ActiveMode::Canary
        );

        let fresh = temp.path().join("new").join("config.toml");
        assert!(persist_policy_mode(&fresh, "enforce").unwrap().is_none());
        assert!(
            std::fs::read_to_string(&fresh)
                .unwrap()
                .contains("initial_mode = \"enforce\"")
        );
    }
}
