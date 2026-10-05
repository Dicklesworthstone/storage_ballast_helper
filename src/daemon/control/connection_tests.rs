//! Exercise admission and I/O through the actual connection entry point.

use super::*;
use std::io::{Read as _, Write as _};
use std::net::Shutdown;

struct CountingBackend(AtomicUsize);

impl ControlBackend for CountingBackend {
    fn handle(&self, command: ControlCommand, _peer: Option<Peer>) -> ControlResponse {
        self.0.fetch_add(1, Ordering::SeqCst);
        ControlResponse::success(json!({"command": command.name()}))
    }
}

fn shared(backend: Arc<dyn ControlBackend>) -> Shared {
    Shared {
        token: "secret".to_string(),
        backend,
        limiter: Mutex::new(RateLimiter::new(1000.0)),
        active: Arc::new(AtomicUsize::new(0)),
    }
}

fn ping() -> Vec<u8> {
    transport::encode_frame(&json!({"cmd": "ping", "token": "secret"}), MAX_LINE_BYTES)
        .unwrap()
}

fn reply(stream: &UnixStream) -> ControlResponse {
    let frame = transport::read_frame(stream, MAX_RESPONSE_BYTES, Instant::now(), IO_TIMEOUT)
        .unwrap();
    serde_json::from_slice(&frame).unwrap()
}

#[test]
fn admission_reserves_capacity_before_any_worker_can_run() {
    let backend = Arc::new(CountingBackend(AtomicUsize::new(0)));
    let shared = shared(backend.clone());
    let now = Instant::now();
    let slots: Vec<_> = (0..MAX_CONCURRENT_CONNECTIONS)
        .map(|_| admit_connection(&shared, now).unwrap())
        .collect();
    for _ in 0..100 {
        let refusal = admit_connection(&shared, now).err().unwrap();
        assert_eq!(refusal.error.unwrap().code, "busy");
        assert_eq!(shared.active.load(Ordering::Acquire), MAX_CONCURRENT_CONNECTIONS);
    }
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    // This is also what happens when spawning the owning closure fails.
    drop(slots);
    assert_eq!(shared.active.load(Ordering::Acquire), 0);
    assert!(admit_connection(&shared, now).is_ok());
}

#[test]
fn a_rate_limited_connection_returns_its_reserved_slot() {
    let shared = shared(Arc::new(CountingBackend(AtomicUsize::new(0))));
    let now = Instant::now();
    {
        let mut limiter = shared.limiter.lock();
        limiter.tokens = 0.0;
        limiter.last = now;
    }
    let refusal = admit_connection(&shared, now).err().unwrap();
    assert_eq!(refusal.error.unwrap().code, "rate_limited");
    assert_eq!(shared.active.load(Ordering::Acquire), 0);
}

#[test]
fn a_request_that_expired_before_worker_start_never_reaches_the_backend() {
    let backend = Arc::new(CountingBackend(AtomicUsize::new(0)));
    let shared = shared(backend.clone());
    let slot = admit_connection(&shared, Instant::now()).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&ping()).unwrap();
    let expired = Instant::now().checked_sub(IO_TIMEOUT).unwrap();
    serve_connection(&server, &shared, slot, expired);
    assert_eq!(reply(&client).error.unwrap().code, "timeout");
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert_eq!(shared.active.load(Ordering::Acquire), 0);
}

#[test]
fn unauthorized_requests_release_their_slot_without_dispatching() {
    let backend = Arc::new(CountingBackend(AtomicUsize::new(0)));
    let shared = shared(backend.clone());
    let slot = admit_connection(&shared, Instant::now()).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(b"{\"cmd\":\"shutdown\",\"token\":\"wrong\"}\n").unwrap();
    serve_connection(&server, &shared, slot, Instant::now());
    assert_eq!(reply(&client).error.unwrap().code, "unauthorized");
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert_eq!(shared.active.load(Ordering::Acquire), 0);
}

struct LargeBackend(usize);

impl ControlBackend for LargeBackend {
    fn handle(&self, _command: ControlCommand, _peer: Option<Peer>) -> ControlResponse {
        ControlResponse::success(json!({"data": "x".repeat(self.0)}))
    }
}

#[test]
fn a_slow_response_reader_holds_its_slot_until_delivery_finishes() {
    let shared = Arc::new(shared(Arc::new(LargeBackend(1024 * 1024))));
    let (mut client, server) = UnixStream::pair().unwrap();
    nix::sys::socket::setsockopt(&server, nix::sys::socket::sockopt::SndBuf, &4096).unwrap();
    let slot = admit_connection(&shared, Instant::now()).unwrap();
    let worker_shared = Arc::clone(&shared);
    let worker = thread::spawn(move || {
        serve_connection(&server, &worker_shared, slot, Instant::now());
    });
    client.write_all(&ping()).unwrap();
    client.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    // One byte proves the backend returned and response delivery has started.
    // Do not drain the rest: the 1 MiB reply cannot fit in the 4 KiB send buffer.
    let mut first = [0u8; 1];
    client.read_exact(&mut first).unwrap();
    let during_delivery = shared.active.load(Ordering::Acquire);
    let held: Vec<_> = (1..MAX_CONCURRENT_CONNECTIONS)
        .map(|_| admit_connection(&shared, Instant::now()).unwrap())
        .collect();
    let refused = admit_connection(&shared, Instant::now()).err();
    // Always unblock and join before assertions that could panic.
    client.shutdown(Shutdown::Both).unwrap();
    worker.join().unwrap();
    drop(held);
    assert_eq!(during_delivery, 1);
    assert_eq!(refused.unwrap().error.unwrap().code, "busy");
    assert_eq!(shared.active.load(Ordering::Acquire), 0);
}

#[test]
fn oversized_requests_do_not_dispatch_and_do_not_poison_the_next_connection() {
    let backend = Arc::new(CountingBackend(AtomicUsize::new(0)));
    let shared = Arc::new(shared(backend.clone()));
    let (client, server) = UnixStream::pair().unwrap();
    let slot = admit_connection(&shared, Instant::now()).unwrap();
    let worker_shared = Arc::clone(&shared);
    let worker = thread::spawn(move || {
        serve_connection(&server, &worker_shared, slot, Instant::now());
    });
    transport::write_frame(&client, &vec![b'x'; MAX_LINE_BYTES + 1], Instant::now(), IO_TIMEOUT)
        .unwrap();
    let rejected = reply(&client);
    worker.join().unwrap();
    assert_eq!(rejected.error.unwrap().code, "bad_request");
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert_eq!(shared.active.load(Ordering::Acquire), 0);

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&ping()).unwrap();
    let slot = admit_connection(&shared, Instant::now()).unwrap();
    serve_connection(&server, &shared, slot, Instant::now());
    assert!(reply(&client).ok);
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_eq!(shared.active.load(Ordering::Acquire), 0);
}

#[test]
fn oversized_client_requests_fail_before_connecting() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("no-daemon.sock");
    let result = request(&socket, "secret", "explain", &json!({"id": "x".repeat(MAX_LINE_BYTES)}));
    match result.unwrap_err() {
        SbhError::Io { source, .. } => assert_eq!(source.kind(), std::io::ErrorKind::InvalidData),
        error => panic!("expected the frame bound, not a connection failure: {error}"),
    }
    assert!(!socket.exists());
}

#[test]
fn oversized_backend_results_return_an_explicit_bounded_response() {
    let shared = shared(Arc::new(LargeBackend(MAX_RESPONSE_BYTES)));
    let slot = admit_connection(&shared, Instant::now()).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&ping()).unwrap();
    serve_connection(&server, &shared, slot, Instant::now());
    let response = reply(&client);
    assert!(!response.ok);
    let error = response.error.unwrap();
    assert_eq!(error.code, "response_too_large");
    assert!(error.message.contains("may have completed"));
    assert_eq!(shared.active.load(Ordering::Acquire), 0);
}

fn parse_command(cmd: &str, args: Value) -> std::result::Result<ControlCommand, ControlError> {
    ControlCommand::parse(&ControlRequest {
        cmd: cmd.to_string(),
        args,
        token: "secret".to_string(),
    })
}

#[test]
fn malformed_mounts_never_expand_a_ballast_action_to_all_pools() {
    for mount in [
        json!(false), json!(1), json!([]), json!({}), json!(""),
        json!(" "), json!("relative"), json!("/data\u{0}other"),
    ] {
        for operation in [json!({"release": 2}), json!({"replenish": true})] {
            let mut args = operation;
            args["mount"] = mount.clone();
            let error = parse_command("ballast", args).unwrap_err();
            assert_eq!(error.code, "bad_request");
            assert!(error.message.contains("mount"));
        }
    }
}

#[test]
fn explicit_valid_ballast_scope_is_preserved_exactly() {
    for mount in ["/", "/data", "/Volumes/Build Cache"] {
        assert_eq!(
            parse_command("ballast", json!({"release": 2, "mount": mount})).unwrap(),
            ControlCommand::Ballast(BallastAction::Release {
                count: 2,
                mount: Some(PathBuf::from(mount)),
            })
        );
    }
    for args in [json!({"release": 2}), json!({"release": 2, "mount": null})] {
        assert_eq!(
            parse_command("ballast", args).unwrap(),
            ControlCommand::Ballast(BallastAction::Release { count: 2, mount: None })
        );
    }
    assert_eq!(
        parse_command("ballast", json!({"replenish": true, "mount": "/data"})).unwrap(),
        ControlCommand::Ballast(BallastAction::Replenish { mount: Some(PathBuf::from("/data")) })
    );
}

#[test]
fn ambiguous_operations_and_mistyped_flags_are_not_coerced() {
    for args in [
        json!({"release": 1, "replenish": true}),
        json!({"release": 1, "replenish": "false"}),
        json!({"release": 1, "replenish": null}),
        json!({"release": 1, "replenish": 0}),
        json!({"replenish": "true"}),
        json!({"replenish": false}),
    ] {
        assert_eq!(parse_command("ballast", args).unwrap_err().code, "bad_request");
    }
    assert!(parse_command("ballast", json!({"release": 1, "replenish": false})).is_ok());
    for force in [json!(1), json!("true"), json!(null), json!([])] {
        assert_eq!(
            parse_command("scan-now", json!({"force": force})).unwrap_err().code,
            "bad_request"
        );
    }
    for force in [false, true] {
        assert_eq!(
            parse_command("scan-now", json!({"force": force})).unwrap(),
            ControlCommand::ScanNow { paths: Vec::new(), force }
        );
    }
}

#[test]
fn argument_shape_and_typo_checks_cover_every_documented_command() {
    for (cmd, valid) in [
        ("ping", json!({})), ("status", json!({})), ("shutdown", json!({})),
        ("reload", json!({})), ("scan-now", json!({})), ("scan_now", json!({})),
        ("policy", json!({"action": "promote"})),
        ("explain", json!({"id": "41d4fafc918d"})),
        ("ballast", json!({"release": 1})),
    ] {
        assert!(parse_command(cmd, valid.clone()).is_ok(), "{cmd}");
        let mut typo = valid;
        typo["mounts"] = json!(["/data"]);
        assert_eq!(parse_command(cmd, typo).unwrap_err().code, "bad_request", "{cmd}");
        for scalar in [json!(true), json!(1), json!("/data"), json!([])] {
            assert_eq!(parse_command(cmd, scalar).unwrap_err().code, "bad_request", "{cmd}");
        }
    }
    assert_eq!(parse_command("unknown", json!({})).unwrap_err().code, "unknown_command");
}

#[test]
fn empty_or_nul_scan_paths_are_rejected_instead_of_becoming_daemon_working_directory() {
    for path in ["", "  ", "a\u{0}b"] {
        assert_eq!(
            parse_command("scan-now", json!({"paths": [path]})).unwrap_err().code,
            "bad_request"
        );
    }
}

#[test]
fn authenticated_malformed_mutations_never_reach_the_backend() {
    struct RecordingBackend(Mutex<Vec<ControlCommand>>);
    impl ControlBackend for RecordingBackend {
        fn handle(&self, command: ControlCommand, _peer: Option<Peer>) -> ControlResponse {
            self.0.lock().push(command);
            ControlResponse::success(json!({}))
        }
    }
    let backend = Arc::new(RecordingBackend(Mutex::new(Vec::new())));
    let shared = shared(backend.clone());
    for request in [
        json!({"cmd": "ballast", "args": {"release": 2, "mount": 123}, "token": "secret"}),
        json!({"cmd": "ballast", "args": {"release": 2, "mounts": ["/data"]}, "token": "secret"}),
        json!({"cmd": "ballast", "args": {"release": 2, "replenish": true}, "token": "secret"}),
        json!({"cmd": "shutdown", "args": false, "token": "secret"}),
        json!({"cmd": "shutdown", "args": {}, "force": false, "token": "secret"}),
        json!({"cmd": "scan-now", "args": {"path": "/data"}, "token": "secret"}),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&transport::encode_frame(&request, MAX_LINE_BYTES).unwrap()).unwrap();
        let slot = admit_connection(&shared, Instant::now()).unwrap();
        serve_connection(&server, &shared, slot, Instant::now());
        assert_eq!(reply(&client).error.unwrap().code, "bad_request");
        assert!(backend.0.lock().is_empty());
        assert_eq!(shared.active.load(Ordering::Acquire), 0);
    }
    let request = json!({"cmd": "ballast", "args": {"release": 1, "mount": "/data"}, "token": "secret"});
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&transport::encode_frame(&request, MAX_LINE_BYTES).unwrap()).unwrap();
    let slot = admit_connection(&shared, Instant::now()).unwrap();
    serve_connection(&server, &shared, slot, Instant::now());
    assert!(reply(&client).ok);
    assert_eq!(
        backend.0.lock().as_slice(),
        &[ControlCommand::Ballast(BallastAction::Release { count: 1, mount: Some(PathBuf::from("/data")) })]
    );
}
