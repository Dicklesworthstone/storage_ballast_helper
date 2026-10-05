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
