//! Bounded JSON-line I/O with one non-renewing budget per direction.
//!
//! Socket timeouts apply to individual syscalls. A peer sending one byte before
//! each timeout must not extend a request indefinitely. Recompute the remaining
//! budget before every read/write, including retries after interrupted calls.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde::Serialize;

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "control I/O deadline exceeded")
}

fn remaining(start: Instant, budget: Duration, now: Instant) -> io::Result<Duration> {
    now.checked_duration_since(start)
        .and_then(|elapsed| budget.checked_sub(elapsed))
        .filter(|left| !left.is_zero())
        .ok_or_else(timed_out)
}

fn normalize_timeout(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => timed_out(),
        _ => error,
    }
}

/// Read one frame, including its delimiter. EOF-delimited requests remain
/// supported; bytes after the first newline never become another command.
pub(super) fn read_frame(
    stream: &UnixStream,
    limit: usize,
    start: Instant,
    budget: Duration,
) -> io::Result<Vec<u8>> {
    let mut reader = stream;
    read_with(
        limit,
        start,
        budget,
        |bytes, left| {
            stream.set_read_timeout(Some(left))?;
            reader.read(bytes)
        },
        Instant::now,
    )
}

fn read_with(
    limit: usize,
    start: Instant,
    budget: Duration,
    mut read: impl FnMut(&mut [u8], Duration) -> io::Result<usize>,
    mut now: impl FnMut() -> Instant,
) -> io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(limit.min(4096));
    let mut buffer = [0u8; 4096];
    loop {
        let left = remaining(start, budget, now())?;
        // Read at most one byte beyond the bound so an unterminated frame at
        // the exact limit is distinguishable from a valid EOF-delimited frame.
        let room = limit.saturating_sub(frame.len());
        let read_len = buffer.len().min(room.saturating_add(1));
        let count = match read(&mut buffer[..read_len], left) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(normalize_timeout(error)),
        };
        remaining(start, budget, now())?;
        if count == 0 {
            return Ok(frame);
        }
        let newline = buffer[..count].iter().position(|&byte| byte == b'\n');
        let end = newline.map_or(count, |index| index + 1);
        if end > room {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("control frame exceeds {limit} bytes"),
            ));
        }
        frame.extend_from_slice(&buffer[..end]);
        if newline.is_some() {
            return Ok(frame);
        }
    }
}

pub(super) fn write_frame(
    stream: &UnixStream,
    frame: &[u8],
    start: Instant,
    budget: Duration,
) -> io::Result<()> {
    let mut writer = stream;
    write_with(
        frame,
        start,
        budget,
        |bytes, left| {
            stream.set_write_timeout(Some(left))?;
            writer.write(bytes)
        },
        Instant::now,
    )
}

fn write_with(
    mut frame: &[u8],
    start: Instant,
    budget: Duration,
    mut write: impl FnMut(&[u8], Duration) -> io::Result<usize>,
    mut now: impl FnMut() -> Instant,
) -> io::Result<()> {
    while !frame.is_empty() {
        let left = remaining(start, budget, now())?;
        let count = match write(frame, left) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "control peer stopped accepting the response",
                ));
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(normalize_timeout(error)),
        };
        remaining(start, budget, now())?;
        frame = &frame[count..];
    }
    Ok(())
}

/// Serialize through a bounded sink, not to a potentially unbounded String.
/// Include the newline in the limit used by the receiving side.
pub(super) fn encode_frame(value: &impl Serialize, limit: usize) -> io::Result<Vec<u8>> {
    struct BoundedBuffer {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for BoundedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control JSON exceeds the frame limit",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let payload_limit = limit.checked_sub(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "control frame limit is zero")
    })?;
    let mut output = BoundedBuffer {
        bytes: Vec::with_capacity(limit.min(4096)),
        limit: payload_limit,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    output.bytes.push(b'\n');
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn encoding_and_reading_share_the_same_inclusive_limit() {
        let value = serde_json::json!({"ok": true, "result": "é"});
        let encoded = encode_frame(&value, 1024).unwrap();
        assert_eq!(encode_frame(&value, encoded.len()).unwrap(), encoded);
        assert_eq!(encoded.last(), Some(&b'\n'));
        assert!(encode_frame(&value, encoded.len() - 1).is_err());
        assert!(encode_frame(&value, 0).is_err());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
            value
        );
    }

    #[test]
    fn fragmented_frame_stops_at_the_first_newline() {
        let start = Instant::now();
        let mut parts = [b"{\"o".as_slice(), b"k\":true}\nignored".as_slice()].into_iter();
        let frame = read_with(
            64,
            start,
            Duration::from_secs(1),
            |buffer, _| {
                let part = parts.next().unwrap();
                buffer[..part.len()].copy_from_slice(part);
                Ok(part.len())
            },
            || start,
        )
        .unwrap();
        assert_eq!(frame, b"{\"ok\":true}\n");
    }

    #[test]
    fn eof_delimited_frame_at_the_limit_is_accepted_but_one_more_byte_is_not() {
        let start = Instant::now();
        for (payload, good) in [(b"1234".as_slice(), true), (b"12345".as_slice(), false)] {
            let mut input = payload;
            let result = read_with(
                4,
                start,
                Duration::from_secs(1),
                |buffer, _| input.read(buffer),
                || start,
            );
            assert_eq!(result.is_ok(), good);
            if let Ok(frame) = result {
                assert_eq!(frame, payload);
            }
        }
    }

    #[test]
    fn an_unterminated_frame_cannot_grow_past_the_limit() {
        let start = Instant::now();
        let total_read = Cell::new(0);
        let result = read_with(
            16,
            start,
            Duration::from_secs(1),
            |buffer, _| {
                buffer.fill(b'x');
                total_read.set(total_read.get() + buffer.len());
                Ok(buffer.len())
            },
            || start,
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(total_read.get(), 17);
    }

    #[test]
    fn steady_byte_progress_does_not_renew_the_read_budget() {
        let start = Instant::now();
        let clock = Cell::new(start);
        let calls = Cell::new(0);
        let result = read_with(
            100,
            start,
            Duration::from_millis(5),
            |buffer, left| {
                assert_eq!(left, Duration::from_millis(5 - calls.get()));
                buffer[0] = b'x';
                calls.set(calls.get() + 1);
                clock.set(clock.get() + Duration::from_millis(1));
                Ok(1)
            },
            || clock.get(),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(calls.get(), 5);
    }

    #[test]
    fn repeated_interruptions_do_not_renew_the_deadline() {
        let start = Instant::now();
        let clock = Cell::new(start);
        let result = read_with(
            100,
            start,
            Duration::from_millis(5),
            |_, _| {
                clock.set(clock.get() + Duration::from_millis(1));
                Err(io::ErrorKind::Interrupted.into())
            },
            || clock.get(),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(clock.get().duration_since(start), Duration::from_millis(5));
    }

    #[test]
    fn partial_writes_share_one_budget() {
        let start = Instant::now();
        let clock = Cell::new(start);
        let count = Cell::new(0);
        let result = write_with(
            b"0123456789",
            start,
            Duration::from_millis(5),
            |bytes, left| {
                assert_eq!(left, Duration::from_millis(5 - count.get()));
                assert_eq!(bytes[0], b'0' + u8::try_from(count.get()).unwrap());
                count.set(count.get() + 1);
                clock.set(clock.get() + Duration::from_millis(1));
                Ok(1)
            },
            || clock.get(),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(count.get(), 5);
    }

    #[test]
    fn short_writes_deliver_every_byte_without_duplication() {
        let start = Instant::now();
        let mut output = Vec::new();
        write_with(
            b"abcdef\n",
            start,
            Duration::from_secs(1),
            |bytes, _| {
                let count = bytes.len().min(2);
                output.extend_from_slice(&bytes[..count]);
                Ok(count)
            },
            || start,
        )
        .unwrap();
        assert_eq!(output, b"abcdef\n");
        let error =
            write_with(b"x", start, Duration::from_secs(1), |_, _| Ok(0), || start).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn elapsed_budget_prevents_even_the_first_syscall() {
        let start = Instant::now();
        let now = start + Duration::from_secs(5);
        let error = read_with(
            64,
            start,
            Duration::from_secs(5),
            |_, _| panic!("expired request must not read"),
            || now,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let error = write_with(
            b"x",
            start,
            Duration::from_secs(5),
            |_, _| panic!("expired response must not write"),
            || now,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn unix_socket_pair_round_trips_a_real_json_frame() {
        let (writer, reader) = UnixStream::pair().unwrap();
        let value = serde_json::json!({"cmd": "ping", "token": "secret"});
        let frame = encode_frame(&value, 1024).unwrap();
        write_frame(&writer, &frame, Instant::now(), Duration::from_secs(1)).unwrap();
        let received = read_frame(&reader, 1024, Instant::now(), Duration::from_secs(1)).unwrap();
        assert_eq!(received, frame);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&received).unwrap(),
            value
        );
    }

    #[test]
    fn a_silent_socket_times_out_instead_of_waiting_for_newline_forever() {
        let (_peer, reader) = UnixStream::pair().unwrap();
        let error =
            read_frame(&reader, 1024, Instant::now(), Duration::from_millis(20)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
