//! Bounded activity-log tailing that follows the daemon's rotating filename.
//!
//! The initial tail and subsequent polls share one descriptor and byte cursor.
//! An incomplete record stays buffered until its newline arrives; rotation
//! seals that fragment before switching files, so records from two files can
//! never be joined. Memory is bounded independently of the requested tail size.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

const READ_CHUNK_BYTES: usize = 8192;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const POLL_BYTES: u64 = 1024 * 1024;
const CHECKPOINT_BYTES: usize = 64;

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
}

impl FileIdentity {
    fn of(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        Self {
            created: metadata.created().ok(),
        }
    }
}

fn open_regular(path: &Path) -> io::Result<(File, Metadata)> {
    let mut options = OpenOptions::new();
    options.read(true);
    // A replaced path must not block the reader indefinitely if it is a FIFO.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activity log is not a regular file",
        ));
    }
    Ok((file, metadata))
}

fn oversized_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "activity log record exceeds the 1 MiB reader limit",
    )
}

/// Match the event name case-insensitively, retaining the historical raw-line
/// fallback for old or damaged records that have no usable `event` field.
fn matches_filter(line: &str, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    if let Ok(value) = serde_json::from_str::<Value>(line)
        && let Some(event) = value.get("event").and_then(Value::as_str)
    {
        return event.to_lowercase().contains(filter);
    }
    line.to_lowercase().contains(filter)
}

/// Find a byte boundary, keeping only one bounded record while walking back
/// from a snapshot of EOF. A live final fragment is carried into follow mode
/// but does not count as a completed entry in the requested tail.
fn tail_start<R: Read + Seek>(
    file: &mut R,
    end: u64,
    count: usize,
    follow: bool,
    filter: Option<&str>,
) -> io::Result<u64> {
    if count == 0 && !follow {
        return Ok(end);
    }
    let mut remaining = count;
    let mut position = end;
    let mut at_eof = true;
    let mut reversed = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    while position > 0 {
        let size =
            usize::try_from(position.min(READ_CHUNK_BYTES as u64)).expect("read chunk fits usize");
        position -= size as u64;
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut chunk[..size])?;
        for index in (0..size).rev() {
            if chunk[index] != b'\n' {
                if reversed.len() == MAX_RECORD_BYTES {
                    return Err(oversized_record());
                }
                reversed.push(chunk[index]);
                continue;
            }
            let start = position + index as u64 + 1;
            if at_eof && follow {
                if remaining == 0 {
                    return Ok(start);
                }
            } else {
                reversed.reverse();
                let line = String::from_utf8_lossy(&reversed);
                if !line.trim().is_empty() && matches_filter(&line, filter) {
                    remaining -= 1;
                    if remaining == 0 {
                        return Ok(start);
                    }
                }
            }
            reversed.clear();
            at_eof = false;
        }
    }
    Ok(0)
}

/// An activity log opened once for both initial tailing and subsequent polls.
pub struct ActivityLogReader {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    filter: Option<String>,
    offset: u64,
    pending: Vec<u8>,
    checkpoint: Vec<u8>,
    restart: bool,
}

impl ActivityLogReader {
    /// Open a regular log file; normalize the event filter once per reader.
    pub fn open(path: &Path, type_filter: Option<&str>) -> io::Result<Self> {
        let (file, metadata) = open_regular(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity: FileIdentity::of(&metadata),
            filter: type_filter.map(str::to_lowercase),
            offset: 0,
            pending: Vec::new(),
            checkpoint: Vec::new(),
            restart: false,
        })
    }

    /// Emit the last `count` matching records, oldest first. In follow mode,
    /// retain an unfinished final record even when `count` is zero. Otherwise
    /// an unterminated final line counts as an entry, as it does for `tail`.
    pub fn tail(
        &mut self,
        count: usize,
        follow: bool,
        emit: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        let end = self.file.metadata()?.len();
        self.offset = tail_start(&mut self.file, end, count, follow, self.filter.as_deref())?;
        self.file.seek(SeekFrom::Start(self.offset))?;
        self.pending.clear();
        self.restart = false;
        self.save_checkpoint()?;
        self.read_until(end, emit)?;
        if !follow {
            self.emit_pending(emit)?;
        }
        Ok(())
    }

    /// Consume up to 1 MiB of newly available data. Return whether progress
    /// was made, so the caller sleeps only when caught up. A missing filename
    /// during rename/recreate rotation is transient; keep draining the old fd.
    pub fn poll(&mut self, emit: &mut impl FnMut(&str) -> io::Result<()>) -> io::Result<bool> {
        let metadata = self.file.metadata()?;
        if self.restart || metadata.len() < self.offset || !self.checkpoint_matches()? {
            // copytruncate can regrow past the cursor between polls. Comparing
            // bytes behind the cursor detects that case without retaining the
            // log. Seal the old fragment before beginning the new generation.
            self.emit_pending(emit)?;
            self.offset = 0;
            self.file.seek(SeekFrom::Start(0))?;
            self.checkpoint.clear();
            self.restart = false;
        }
        let before = self.offset;
        let end = metadata.len().min(self.offset.saturating_add(POLL_BYTES));
        self.read_until(end, emit)?;
        if self.offset < metadata.len() && self.offset > before {
            return Ok(true);
        }

        let named = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(self.offset > before);
            }
            Err(error) => return Err(error),
        };
        if FileIdentity::of(&named) != self.identity {
            // The writer can flush a final suffix after this poll's first
            // length snapshot and then rotate. It closes the old descriptor
            // before creating the new file, so renew the old EOF observation
            // after seeing the replacement and drain that suffix first.
            if self.file.metadata()?.len() > self.offset {
                return Ok(true);
            }
            // Re-stat the opened descriptor: the filename can rotate again
            // between metadata() and open(), and its earlier identity is not
            // authority for whichever file was actually opened.
            let (file, metadata) = match open_regular(&self.path) {
                Ok(opened) => opened,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(self.offset > before);
                }
                Err(error) => return Err(error),
            };
            let identity = FileIdentity::of(&metadata);
            if identity != self.identity {
                self.emit_pending(emit)?;
                self.file = file;
                self.identity = identity;
                self.offset = 0;
                self.checkpoint.clear();
                self.restart = false;
                return Ok(true);
            }
        }
        Ok(self.offset > before)
    }

    fn read_until(
        &mut self,
        end: u64,
        emit: &mut impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        while self.offset < end {
            // Output can block while the writer rotates or copytruncates.
            // Do not let a later chunk from a rewritten inode overwrite the
            // consumed-generation checkpoint and hide a required restart.
            if !self.checkpoint_matches()? {
                self.restart = true;
                break;
            }
            let limit = usize::try_from((end - self.offset).min(READ_CHUNK_BYTES as u64))
                .expect("read chunk fits usize");
            let read = match self.file.read(&mut chunk[..limit]) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if read == 0 {
                break;
            }
            self.offset += read as u64;
            self.remember_consumed(&chunk[..read]);
            for &byte in &chunk[..read] {
                if byte == b'\n' {
                    self.emit_pending(emit)?;
                } else {
                    if self.pending.len() == MAX_RECORD_BYTES {
                        return Err(oversized_record());
                    }
                    self.pending.push(byte);
                }
            }
        }
        Ok(())
    }

    fn remember_consumed(&mut self, bytes: &[u8]) {
        // Use the bytes actually read, before handing records to a consumer.
        // Re-reading them after output lets a concurrent copytruncate replace
        // the checkpoint with bytes from a generation we never consumed.
        let appended = bytes.len().min(CHECKPOINT_BYTES);
        let kept = self.checkpoint.len().min(CHECKPOINT_BYTES - appended);
        self.checkpoint.drain(..self.checkpoint.len() - kept);
        self.checkpoint
            .extend_from_slice(&bytes[bytes.len() - appended..]);
    }

    fn emit_pending(&mut self, emit: &mut impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        let line = String::from_utf8_lossy(&self.pending);
        let line = line.trim_end_matches('\r');
        if !line.trim().is_empty() && matches_filter(line, self.filter.as_deref()) {
            emit(line)?;
        }
        self.pending.clear();
        Ok(())
    }

    fn save_checkpoint(&mut self) -> io::Result<()> {
        let size = usize::try_from(self.offset.min(CHECKPOINT_BYTES as u64))
            .expect("checkpoint fits usize");
        self.checkpoint.resize(size, 0);
        self.file.seek(SeekFrom::Start(self.offset - size as u64))?;
        let result = self.file.read_exact(&mut self.checkpoint);
        self.file.seek(SeekFrom::Start(self.offset))?;
        match result {
            Ok(()) => Ok(()),
            // A concurrent truncation is handled by the next poll.
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                self.checkpoint.clear();
                self.restart = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn checkpoint_matches(&mut self) -> io::Result<bool> {
        let mut observed = [0_u8; CHECKPOINT_BYTES];
        let size = self.checkpoint.len();
        self.file.seek(SeekFrom::Start(self.offset - size as u64))?;
        let result = self.file.read_exact(&mut observed[..size]);
        self.file.seek(SeekFrom::Start(self.offset))?;
        match result {
            Ok(()) => Ok(observed[..size] == self.checkpoint),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Preserve valid JSON records verbatim. Damaged lines remain visible as
/// explicit diagnostic records instead of breaking a JSONL consumer's stream.
pub fn write_json_entry(output: &mut impl Write, line: &str) -> io::Result<()> {
    if serde_json::from_str::<Value>(line).is_ok() {
        writeln!(output, "{line}")
    } else {
        writeln!(
            output,
            "{}",
            serde_json::json!({"event": "invalid_log_line", "raw": line}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;

    fn append(path: &Path, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn tail(reader: &mut ActivityLogReader, count: usize, follow: bool) -> Vec<String> {
        let mut entries = Vec::new();
        reader
            .tail(count, follow, &mut |line| {
                entries.push(line.to_string());
                Ok(())
            })
            .unwrap();
        entries
    }

    fn poll(reader: &mut ActivityLogReader) -> Vec<String> {
        let mut entries = Vec::new();
        for _ in 0..10 {
            if !reader
                .poll(&mut |line| {
                    entries.push(line.to_string());
                    Ok(())
                })
                .unwrap()
            {
                return entries;
            }
        }
        panic!("reader did not catch up");
    }

    #[test]
    fn tail_counts_matching_entries_and_keeps_chronological_order() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(
            &path,
            "{\"event\":\"scan\",\"n\":1}\n\n{\"event\":\"error\"}\n\
             {\"event\":\"SCAN\",\"n\":2}\n{\"event\":\"scan\",\"n\":3}",
        )
        .unwrap();
        let mut reader = ActivityLogReader::open(&path, Some("ScAn")).unwrap();
        assert_eq!(
            tail(&mut reader, 2, false),
            [
                "{\"event\":\"SCAN\",\"n\":2}",
                "{\"event\":\"scan\",\"n\":3}"
            ],
        );
        assert!(tail(&mut reader, 0, false).is_empty());
    }

    #[test]
    fn tail_zero_follow_retains_split_utf8_record_until_completed() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, b"old\n{\"event\":\"scan\",\"path\":\"\xc3").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert!(tail(&mut reader, 0, true).is_empty());
        assert!(poll(&mut reader).is_empty());
        append(&path, b"\xa9\"}");
        assert!(poll(&mut reader).is_empty());
        append(&path, b"\nnext\n");
        assert_eq!(
            poll(&mut reader),
            ["{\"event\":\"scan\",\"path\":\"é\"}", "next"]
        );
        assert!(poll(&mut reader).is_empty());
    }

    #[test]
    fn append_during_initial_tail_is_followed_without_gap_or_duplicate() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "first\nsecond\n").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        let mut entries = Vec::new();
        reader
            .tail(1, true, &mut |line| {
                entries.push(line.to_string());
                append(&path, b"third\n");
                Ok(())
            })
            .unwrap();
        assert_eq!(entries, ["second"]);
        assert_eq!(poll(&mut reader), ["third"]);
        assert!(poll(&mut reader).is_empty());
    }

    #[test]
    fn rotation_drains_old_file_through_missing_name_then_follows_new_file() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        let rotated = fixture.path().join("activity.jsonl.1");
        fs::write(&path, "old\n").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert_eq!(tail(&mut reader, 1, true), ["old"]);
        fs::rename(&path, &rotated).unwrap();
        append(&rotated, b"last old\n");
        assert_eq!(poll(&mut reader), ["last old"]);
        assert!(poll(&mut reader).is_empty());
        fs::write(&path, "new\npartial").unwrap();
        assert_eq!(poll(&mut reader), ["new"]);
        append(&path, b" complete\n");
        assert_eq!(poll(&mut reader), ["partial complete"]);
        assert!(poll(&mut reader).is_empty());
    }

    #[test]
    fn rotation_never_joins_unfinished_records_from_different_files() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "old fragment").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert!(tail(&mut reader, 1, true).is_empty());
        fs::rename(&path, fixture.path().join("activity.jsonl.1")).unwrap();
        fs::write(&path, "new record\n").unwrap();
        assert_eq!(poll(&mut reader), ["old fragment", "new record"]);
    }

    #[test]
    fn rotation_drains_a_suffix_appended_after_the_poll_length_snapshot() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "initial\n").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert!(tail(&mut reader, 0, true).is_empty());
        append(&path, b"before rotation\n");
        let mut entries = Vec::new();
        reader
            .poll(&mut |line| {
                entries.push(line.to_string());
                append(&path, b"final flushed suffix\n");
                fs::rename(&path, fixture.path().join("activity.jsonl.1")).unwrap();
                fs::write(&path, "new generation\n").unwrap();
                Ok(())
            })
            .unwrap();
        entries.extend(poll(&mut reader));
        assert_eq!(
            entries,
            ["before rotation", "final flushed suffix", "new generation"],
        );
    }

    #[test]
    fn copytruncate_is_detected_when_the_replacement_regrows_past_the_cursor() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "old record\n").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert!(tail(&mut reader, 0, true).is_empty());
        fs::write(&path, "new and much longer record\nnext\n").unwrap();
        assert_eq!(poll(&mut reader), ["new and much longer record", "next"]);
        assert!(poll(&mut reader).is_empty());
        fs::write(&path, "short\n").unwrap();
        assert_eq!(poll(&mut reader), ["short"]);
    }

    #[test]
    fn copytruncate_during_output_cannot_replace_the_consumed_checkpoint() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "initial\n").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert!(tail(&mut reader, 0, true).is_empty());
        append(&path, b"before truncation\n");
        let mut entries = Vec::new();
        reader
            .poll(&mut |line| {
                entries.push(line.to_string());
                fs::write(
                    &path,
                    "new generation longer than the consumed old cursor\n",
                )
                .unwrap();
                Ok(())
            })
            .unwrap();
        entries.extend(poll(&mut reader));
        assert_eq!(
            entries,
            [
                "before truncation",
                "new generation longer than the consumed old cursor"
            ],
        );
    }

    #[test]
    fn copytruncate_between_read_chunks_restarts_before_consuming_the_new_suffix() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert!(tail(&mut reader, 0, true).is_empty());
        let original = "a".repeat(READ_CHUNK_BYTES - 1);
        let replacement = "b".repeat(READ_CHUNK_BYTES + 100);
        fs::write(&path, format!("{original}\nold suffix\n")).unwrap();
        let mut entries = Vec::new();
        reader
            .poll(&mut |line| {
                entries.push(line.to_string());
                fs::write(&path, format!("{replacement}\n")).unwrap();
                Ok(())
            })
            .unwrap();
        entries.extend(poll(&mut reader));
        assert_eq!(entries, [original, replacement]);
    }

    #[test]
    fn reverse_tail_handles_records_spanning_read_chunks() {
        let record = "a".repeat(READ_CHUNK_BYTES + 5);
        let text = format!("old\n{record}\nlast\n");
        let mut cursor = Cursor::new(text.as_bytes());
        assert_eq!(
            tail_start(&mut cursor, text.len() as u64, 2, false, None).unwrap(),
            4
        );
        assert_eq!(
            tail_start(&mut cursor, text.len() as u64, usize::MAX, false, None).unwrap(),
            0,
        );
    }

    #[test]
    fn recent_tail_does_not_read_an_oversized_old_record() {
        let mut text = "a".repeat(MAX_RECORD_BYTES + 1);
        text.push_str("\nrecent\n");
        let mut cursor = Cursor::new(text.as_bytes());
        assert_eq!(
            tail_start(&mut cursor, text.len() as u64, 1, false, None).unwrap(),
            (MAX_RECORD_BYTES + 2) as u64,
        );
        assert_eq!(
            tail_start(&mut cursor, text.len() as u64, 2, false, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
        );
    }

    #[test]
    fn oversized_unterminated_follow_record_fails_without_unbounded_growth() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert!(tail(&mut reader, 0, true).is_empty());
        append(&path, &vec![b'a'; MAX_RECORD_BYTES]);
        assert!(reader.poll(&mut |_| Ok(())).unwrap());
        append(&path, b"b");
        assert_eq!(
            reader.poll(&mut |_| Ok(())).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
        );
        assert_eq!(reader.pending.len(), MAX_RECORD_BYTES);
    }

    #[test]
    fn json_mode_preserves_fields_and_frames_damaged_lines() {
        let valid = r#"{"event":"artifact_delete", "bytes":42,"nested":{"ok":true}}"#;
        let mut output = Vec::new();
        write_json_entry(&mut output, valid).unwrap();
        write_json_entry(&mut output, "torn { record").unwrap();
        let text = String::from_utf8(output).unwrap();
        let entries: Vec<_> = text.lines().collect();
        assert_eq!(entries[0], valid);
        let damaged: Value = serde_json::from_str(entries[1]).unwrap();
        assert_eq!(damaged["event"], "invalid_log_line");
        assert_eq!(damaged["raw"], "torn { record");
    }

    #[test]
    fn follower_refuses_non_regular_replacement() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("activity.jsonl");
        fs::write(&path, "old\n").unwrap();
        let mut reader = ActivityLogReader::open(&path, None).unwrap();
        assert_eq!(tail(&mut reader, 1, true), ["old"]);
        fs::rename(&path, fixture.path().join("activity.jsonl.1")).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            reader.poll(&mut |_| Ok(())).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
        );
    }
}
