//! Durable intent/outcome records for compression, and read-only crash inspection.
//!
//! An fsynced intent precedes every file's first rewrite. An interrupted intent
//! is NOT proof that a rewrite happened, nor that any bytes were reclaimed.
//! Recovery only verifies the original identity and content hash; it never
//! replays a mutation or substitutes a current hash for physical-space evidence.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{CompressionFileReport, CompressionPolicy};

const SCHEMA: &str = "sbh.compression.journal.v1";
const MAX_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 128 * 1024;
const MAX_PATH_BYTES: usize = 16 * 1024;
/// How long recovery waits for the writer's lock before calling the pass live.
const LIVE_LOCK_PATIENCE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    links: u64,
}

impl Identity {
    fn read(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid(
                "a journal or compression input must be a regular file",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            links: metadata.nlink(),
        })
    }

    fn same_contents_and_identity(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.size == other.size
            && self.mtime == other.mtime
            && self.mtime_nsec == other.mtime_nsec
            && self.links == other.links
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    operation_id: String,
    // Native pathname bytes are authoritative; the display path in a finished
    // report may contain replacement characters and must never be replayed.
    path_hex: String,
    identity: Identity,
    sha256_before: String,
    physical_data_bytes_before: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    run_id: String,
    sequence: u64,
    at: String,
    entry: Entry,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Entry {
    RunStarted {
        pid: u32,
        input_files: usize,
        policy: CompressionPolicy,
    },
    Prepared {
        intent: Intent,
    },
    FileFinished {
        report: Box<CompressionFileReport>,
    },
    RunFinished {
        exit_code: i32,
        unvisited_files: usize,
    },
}

/// One recorded operation and, for an unfinished intent, its current read-only
/// verification result. Historical results are not reclassified as current ones.
#[derive(Debug, Serialize)]
pub struct RecoveryOperation {
    /// Stable operation identifier from the fsynced intent.
    pub operation_id: String,
    /// Display only; execution/verification use the stored native path bytes.
    pub path: String,
    /// Durable historical outcome, when one was recorded before interruption.
    pub recorded_result: Option<CompressionFileReport>,
    /// recorded_only, contents_verified, content_mismatch, unavailable, or budget_exhausted.
    pub verification: String,
    /// True only for an unfinished intent whose current identity/hash were checked.
    pub content_verified_now: bool,
    /// Explanation; content verification never implies physical reclaim.
    pub detail: String,
}

/// Read-only inspection of an interrupted or completed compression pass.
#[derive(Debug, Serialize)]
pub struct RecoveryReport {
    /// Stable output schema.
    pub schema: &'static str,
    /// This command never rewrites inputs or journal records.
    pub read_only: bool,
    /// Display path of the inspected journal.
    pub journal_path: String,
    /// Run identifier shared by every record.
    pub run_id: String,
    /// Limits recorded when the original pass started.
    pub policy: CompressionPolicy,
    /// Whether a durable, valid end-of-run record exists.
    pub run_finished: bool,
    /// Original exit code, not fabricated for an interrupted pass.
    pub recorded_exit_code: Option<i32>,
    /// Input paths the original pass did not visit, when a footer recorded them.
    pub recorded_unvisited_files: Option<usize>,
    /// A final non-newline-terminated record was ignored as torn/uncertain.
    pub truncated_tail: bool,
    /// Operations in original intent order.
    pub operations: Vec<RecoveryOperation>,
    /// 0 for a recorded successful pass; 2/4 retain recorded failure status.
    /// Interrupted or torn journals always return 4, even if contents verify.
    pub exit_code: i32,
}

struct Parsed {
    run_id: String,
    policy: CompressionPolicy,
    operations: Vec<(Intent, Option<CompressionFileReport>)>,
    footer: Option<(i32, usize)>,
    truncated_tail: bool,
}

/// Inspect a journal and re-hash unfinished inputs within a logical-byte and
/// cooperative time budget.
///
/// No config file, Btrfs ioctl, or writable input
/// descriptor is used. Active, non-private, malformed, and oversized journals
/// are refused. A changed or missing source remains uncertain rather than
/// becoming permission to compress it again.
pub fn recover(path: &Path, max_bytes: u64, timeout_secs: u64) -> io::Result<RecoveryReport> {
    if max_bytes == 0 || !(1..=3600).contains(&timeout_secs) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery requires a nonzero byte budget and 1..3600 seconds",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let journal = open_read_only(path)?;
    let metadata = journal.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "journal must be a private, single-link regular file owned by the current effective user",
        ));
    }
    // A second descriptor in the same process also conflicts with the writer's
    // exclusive lock. A live pass is not an interrupted pass.
    lock_shared_patiently(&journal, deadline)?;
    let before = Identity::read(&journal)?;
    if before.size > MAX_JOURNAL_BYTES {
        return Err(invalid(
            "compression journal exceeds the 32 MiB read budget",
        ));
    }
    let mut bytes = Vec::new();
    (&journal)
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES || Identity::read(&journal)? != before {
        return Err(invalid(
            "journal changed or exceeded its read budget during inspection",
        ));
    }
    let parsed = parse_records(&bytes)?;
    let mut remaining = max_bytes;
    let mut operations = Vec::with_capacity(parsed.operations.len());
    for (intent, recorded_result) in parsed.operations {
        let source = decode_path(&intent.path_hex)?;
        let mut operation = RecoveryOperation {
            operation_id: intent.operation_id.clone(),
            path: source.to_string_lossy().into_owned(),
            recorded_result,
            verification: "recorded_only".into(),
            content_verified_now: false,
            detail: "durable historical outcome; the current file was not rechecked".into(),
        };
        if operation.recorded_result.is_none() {
            if intent.identity.size > remaining || Instant::now() >= deadline {
                operation.verification = "budget_exhausted".into();
                operation.detail =
                    "unfinished intent was not verified within this recovery budget".into();
            } else {
                // Charge the whole request before reading, including failed or
                // short reads, so many failed sources cannot evade the budget.
                remaining -= intent.identity.size;
                match verify_unfinished(&source, &intent, deadline) {
                    Ok(true) => {
                        operation.verification = "contents_verified".into();
                        operation.content_verified_now = true;
                        operation.detail = "original identity, size, mtime and SHA-256 verified; whether compression ran and how much space it reclaimed remain unknown".into();
                    }
                    Ok(false) => {
                        operation.verification = "content_mismatch".into();
                        operation.detail = "current content does not match the pre-mutation SHA-256; no automatic repair or replay was attempted".into();
                    }
                    Err(error) => {
                        operation.verification = if error.kind() == io::ErrorKind::TimedOut {
                            "budget_exhausted"
                        } else {
                            "unavailable"
                        }
                        .into();
                        operation.detail = error.to_string();
                    }
                }
            }
        }
        operations.push(operation);
    }
    let exit_code = if parsed.truncated_tail {
        4
    } else {
        parsed.footer.map_or(4, |(code, _)| code)
    };
    Ok(RecoveryReport {
        schema: "sbh.compression.recovery.v1",
        read_only: true,
        journal_path: path.to_string_lossy().into_owned(),
        run_id: parsed.run_id,
        policy: parsed.policy,
        run_finished: parsed.footer.is_some(),
        recorded_exit_code: parsed.footer.map(|(code, _)| code),
        recorded_unvisited_files: parsed.footer.map(|(_, count)| count),
        truncated_tail: parsed.truncated_tail,
        operations,
        exit_code,
    })
}

#[allow(clippy::too_many_lines)] // one linear record grammar
fn parse_records(bytes: &[u8]) -> io::Result<Parsed> {
    let complete_end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |last| last + 1);
    let truncated_tail = complete_end != bytes.len();
    let mut records = bytes[..complete_end]
        .split_inclusive(|byte| *byte == b'\n')
        .map(|line| &line[..line.len() - 1]);
    let first = records
        .next()
        .ok_or_else(|| invalid("journal has no complete run header"))?;
    let header = decode_record(first)?;
    if header.sequence != 0 || header.run_id.is_empty() || header.run_id.len() > 128 {
        return Err(invalid("invalid compression journal run header"));
    }
    let Entry::RunStarted {
        input_files,
        policy,
        ..
    } = header.entry
    else {
        return Err(invalid(
            "compression journal does not begin with run_started",
        ));
    };
    policy.validate()?;
    if !(1..=4096).contains(&input_files) {
        return Err(invalid("journal input count exceeds the pass limit"));
    }
    let mut operations: Vec<(Intent, Option<CompressionFileReport>)> = Vec::new();
    let mut indexes = BTreeMap::new();
    let mut pending: Option<usize> = None;
    let mut footer = None;
    for (index, line) in records.enumerate() {
        if index > 8192 || footer.is_some() {
            return Err(invalid(
                "journal has excess records or records after run_finished",
            ));
        }
        let record = decode_record(line)?;
        if record.run_id != header.run_id || record.sequence != index as u64 + 1 {
            return Err(invalid("journal run identity or sequence is inconsistent"));
        }
        match record.entry {
            Entry::RunStarted { .. } => return Err(invalid("duplicate journal header")),
            Entry::Prepared { intent } => {
                if pending.is_some()
                    || operations.len() >= input_files
                    || intent.operation_id != format!("{}:{}", header.run_id, record.sequence)
                    || indexes.contains_key(&intent.operation_id)
                    || intent.identity.links != 1
                    || !valid_hash(&intent.sha256_before)
                {
                    return Err(invalid(
                        "duplicate, overlapping or invalid compression intent",
                    ));
                }
                decode_path(&intent.path_hex)?;
                let position = operations.len();
                indexes.insert(intent.operation_id.clone(), position);
                pending = Some(position);
                operations.push((intent, None));
            }
            Entry::FileFinished { report } => {
                let position = pending.ok_or_else(|| invalid("outcome has no pending intent"))?;
                let intent = &operations[position].0;
                if report.operation_id.as_deref() != Some(intent.operation_id.as_str())
                    || report.logical_bytes != intent.identity.size
                    || report.sha256_before.as_deref() != Some(intent.sha256_before.as_str())
                    || report.physical_data_bytes_before != Some(intent.physical_data_bytes_before)
                    || !matches!(report.outcome.as_str(), "compressed" | "partial" | "failed")
                    || (report.outcome == "compressed"
                        && (!report.content_verified || !report.mutation_attempted))
                    || (report.content_verified
                        && (!report.mutation_attempted
                            || report.sha256_after.as_deref()
                                != Some(intent.sha256_before.as_str())))
                {
                    return Err(invalid(
                        "journal outcome does not match its prepared intent",
                    ));
                }
                operations[position].1 = Some(*report);
                pending = None;
            }
            Entry::RunFinished {
                exit_code,
                unvisited_files,
            } => {
                if pending.is_some()
                    || !matches!(exit_code, 0 | 2 | 4)
                    || unvisited_files > input_files
                    || (exit_code == 0 && unvisited_files != 0)
                    || (exit_code == 0
                        && operations.iter().any(|(_, report)| {
                            report
                                .as_ref()
                                .is_none_or(|report| report.outcome != "compressed")
                        }))
                {
                    return Err(invalid(
                        "run footer falsely completes unfinished or failed work",
                    ));
                }
                footer = Some((exit_code, unvisited_files));
            }
        }
    }
    Ok(Parsed {
        run_id: header.run_id,
        policy,
        operations,
        footer,
        truncated_tail,
    })
}

fn decode_record(line: &[u8]) -> io::Result<Record> {
    if line.is_empty() || line.len() > MAX_RECORD_BYTES {
        return Err(invalid("empty or oversized journal record"));
    }
    let record: Record = serde_json::from_slice(line).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed complete journal record: {error}"),
        )
    })?;
    if record.schema != SCHEMA {
        return Err(invalid("unsupported compression journal schema"));
    }
    Ok(record)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_path(hex: &str) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > MAX_PATH_BYTES * 2 {
        return Err(invalid(
            "invalid native pathname length in compression intent",
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        let digit = |byte: u8| {
            char::from(byte)
                .to_digit(16)
                .ok_or_else(|| invalid("invalid hex in compression pathname"))
        };
        let byte = u8::try_from(digit(pair[0])? * 16 + digit(pair[1])?)
            .map_err(|_| invalid("native pathname byte overflow"))?;
        if byte == 0 {
            return Err(invalid("NUL in compression pathname"));
        }
        bytes.push(byte);
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid(
            "compression intent pathname must be absolute without parent traversal",
        ));
    }
    Ok(path)
}

/// Take the shared lock, waiting briefly while the exclusive one is held.
///
/// A live pass holds the writer's exclusive lock for its whole run. A child
/// that any thread of this process is spawning also holds the writer's
/// descriptor, and so its lock, until the child execs: usually microseconds,
/// but a whole CPU-quota period when the cgroup is throttled. Recovery right
/// after a pass ended must not call the pass live because of that.
fn lock_shared_patiently(journal: &File, deadline: Instant) -> io::Result<()> {
    let give_up = deadline.min(Instant::now() + LIVE_LOCK_PATIENCE);
    let mut pause = Duration::from_millis(5);
    loop {
        match journal.try_lock_shared() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < give_up => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(100));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "the journal is locked by a compression pass that is still running",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

fn open_read_only(path: &Path) -> io::Result<File> {
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    #[cfg(target_os = "linux")]
    let flags = flags | libc::O_NOATIME;
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

fn verify_unfinished(path: &Path, intent: &Intent, deadline: Instant) -> io::Result<bool> {
    budget(deadline)?;
    let file = open_read_only(path)?;
    let before = Identity::read(&file)?;
    if !intent.identity.same_contents_and_identity(&before) || path.canonicalize()? != path {
        return Err(invalid(
            "unfinished input was replaced, renamed, relinked, or modified",
        ));
    }
    let hash = digest(&file, before.size, deadline)?;
    let after = Identity::read(&file)?;
    let named = std::fs::symlink_metadata(path)?;
    if before != after
        || !named.is_file()
        || named.dev() != before.device
        || named.ino() != before.inode
        || path.canonicalize()? != path
    {
        return Err(invalid(
            "unfinished input changed during read-only verification",
        ));
    }
    Ok(hash == intent.sha256_before)
}

pub(super) fn digest(file: &File, size: u64, deadline: Instant) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut offset = 0_u64;
    while offset < size {
        budget(deadline)?;
        let length = usize::try_from((size - offset).min(buffer.len() as u64))
            .map_err(|_| invalid("hash read length overflow"))?;
        let read = match file.read_at(&mut buffer[..length], offset) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            return Err(invalid("file shortened during hashing"));
        }
        hash.update(&buffer[..read]);
        offset += read as u64;
    }
    Ok(crate::core::hex_lower(hash.finalize()))
}

fn budget(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "compression verification budget exhausted",
        ))
    } else {
        Ok(())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(super) use writer::AuditSession;

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod writer {
    use std::fmt::Write as _;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use rustix::fs::{Mode, OFlags, mkdirat, openat};

    #[allow(clippy::wildcard_imports)] // the parent module's journal grammar
    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub(in crate::scanner::compression) struct AuditSession {
        root: PathBuf,
        input_files: usize,
        policy: CompressionPolicy,
        writer: Option<Writer>,
        failed: bool,
    }

    impl AuditSession {
        // No I/O: previews and apply passes with no eligible input create no
        // journal directories or files. Creation occurs at the mutation gate.
        pub(in crate::scanner::compression) fn new(
            root: PathBuf,
            input_files: usize,
            policy: &CompressionPolicy,
        ) -> Self {
            Self {
                root,
                input_files,
                policy: policy.clone(),
                writer: None,
                failed: false,
            }
        }

        pub(in crate::scanner::compression) fn path(&self) -> Option<&Path> {
            self.writer.as_ref().map(|writer| writer.path.as_path())
        }

        pub(in crate::scanner::compression) fn failed(&self) -> bool {
            self.failed
        }

        pub(in crate::scanner::compression) fn prepare(
            &mut self,
            report: &mut CompressionFileReport,
            file: &File,
        ) -> io::Result<()> {
            let result = self.prepare_inner(report, file);
            self.failed |= result.is_err();
            result
        }

        fn prepare_inner(
            &mut self,
            report: &mut CompressionFileReport,
            file: &File,
        ) -> io::Result<()> {
            if self.failed {
                return Err(invalid(
                    "compression journal is unavailable; mutation refused",
                ));
            }
            if report.operation_id.is_some() || report.mutation_attempted {
                return Err(invalid(
                    "compression intent must be prepared once, before mutation",
                ));
            }
            let identity = Identity::read(file)?;
            let sha256_before = report
                .sha256_before
                .as_ref()
                .filter(|hash| valid_hash(hash))
                .ok_or_else(|| invalid("intent requires the completed preflight SHA-256"))?
                .clone();
            let physical_data_bytes_before = report
                .physical_data_bytes_before
                .ok_or_else(|| invalid("intent requires measured physical allocation"))?;
            if identity.links != 1 || identity.size != report.logical_bytes {
                return Err(invalid("input identity changed before journal preparation"));
            }
            let path_bytes = report.path.as_os_str().as_encoded_bytes();
            if path_bytes.len() > MAX_PATH_BYTES {
                return Err(invalid("input path exceeds journal limit"));
            }
            let mut path_hex = String::with_capacity(path_bytes.len() * 2);
            for byte in path_bytes {
                let _ = write!(path_hex, "{byte:02x}");
            }
            decode_path(&path_hex)?;
            if self.writer.is_none() {
                self.writer = Some(Writer::create(&self.root, self.input_files, &self.policy)?);
            }
            let writer = self
                .writer
                .as_mut()
                .ok_or_else(|| invalid("journal initialization failed"))?;
            let operation_id = format!("{}:{}", writer.run_id, writer.sequence);
            report.operation_id = Some(operation_id.clone());
            writer.append(Entry::Prepared {
                intent: Intent {
                    operation_id,
                    path_hex,
                    identity,
                    sha256_before,
                    physical_data_bytes_before,
                },
            })
        }

        pub(in crate::scanner::compression) fn complete(
            &mut self,
            report: &CompressionFileReport,
        ) -> io::Result<()> {
            if report.operation_id.is_none() {
                return Ok(());
            }
            self.append(Entry::FileFinished {
                report: Box::new(report.clone()),
            })
        }

        pub(in crate::scanner::compression) fn finish(
            &mut self,
            exit_code: i32,
            unvisited_files: usize,
        ) -> io::Result<()> {
            if self.writer.is_none() && !self.failed {
                return Ok(());
            }
            self.append(Entry::RunFinished {
                exit_code,
                unvisited_files,
            })
        }

        fn append(&mut self, entry: Entry) -> io::Result<()> {
            if self.failed {
                return Err(invalid(
                    "compression journal write previously failed; no further records appended",
                ));
            }
            let result = self
                .writer
                .as_mut()
                .ok_or_else(|| invalid("compression journal is missing"))?
                .append(entry);
            self.failed |= result.is_err();
            result
        }
    }

    struct Writer {
        file: File,
        path: PathBuf,
        // Keep the directory pinned until the pass ends. Both the journal file
        // and the directory entry are synchronized before any intent is used.
        directory: File,
        run_id: String,
        sequence: u64,
        bytes: u64,
        poisoned: bool,
    }

    impl Writer {
        fn create(root: &Path, input_files: usize, policy: &CompressionPolicy) -> io::Result<Self> {
            if !root.is_absolute()
                || root
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(invalid(
                    "compression journal directory must be an absolute path without traversal",
                ));
            }
            let parent_path = root
                .parent()
                .ok_or_else(|| invalid("journal directory has no parent"))?;
            let leaf = root
                .file_name()
                .ok_or_else(|| invalid("journal directory has no name"))?;
            // Require an already-initialized state directory. Recursively
            // creating its ancestors here would require syncing every ancestor
            // before an intent could truthfully be called durable.
            let parent = OpenOptions::new().read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(parent_path).map_err(|error| io::Error::new(error.kind(), format!(
                    "initialize the SBH state directory {} before applying compression: {error}", parent_path.display()
                )))?;
            match mkdirat(&parent, leaf, Mode::RWXU) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => return Err(error.into()),
            }
            let directory = File::from(openat(
                &parent,
                leaf,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let metadata = directory.metadata()?;
            if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
                return Err(invalid(
                    "compression journal directory must be private and owned by the current effective user; existing permissions were not changed",
                ));
            }
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| invalid("clock precedes the journal epoch"))?
                .as_nanos();
            let run_id = format!(
                "{nanos:x}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let name = format!("{run_id}.jsonl");
            // Create relative to the verified directory, exclusively. Never
            // follow a final symlink, overwrite, append to an older run, or
            // rotate/delete an operator's audit history.
            let file = File::from(openat(
                &directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            file.try_lock()?;
            let mut writer = Self {
                file,
                path: root.join(name),
                directory,
                run_id,
                sequence: 0,
                bytes: 0,
                poisoned: false,
            };
            writer.append(Entry::RunStarted {
                pid: std::process::id(),
                input_files,
                policy: policy.clone(),
            })?;
            writer.directory.sync_all()?;
            parent.sync_all()?;
            Ok(writer)
        }

        fn append(&mut self, entry: Entry) -> io::Result<()> {
            if self.poisoned {
                return Err(invalid("journal is poisoned by an earlier failed write"));
            }
            let record = Record {
                schema: SCHEMA.into(),
                run_id: self.run_id.clone(),
                sequence: self.sequence,
                at: chrono::Utc::now().to_rfc3339(),
                entry,
            };
            let result = (|| {
                let mut bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
                if bytes.len() > MAX_RECORD_BYTES {
                    return Err(invalid("compression journal record exceeds its size limit"));
                }
                bytes.push(b'\n');
                let total = self
                    .bytes
                    .checked_add(bytes.len() as u64)
                    .filter(|total| *total <= MAX_JOURNAL_BYTES)
                    .ok_or_else(|| {
                        invalid("compression journal reached its 32 MiB limit; mutation stopped")
                    })?;
                self.file.write_all(&bytes)?;
                self.file.sync_all()?;
                self.bytes = total;
                self.sequence += 1;
                Ok(())
            })();
            self.poisoned |= result.is_err();
            result
        }
    }
}

#[cfg(test)]
mod tests;
