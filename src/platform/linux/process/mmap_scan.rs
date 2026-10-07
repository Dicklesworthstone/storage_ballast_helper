//! Bounded memory-map evidence for the visible Linux process namespace.
//!
//! The PAL's Vec-returning API cannot describe partial coverage. Incomplete
//! snapshots therefore return an error, never a successful truncated vector.
//! Reads are streamed, byte-preserving and cooperatively deadline-bounded.
//! This is not an atomic process/mount-namespace snapshot.

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::{OPEN_FILES_MAX_PIDS, OPEN_FILES_SCAN_BUDGET, PROC_ROOT, pid_from_proc_entry_name};
use crate::core::errors::{Result, SbhError};
use crate::core::paths::resolve_absolute_path;
use crate::platform::types::MappedRegion;

const SNAPSHOT_TTL: Duration = Duration::from_secs(30);
// A denied PID can persist indefinitely. Do not repeat an expensive failed
// whole-system sweep for every root or monitor tick; cached failures carry no
// absence authority and expire on the same bounded retry cadence.
const FAILURE_TTL: Duration = Duration::from_secs(30);
const BUFFER_BYTES: usize = 8192;
const STAT_BYTES: usize = 8192;
const PF_KTHREAD: u64 = 0x0020_0000;

type Entries = Box<dyn Iterator<Item = io::Result<OsString>>>;

trait Access {
    fn entries(&self, path: &Path) -> io::Result<Entries>;
    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>>;
    fn gone(&self, path: &Path) -> bool;
    fn now(&self) -> Instant;
}

struct Native;

impl Access for Native {
    fn entries(&self, path: &Path) -> io::Result<Entries> {
        Ok(Box::new(fs::read_dir(path)?.map(|entry| entry.map(|entry| entry.file_name()))))
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(open_regular(path)?))
    }

    fn gone(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_err_and(|error| disappeared(&error))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "non-regular proc metadata"));
    }
    Ok(file)
}

#[derive(Clone, Copy)]
struct Limits {
    time: Duration,
    pids: usize,
    entries: usize,
    bytes: usize,
    bytes_per_pid: usize,
    lines: usize,
    lines_per_pid: usize,
    line_bytes: usize,
    regions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: OPEN_FILES_SCAN_BUDGET,
            pids: OPEN_FILES_MAX_PIDS,
            entries: OPEN_FILES_MAX_PIDS + 4096,
            bytes: 64 * 1024 * 1024,
            bytes_per_pid: 8 * 1024 * 1024,
            lines: 1_048_576,
            lines_per_pid: 65_536,
            line_bytes: 65_536,
            regions: 262_144,
        }
    }
}

#[derive(Default)]
struct Snapshot {
    regions: Vec<MappedRegion>,
    incomplete: Option<String>,
}

impl Snapshot {
    fn fail(&mut self, reason: impl Into<String>) {
        if self.incomplete.is_none() {
            self.incomplete = Some(reason.into());
        }
    }

    fn under(&self, root: &Path) -> Result<Vec<MappedRegion>> {
        if let Some(reason) = &self.incomplete {
            return Err(incomplete_error(reason));
        }
        let root = resolve_absolute_path(root);
        Ok(self.regions.iter().filter(|region| region.path.starts_with(&root)).cloned().collect())
    }
}

fn incomplete_error(reason: &str) -> SbhError {
    SbhError::Runtime {
        details: format!("memory-map inspection incomplete: {reason}"),
    }
}

struct Cached {
    at: Instant,
    snapshot: Arc<Snapshot>,
}

#[derive(Default)]
struct Cache {
    value: Mutex<Option<Cached>>,
    refresh: Mutex<()>,
}

impl Cache {
    fn fresh(&self, now: Instant) -> Option<Arc<Snapshot>> {
        let cached = self.value.lock();
        let entry = cached.as_ref()?;
        let ttl = if entry.snapshot.incomplete.is_some() { FAILURE_TTL } else { SNAPSHOT_TTL };
        (now.checked_duration_since(entry.at)? < ttl).then(|| Arc::clone(&entry.snapshot))
    }

    fn obtain(
        &self,
        now: impl Fn() -> Instant,
        collect: impl FnOnce() -> Snapshot,
    ) -> Result<Arc<Snapshot>> {
        if let Some(snapshot) = self.fresh(now()) {
            return Ok(snapshot);
        }
        // Do not turn parallel root queries into parallel procfs sweeps, or
        // make a monitor wait behind a potentially stalled kernel read.
        let Some(_refresh) = self.refresh.try_lock() else {
            return Err(incomplete_error("another snapshot refresh is in progress"));
        };
        if let Some(snapshot) = self.fresh(now()) {
            return Ok(snapshot);
        }
        let started = now();
        let mut snapshot = collect();
        let finished = now();
        if finished.checked_duration_since(started).is_none_or(|age| age >= SNAPSHOT_TTL) {
            snapshot.fail("snapshot expired during collection");
        }
        // Successful evidence ages from START, never from publication. Failed
        // observations get a retry backoff, not fresh absence authority.
        let at = if snapshot.incomplete.is_some() { finished } else { started };
        let snapshot = Arc::new(snapshot);
        *self.value.lock() = Some(Cached { at, snapshot: Arc::clone(&snapshot) });
        Ok(snapshot)
    }
}

pub(super) fn read_under(root: &Path) -> Result<Vec<MappedRegion>> {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(Cache::default)
        .obtain(Instant::now, || collect(&Native, Path::new(PROC_ROOT), Limits::default()))?
        .under(root)
}

struct Sweep<'a, A> {
    access: &'a A,
    limits: Limits,
    started: Instant,
    bytes: usize,
    lines: usize,
    resolved: HashMap<PathBuf, PathBuf>,
    snapshot: Snapshot,
}

impl<'a, A: Access> Sweep<'a, A> {
    fn new(access: &'a A, limits: Limits) -> Self {
        Self {
            access,
            limits,
            started: access.now(),
            bytes: 0,
            lines: 0,
            resolved: HashMap::new(),
            snapshot: Snapshot::default(),
        }
    }

    fn expired(&mut self) -> bool {
        if self.access.now().checked_duration_since(self.started)
            .is_none_or(|elapsed| elapsed >= self.limits.time)
        {
            self.snapshot.fail("deadline exhausted");
            true
        } else {
            false
        }
    }

    fn pids(&mut self, root: &Path) -> Vec<i32> {
        let entries = match self.access.entries(root) {
            Ok(entries) => entries,
            Err(error) => {
                self.snapshot.fail(format!("proc discovery failed: {error}"));
                return Vec::new();
            }
        };
        let mut pids = Vec::new();
        for (count, entry) in entries.enumerate() {
            if self.expired() { break; }
            if count >= self.limits.entries {
                self.snapshot.fail("proc directory entry limit exceeded");
                break;
            }
            let name = match entry {
                Ok(name) => name,
                Err(error) => {
                    self.snapshot.fail(format!("proc enumeration failed: {error}"));
                    continue;
                }
            };
            let Some(pid) = name.to_str().and_then(pid_from_proc_entry_name).filter(|pid| *pid > 0) else {
                continue;
            };
            if pids.len() >= self.limits.pids {
                self.snapshot.fail("PID limit exceeded");
                break;
            }
            pids.push(pid);
        }
        let current = i32::try_from(std::process::id()).ok();
        pids.sort_unstable_by_key(|pid| (Some(*pid) != current, *pid));
        pids.dedup();
        pids
    }

    fn maps(&mut self, proc_root: &Path, pid: i32) {
        let process = proc_root.join(pid.to_string());
        let file = match self.access.open(&process.join("maps")) {
            Ok(file) => file,
            Err(error) => {
                if !disappeared(&error) || !self.access.gone(&process) {
                    self.snapshot.fail(format!("PID {pid} maps unavailable: {error}"));
                }
                return;
            }
        };
        let cap = self.limits.bytes_per_pid.min(self.limits.bytes.saturating_sub(self.bytes));
        let read_count = Cell::new(0);
        // One extra byte distinguishes exact EOF from truncation. No full
        // maps-file String and no unbounded read_until allocation are used.
        let counted = Counted { inner: file.take(cap as u64 + 1), count: &read_count };
        let mut reader = BufReader::with_capacity(BUFFER_BYTES, counted);
        let mut line = Vec::new();
        let mut lines = 0usize;
        loop {
            if self.expired() { break; }
            line.clear();
            match read_line(&mut reader, &mut line, self.limits.line_bytes, || !self.expired()) {
                Ok(false) => {
                    if lines == 0 && !self.empty_maps_expected(&process, pid) {
                        self.snapshot.fail(format!("PID {pid} empty maps without terminal/kernel evidence"));
                    }
                    break;
                }
                Ok(true) => {}
                Err(error) => {
                    self.snapshot.fail(format!("PID {pid} maps read failed: {error}"));
                    break;
                }
            }
            if read_count.get() > cap {
                self.snapshot.fail(format!("PID {pid} maps byte budget exceeded"));
                break;
            }
            if lines >= self.limits.lines_per_pid || self.lines >= self.limits.lines {
                self.snapshot.fail(format!("PID {pid} maps line budget exceeded"));
                break;
            }
            lines += 1;
            self.lines += 1;
            match parse_row(pid, &line) {
                Ok(Some(region)) => {
                    for path in path_spellings(&region.path) {
                        if self.snapshot.regions.len() >= self.limits.regions {
                            self.snapshot.fail("mapped-region result limit exceeded");
                            break;
                        }
                        let path = self.resolved.entry(path)
                            .or_insert_with_key(|path| resolve_absolute_path(path)).clone();
                        self.snapshot.regions.push(MappedRegion { path, ..region.clone() });
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.snapshot.fail(format!("PID {pid} malformed maps row: {error}"));
                }
            }
        }
        self.bytes = self.bytes.saturating_add(read_count.get());
        self.expired();
    }

    fn empty_maps_expected(&mut self, process: &Path, pid: i32) -> bool {
        if self.expired() { return false; }
        if self.access.gone(process) { return true; }
        let Ok(file) = self.access.open(&process.join("stat")) else { return false; };
        let cap = STAT_BYTES.min(self.limits.bytes.saturating_sub(self.bytes));
        let mut raw = Vec::new();
        let mut reader = file.take(cap as u64 + 1);
        let mut buffer = [0u8; 1024];
        loop {
            if self.expired() { return false; }
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    self.bytes = self.bytes.saturating_add(count);
                    raw.extend_from_slice(&buffer[..count]);
                    if raw.len() > cap { return false; }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return false,
            }
        }
        if self.expired() { return false; }
        let Ok(raw) = std::str::from_utf8(&raw) else { return false; };
        let Some((head, _)) = raw.split_once('(') else { return false; };
        if head.trim().parse::<i32>().ok() != Some(pid) { return false; }
        let Ok(fields) = super::proc_stat_fields_after_comm(raw) else { return false; };
        let Some(flags) = fields.get(6).and_then(|value| value.parse::<u64>().ok()) else { return false; };
        let Some(threads) = fields.get(17).and_then(|value| value.parse::<u64>().ok()) else { return false; };
        threads > 0 && (flags & PF_KTHREAD != 0
            || (threads == 1 && matches!(fields.first().copied(), Some("Z" | "X" | "x"))))
    }
}

fn collect(access: &impl Access, proc_root: &Path, limits: Limits) -> Snapshot {
    let mut sweep = Sweep::new(access, limits);
    for pid in sweep.pids(proc_root) {
        if sweep.expired() { break; }
        sweep.maps(proc_root, pid);
    }
    sweep.snapshot.regions.sort_by(|a, b| a.pid.cmp(&b.pid)
        .then_with(|| a.start_address.cmp(&b.start_address))
        .then_with(|| a.path.cmp(&b.path)));
    sweep.expired();
    sweep.snapshot
}

struct Counted<'a, R> {
    inner: R,
    count: &'a Cell<usize>,
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        self.count.set(self.count.get().saturating_add(count));
        Ok(count)
    }
}

fn read_line(
    reader: &mut impl BufRead,
    out: &mut Vec<u8>,
    limit: usize,
    mut within_deadline: impl FnMut() -> bool,
) -> io::Result<bool> {
    loop {
        if !within_deadline() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "maps deadline exhausted"));
        }
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return if out.is_empty() { Ok(false) } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unterminated maps row"))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if take > limit.saturating_sub(out.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "maps row exceeds limit"));
        }
        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            out.pop(); // newline is framing, not part of the pathname
            return Ok(true);
        }
    }
}

fn disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid mapping header or pathname")
}

fn field<'a>(input: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let remaining = *input;
    let trimmed = remaining.trim_ascii_start();
    let end = trimmed.iter().position(u8::is_ascii_whitespace).unwrap_or(trimmed.len());
    if end == 0 { return Err(malformed()); }
    *input = &trimmed[end..];
    Ok(&trimmed[..end])
}

fn number(raw: &[u8], radix: u32) -> io::Result<u64> {
    if raw.is_empty() || !raw.iter().all(|b| if radix == 16 { b.is_ascii_hexdigit() } else { b.is_ascii_digit() }) {
        return Err(malformed());
    }
    u64::from_str_radix(std::str::from_utf8(raw).map_err(|_| malformed())?, radix).map_err(|_| malformed())
}

pub(super) fn parse_row(pid: i32, raw: &[u8]) -> io::Result<Option<MappedRegion>> {
    let mut rest = raw;
    let range = field(&mut rest)?;
    let perms = field(&mut rest)?;
    let offset = field(&mut rest)?;
    let device = field(&mut rest)?;
    let inode = field(&mut rest)?;
    let split = range.iter().position(|b| *b == b'-').ok_or_else(malformed)?;
    let start = number(&range[..split], 16)?;
    let end = number(&range[split + 1..], 16)?;
    if start >= end || perms.len() != 4 || !matches!(perms[0], b'r' | b'-')
        || !matches!(perms[1], b'w' | b'-') || !matches!(perms[2], b'x' | b'-')
        || !matches!(perms[3], b'p' | b's')
    { return Err(malformed()); }
    number(offset, 16)?;
    let split = device.iter().position(|b| *b == b':').ok_or_else(malformed)?;
    number(&device[..split], 16)?;
    number(&device[split + 1..], 16)?;
    number(inode, 10)?;
    let path = rest.trim_ascii_start();
    if path.is_empty() || (path.starts_with(b"[") && path.ends_with(b"]")) {
        return Ok(None);
    }
    if !path.starts_with(b"/") || path.contains(&0) { return Err(malformed()); }
    Ok(Some(MappedRegion {
        pid,
        path: PathBuf::from(OsString::from_vec(path.to_vec())),
        start_address: Some(start),
        end_address: Some(end),
        protection: Some(String::from_utf8_lossy(&perms[..3]).into_owned()),
    }))
}

fn path_spellings(path: &Path) -> Vec<PathBuf> {
    let raw = path.as_os_str().as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while !rest.is_empty() {
        if rest.starts_with(b"\\012") {
            decoded.push(b'\n');
            rest = &rest[4..];
        } else {
            decoded.push(rest[0]);
            rest = &rest[1..];
        }
    }
    // Linux maps escapes newline but leaves literal backslash-octal sequences
    // ambiguous. Retain both interpretations, and both deleted-suffix forms.
    let mut paths = vec![path.to_path_buf()];
    if decoded != raw { paths.push(PathBuf::from(OsString::from_vec(decoded))); }
    for index in 0..paths.len() {
        if let Some(stripped) = paths[index].as_os_str().as_bytes().strip_suffix(b" (deleted)") {
            let stripped = PathBuf::from(OsStr::from_bytes(stripped));
            if stripped.is_absolute() { paths.push(stripped); }
        }
    }
    paths.sort_unstable();
    paths.dedup();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    struct Fixture {
        _temp: tempfile::TempDir,
        proc: PathBuf,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let base = fs::canonicalize(temp.path()).unwrap();
            let proc = base.join("proc");
            let root = base.join("artifacts");
            fs::create_dir(&proc).unwrap();
            fs::create_dir(&root).unwrap();
            Self { _temp: temp, proc, root }
        }

        fn maps(&self, pid: i32, bytes: &[u8]) {
            let process = self.proc.join(pid.to_string());
            fs::create_dir_all(&process).unwrap();
            fs::write(process.join("maps"), bytes).unwrap();
        }

        fn row(&self, name: &str) -> Vec<u8> {
            format!("1000-2000 r-xp 00000000 08:01 42 {}/{}\n", self.root.display(), name).into_bytes()
        }

        fn scan(&self, access: &impl Access, limits: Limits) -> Snapshot {
            collect(access, &self.proc, limits)
        }
    }

    struct Faults {
        errors: BTreeMap<PathBuf, i32>,
        entry_error: Option<PathBuf>,
        absent_pid: Option<i32>,
        clock: Rc<Cell<Instant>>,
        step: Duration,
        chunk: usize,
        interrupt: bool,
    }

    impl Default for Faults {
        fn default() -> Self {
            Self {
                errors: BTreeMap::new(), entry_error: None, absent_pid: None,
                clock: Rc::new(Cell::new(Instant::now())), step: Duration::ZERO,
                chunk: usize::MAX, interrupt: false,
            }
        }
    }

    struct AdvancingReader {
        inner: Box<dyn Read>,
        clock: Rc<Cell<Instant>>,
        step: Duration,
        chunk: usize,
        interrupt: bool,
    }

    impl Read for AdvancingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.clock.set(self.clock.get() + self.step);
            if self.interrupt { return Err(io::Error::from(io::ErrorKind::Interrupted)); }
            let len = buffer.len().min(self.chunk);
            self.inner.read(&mut buffer[..len])
        }
    }

    impl Access for Faults {
        fn entries(&self, path: &Path) -> io::Result<Entries> {
            if let Some(code) = self.errors.get(path) { return Err(io::Error::from_raw_os_error(*code)); }
            let mut entries: Vec<_> = Native.entries(path)?.collect();
            entries.sort_by(|a, b| a.as_ref().ok().cmp(&b.as_ref().ok()));
            if self.entry_error.as_deref() == Some(path) {
                entries.insert(0, Err(io::Error::from_raw_os_error(libc::EIO)));
            }
            if let Some(pid) = self.absent_pid { entries.push(Ok(OsString::from(pid.to_string()))); }
            Ok(Box::new(entries.into_iter()))
        }
        fn open(&self, path: &Path) -> io::Result<Box<dyn Read>> {
            if let Some(code) = self.errors.get(path) { return Err(io::Error::from_raw_os_error(*code)); }
            Ok(Box::new(AdvancingReader {
                inner: Native.open(path)?, clock: Rc::clone(&self.clock), step: self.step,
                chunk: self.chunk, interrupt: self.interrupt,
            }))
        }
        fn gone(&self, path: &Path) -> bool { Native.gone(path) }
        fn now(&self) -> Instant { self.clock.get() }
    }

    fn task_stat(pid: i32, state: &str, flags: u64, threads: usize) -> String {
        let mut fields = vec!["0".to_string(); 20];
        fields[0] = state.into();
        fields[6] = flags.to_string();
        fields[17] = threads.to_string();
        format!("{pid} (name with ) parens) {}\n", fields.join(" "))
    }

    #[test]
    fn complete_snapshot_preserves_sorted_regions_and_scoped_queries() {
        let fixture = Fixture::new();
        fixture.maps(22, &fixture.row("later"));
        fixture.maps(11, &fixture.row("earlier"));
        let result = fixture.scan(&Native, Limits::default());
        assert!(result.incomplete.is_none());
        let all = result.under(&fixture.root).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].pid, all[1].pid), (11, 22));
        assert_eq!(all[0].protection.as_deref(), Some("r-x"));
        assert_eq!(all[0].start_address, Some(0x1000));
        assert_eq!(all[0].end_address, Some(0x2000));
        assert_eq!(result.under(&fixture.root.join("earlier")).unwrap().len(), 1);
        assert!(result.under(&fixture.root.join("unrelated")).unwrap().is_empty());
    }

    #[test]
    fn denied_maps_keep_partial_positives_but_cannot_return_a_successful_vector() {
        let fixture = Fixture::new();
        fixture.maps(1, &fixture.row("hidden"));
        fixture.maps(2, &fixture.row("visible"));
        for code in [libc::EACCES, libc::EPERM, libc::EIO, libc::EMFILE] {
            let mut access = Faults::default();
            access.errors.insert(fixture.proc.join("1/maps"), code);
            let snapshot = fixture.scan(&access, Limits::default());
            assert_eq!(snapshot.regions.len(), 1);
            assert_eq!(snapshot.regions[0].path, fixture.root.join("visible"));
            assert!(snapshot.under(&fixture.root).is_err());
            assert!(snapshot.under(&fixture.root.join("unrelated")).is_err());
        }
    }

    #[test]
    fn discovery_and_iteration_failures_are_not_empty_complete_evidence() {
        let fixture = Fixture::new();
        fixture.maps(1, &fixture.row("held"));
        let mut denied = Faults::default();
        denied.errors.insert(fixture.proc.clone(), libc::EACCES);
        assert!(fixture.scan(&denied, Limits::default()).under(&fixture.root).is_err());
        let faulty = Faults { entry_error: Some(fixture.proc.clone()), ..Faults::default() };
        let result = fixture.scan(&faulty, Limits::default());
        assert_eq!(result.regions.len(), 1);
        assert!(result.under(&fixture.root).is_err());
    }

    #[test]
    fn missing_live_maps_are_incomplete_but_confirmed_gone_pids_are_benign() {
        let fixture = Fixture::new();
        fixture.maps(1, &fixture.row("held"));
        let access = Faults { absent_pid: Some(99), ..Faults::default() };
        assert!(fixture.scan(&access, Limits::default()).incomplete.is_none());
        fs::create_dir(fixture.proc.join("2")).unwrap();
        let result = fixture.scan(&Native, Limits::default());
        assert!(result.incomplete.is_some());
        assert_eq!(result.regions.len(), 1);
    }

    #[test]
    fn empty_maps_require_matching_kernel_or_terminal_single_thread_evidence() {
        let fixture = Fixture::new();
        fixture.maps(1, b"");
        let stat = fixture.proc.join("1/stat");
        for (pid, state, flags, threads, complete) in [
            (1, "S", PF_KTHREAD, 1, true), (1, "Z", 0, 1, true),
            (1, "Z", 0, 2, false), (1, "S", 0, 1, false),
            (2, "Z", 0, 1, false), (1, "Z", 0, 0, false),
        ] {
            fs::write(&stat, task_stat(pid, state, flags, threads)).unwrap();
            assert_eq!(fixture.scan(&Native, Limits::default()).incomplete.is_none(), complete);
        }
        fs::write(&stat, vec![b'x'; STAT_BYTES + 1]).unwrap();
        assert!(fixture.scan(&Native, Limits::default()).incomplete.is_some());
        let mut access = Faults::default();
        access.errors.insert(stat, libc::EACCES);
        assert!(fixture.scan(&access, Limits::default()).incomplete.is_some());
    }

    #[test]
    fn parser_preserves_byte_paths_whitespace_and_ambiguous_kernel_spellings() {
        let raw = b"1000-2000 rw-s 00000000 00:01 42 /cache/nonutf-\xff name\\012x (deleted)  ";
        let region = parse_row(7, raw).unwrap().unwrap();
        assert_eq!(region.path.as_os_str().as_bytes(), b"/cache/nonutf-\xff name\\012x (deleted)  ");
        assert_eq!(region.protection.as_deref(), Some("rw-"));
        let path = Path::new(OsStr::from_bytes(b"/cache/name-\xff\\012x (deleted)"));
        let variants = path_spellings(path);
        for expected in [
            b"/cache/name-\xff\\012x (deleted)".as_slice(), b"/cache/name-\xff\nx (deleted)",
            b"/cache/name-\xff\\012x", b"/cache/name-\xff\nx",
        ] {
            assert!(variants.contains(&PathBuf::from(OsStr::from_bytes(expected))));
        }
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn malformed_rows_revoke_coverage_while_valid_rows_survive() {
        let fixture = Fixture::new();
        let valid = fixture.row("kept");
        for malformed in [
            "junk", "2000-1000 r-xp 0 00:01 42 /cache/x", "1000-2000 rw?x 0 00:01 42 /cache/x",
            "1000-2000 r-xp xyz 00:01 42 /cache/x", "1000-2000 r-xp 0 BAD 42 /cache/x",
            "1000-2000 r-xp 0 00:01 nope /cache/x", "1000-2000 r-xp 0 00:01 42 relative",
        ] {
            let mut bytes = format!("{malformed}\n").into_bytes();
            bytes.extend_from_slice(&valid);
            fixture.maps(1, &bytes);
            let result = fixture.scan(&Native, Limits::default());
            assert!(result.incomplete.is_some(), "{malformed}");
            assert_eq!(result.regions.len(), 1);
        }
        for row in [b"1000-2000 rw-p 0 00:00 0".as_slice(), b"1000-2000 rw-p 0 00:00 0 [anon:name]"] {
            assert!(parse_row(1, row).unwrap().is_none());
        }
    }

    #[test]
    fn exact_byte_and_row_length_bounds_are_distinguished_from_truncation() {
        let fixture = Fixture::new();
        let row = fixture.row("one");
        fixture.maps(1, &row);
        for cap in [row.len() - 1, row.len(), row.len() + 1] {
            for limits in [
                Limits { bytes: cap, ..Limits::default() },
                Limits { bytes_per_pid: cap, ..Limits::default() },
                Limits { line_bytes: cap, ..Limits::default() },
            ] {
                assert_eq!(fixture.scan(&Native, limits).incomplete.is_none(), cap >= row.len());
            }
        }
        fixture.maps(1, &row[..row.len() - 1]);
        assert!(fixture.scan(&Native, Limits::default()).incomplete.is_some(), "missing final newline");
        fixture.maps(1, &vec![b'x'; 1024 * 1024]);
        assert!(fixture.scan(&Native, Limits { line_bytes: 64, ..Limits::default() }).incomplete.is_some());
    }

    #[test]
    fn pid_line_and_result_limits_bound_work_without_claiming_full_coverage() {
        let fixture = Fixture::new();
        for pid in 1..=3 { fixture.maps(pid, &fixture.row("mapped")); }
        for cap in 0..=4 {
            for limits in [
                Limits { pids: cap, ..Limits::default() },
                Limits { entries: cap, ..Limits::default() },
                Limits { lines: cap, ..Limits::default() },
                Limits { regions: cap, ..Limits::default() },
            ] {
                let result = fixture.scan(&Faults::default(), limits);
                assert_eq!(result.incomplete.is_none(), cap >= 3);
                assert!(result.regions.len() <= cap);
            }
        }
        let mut rows = fixture.row("first");
        rows.extend(fixture.row("second"));
        fixture.maps(1, &rows);
        let result = fixture.scan(&Native, Limits { lines_per_pid: 1, ..Limits::default() });
        assert!(result.incomplete.is_some());
        assert_eq!(result.regions.len(), 3, "a large PID must not hide later readable PIDs");
    }

    #[test]
    fn slow_single_pid_and_repeated_interruptions_cannot_renew_the_deadline() {
        let fixture = Fixture::new();
        let row = fixture.row("held");
        fixture.maps(1, &row.repeat(5));
        let access = Faults { step: Duration::from_secs(1), chunk: row.len(), ..Faults::default() };
        let limits = Limits { time: Duration::from_secs(2), ..Limits::default() };
        let result = fixture.scan(&access, limits);
        assert!(result.incomplete.is_some());
        assert_eq!(result.regions.len(), 2);
        let interrupted = Faults { step: Duration::from_secs(1), interrupt: true, ..Faults::default() };
        let result = fixture.scan(&interrupted, limits);
        assert!(result.incomplete.is_some());
        assert!(result.regions.is_empty());
    }

    #[test]
    fn nonregular_maps_inputs_are_refused_without_waiting() {
        let fixture = Fixture::new();
        let process = fixture.proc.join("1");
        fs::create_dir(&process).unwrap();
        nix::unistd::mkfifo(&process.join("maps"), nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(fixture.scan(&Native, Limits::default()).under(&fixture.root).is_err());
    }

    #[test]
    fn cache_ages_success_from_collection_start_and_reuses_it_across_roots() {
        let cache = Cache::default();
        let start = Instant::now();
        let clock = Cell::new(start);
        let count = Cell::new(0);
        cache.obtain(|| clock.get(), || {
            count.set(count.get() + 1);
            clock.set(start + Duration::from_secs(10));
            Snapshot::default()
        }).unwrap();
        clock.set(start + Duration::from_secs(29));
        assert!(cache.obtain(|| clock.get(), || panic!("must reuse")).unwrap().under(Path::new("/a")).is_ok());
        clock.set(start + Duration::from_secs(30));
        cache.obtain(|| clock.get(), || { count.set(count.get() + 1); Snapshot::default() }).unwrap();
        assert_eq!(count.get(), 2, "publication time must not extend freshness");
    }

    #[test]
    fn failed_refresh_never_resurrects_old_success_and_has_a_bounded_retry_backoff() {
        let cache = Cache::default();
        let start = Instant::now();
        cache.obtain(|| start, Snapshot::default).unwrap();
        let failed_at = start + SNAPSHOT_TTL;
        let failed = cache.obtain(|| failed_at, || {
            let mut result = Snapshot::default(); result.fail("denied"); result
        }).unwrap();
        assert!(failed.under(Path::new("/")).is_err());
        assert!(cache.obtain(|| failed_at + Duration::from_secs(1), || panic!("must back off"))
            .unwrap().under(Path::new("/")).is_err());
        assert!(cache.obtain(|| failed_at + FAILURE_TTL, Snapshot::default)
            .unwrap().under(Path::new("/")).is_ok());
    }

    #[test]
    fn an_expired_collection_is_never_published_as_fresh_success() {
        let cache = Cache::default();
        let start = Instant::now();
        let clock = Cell::new(start);
        let result = cache.obtain(|| clock.get(), || {
            clock.set(start + SNAPSHOT_TTL); Snapshot::default()
        }).unwrap();
        assert!(result.under(Path::new("/")).is_err());
    }

    #[test]
    fn concurrent_refresh_is_coalesced_without_blocking_other_callers() {
        use std::sync::mpsc;
        use std::thread;
        let cache = Arc::new(Cache::default());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first = Arc::clone(&cache);
        let worker = thread::spawn(move || first.obtain(Instant::now, || {
            entered_tx.send(()).unwrap(); release_rx.recv().unwrap(); Snapshot::default()
        }));
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = Arc::clone(&cache);
        let (reply_tx, reply_rx) = mpsc::channel();
        let requester = thread::spawn(move || {
            let result = second.obtain(Instant::now, || panic!("duplicate sweep"));
            reply_tx.send(result.is_err()).unwrap();
        });
        let refused = reply_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        assert!(worker.join().unwrap().is_ok());
        requester.join().unwrap();
        assert!(refused.unwrap());
        assert!(cache.obtain(Instant::now, || panic!("already refreshed")).is_ok());
    }

    #[test]
    fn current_pid_native_maps_retain_executable_mapping_with_complete_coverage() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let mut sweep = Sweep::new(&Native, Limits::default());
        sweep.maps(Path::new(PROC_ROOT), pid);
        sweep.expired();
        let executable = resolve_absolute_path(&std::env::current_exe().unwrap());
        let regions = sweep.snapshot.under(&executable).unwrap();
        assert!(regions.iter().any(|region| region.pid == pid
            && region.protection.as_deref().is_some_and(|mode| mode.contains('x'))));
    }
}
