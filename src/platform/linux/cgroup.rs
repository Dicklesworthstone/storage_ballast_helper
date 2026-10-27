//! Read-only admission evidence for this process's visible cgroup-v2 memory limits.
//!
//! Host MemAvailable does not describe a service's allocation budget. Inspect
//! every visible ancestor, never subtract a child's usage from a parent's limit,
//! and never count swap as extra RAM. This is an observation, not a reservation:
//! hidden namespace ancestors and concurrent charges remain outside its proof.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags, fstatfs, open, openat};

use crate::platform::pal::{MemoryBoundaryKind, MemoryHeadroom};

pub(super) mod pressure;

const MEMBERSHIP: &str = "/proc/self/cgroup";
const MOUNTS: &str = "/proc/self/mountinfo";
const MEMBERSHIP_BYTES: usize = 64 * 1024;
const MOUNT_BYTES: usize = 1024 * 1024;
const PATH_BYTES: usize = 8192;
const SCALAR_BYTES: usize = 64;
const CONTROLLER_BYTES: usize = 4096;
const TOTAL_BYTES: usize = 3 * 1024 * 1024;
const MAX_READS: usize = 512;
const MAX_ANCESTORS: usize = 32;
const SCAN_TIME: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
enum Source {
    Proc,
    Cgroup,
}

trait Access {
    fn read(&self, path: &Path, limit: usize, source: Source) -> io::Result<Vec<u8>>;
    fn now(&self) -> Instant;
}

struct Native;

impl Access for Native {
    fn read(&self, path: &Path, limit: usize, source: Source) -> io::Result<Vec<u8>> {
        let file = match source {
            Source::Proc => OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)?,
            Source::Cgroup => open_cgroup_file(path)?,
        };
        let expected = match source {
            Source::Proc => 0x9fa0,
            Source::Cgroup => 0x6367_7270,
        };
        if fstatfs(&file)?.f_type != expected || !file.metadata()?.is_file() {
            return Err(invalid(
                "memory evidence is not a regular file on the expected kernel filesystem",
            ));
        }
        let mut bytes = Vec::new();
        file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(invalid("memory evidence exceeded its byte allowance"));
        }
        Ok(bytes)
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

fn open_cgroup_file(path: &Path) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let mut directory = open("/", flags | OFlags::DIRECTORY, Mode::empty())?;
    let mut components = path.components().peekable();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid("cgroup evidence path is not absolute"));
    }
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(invalid("cgroup evidence path contains traversal"));
        };
        if components.peek().is_none() {
            return Ok(File::from(openat(&directory, name, flags, Mode::empty())?));
        }
        directory = openat(&directory, name, flags | OFlags::DIRECTORY, Mode::empty())?;
    }
    Err(invalid("cgroup evidence path has no filename"))
}

struct Observation<'a, A> {
    access: &'a A,
    started: Instant,
    reads: usize,
    bytes: usize,
}

impl<'a, A: Access> Observation<'a, A> {
    fn new(access: &'a A) -> Self {
        Self {
            access,
            started: access.now(),
            reads: 0,
            bytes: 0,
        }
    }

    fn check_time(&self) -> io::Result<()> {
        if self
            .access
            .now()
            .checked_duration_since(self.started)
            .is_some_and(|elapsed| elapsed < SCAN_TIME)
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cgroup memory observation timed out",
            ))
        }
    }

    fn read(&mut self, path: &Path, limit: usize, source: Source) -> io::Result<Vec<u8>> {
        self.check_time()?;
        if self.reads >= MAX_READS || limit > TOTAL_BYTES.saturating_sub(self.bytes) {
            return Err(invalid(
                "cgroup memory observation exhausted its work budget",
            ));
        }
        self.reads += 1;
        let result = self.access.read(path, limit, source);
        self.check_time()?;
        match result {
            Ok(bytes) if bytes.len() <= limit => {
                self.bytes += bytes.len();
                Ok(bytes)
            }
            Ok(_) => Err(invalid("cgroup reader returned oversized evidence")),
            Err(error) => {
                // Failed reads are attempts too, not a fresh byte allowance.
                self.bytes += limit;
                Err(error)
            }
        }
    }

    fn optional(&mut self, path: &Path, limit: usize) -> io::Result<Option<Vec<u8>>> {
        match self.read(path, limit, Source::Cgroup) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Constraint {
    scope: PathBuf,
    field: &'static str,
    used: u64,
    limit: u64,
}

impl Constraint {
    fn refuses(&self, percent: u8) -> bool {
        // Swap disabled at zero is not itself a reason to refuse RAM. Memory
        // limits at zero, however, cannot back even the first new log page.
        if self.limit == 0 {
            return self.field != "memory.swap.max" || self.used != 0;
        }
        u128::from(self.limit.saturating_sub(self.used)) * 100
            < u128::from(self.limit) * u128::from(percent)
    }
}

/// Additional RAM-write refusal, without changing the host-wide memory API.
///
/// Legacy memory-controller hierarchies, unreadable evidence and hidden bind
/// ancestors are errors rather than a claim of available capacity. No writes,
/// reclaim requests, process enumeration or configuration changes are performed.
pub fn ram_write_refusal(percent: u8) -> io::Result<Option<String>> {
    refusal_with(&Native, percent)
}

/// Tightest observed finite RAM boundary across this process's visible ancestry.
///
/// This uses the same bounded, stable hierarchy observation as RAM logging,
/// but adds no percentage reserve and never treats swap as a RAM allowance.
pub fn ram_write_headroom() -> io::Result<Option<MemoryHeadroom>> {
    headroom_with(&Native)
}

fn headroom_with(access: &impl Access) -> io::Result<Option<MemoryHeadroom>> {
    Ok(inspect(access, false)?
        .into_iter()
        .filter_map(|constraint| {
            let boundary_kind = match constraint.field {
                "memory.high" => MemoryBoundaryKind::Throttle,
                "memory.max" => MemoryBoundaryKind::HardLimit,
                // Swap is independently constrained and is never necessary
                // to fit a byte request which already fits observed RAM.
                _ => return None,
            };
            Some(MemoryHeadroom {
                scope: constraint.scope,
                boundary: constraint.field,
                boundary_kind,
                current_bytes: constraint.used,
                limit_bytes: constraint.limit,
            })
        })
        .min_by_key(MemoryHeadroom::available_bytes))
}

fn refusal_with(access: &impl Access, percent: u8) -> io::Result<Option<String>> {
    if !(1..=100).contains(&percent) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid memory headroom percentage",
        ));
    }
    Ok(inspect(access, true)?
        .into_iter()
        .find(|limit| limit.refuses(percent))
        .map(|limit| {
            format!(
                "cgroup \"{}\" {} has {} of {} bytes headroom ({}% required)",
                limit.scope.display(),
                limit.field,
                limit.limit.saturating_sub(limit.used),
                limit.limit,
                percent,
            )
        }))
}

fn inspect(access: &impl Access, include_swap: bool) -> io::Result<Vec<Constraint>> {
    let mut observation = Observation::new(access);
    let membership = observation.read(Path::new(MEMBERSHIP), MEMBERSHIP_BYTES, Source::Proc)?;
    let member = membership_path(&membership)?;
    let mounts = observation.read(Path::new(MOUNTS), MOUNT_BYTES, Source::Proc)?;
    let mount = hierarchy_mount(&mounts, &member)?;
    let relative = member
        .strip_prefix("/")
        .map_err(|_| invalid("invalid cgroup membership"))?;
    let leaf = mount.join(relative);
    if leaf.as_os_str().as_encoded_bytes().len() > PATH_BYTES {
        return Err(invalid("resolved cgroup path exceeded its allowance"));
    }
    let mut constraints = Vec::new();
    let mut reached_root = false;
    for (depth, scope) in leaf.ancestors().enumerate() {
        if depth >= MAX_ANCESTORS || !scope.starts_with(&mount) {
            return Err(invalid("cgroup ancestry exceeded its observation boundary"));
        }
        observe_scope(
            &mut observation,
            scope,
            &mount,
            &mut constraints,
            include_swap,
        )?;
        if scope == mount {
            reached_root = true;
            break;
        }
    }
    if !reached_root {
        return Err(invalid("cgroup hierarchy root was not observed"));
    }
    // A migration or mount-table change invalidates the entire observation.
    // Counter samples are not cached across admissions or interpreted as leases.
    if observation.read(Path::new(MEMBERSHIP), MEMBERSHIP_BYTES, Source::Proc)? != membership
        || observation.read(Path::new(MOUNTS), MOUNT_BYTES, Source::Proc)? != mounts
    {
        return Err(invalid(
            "cgroup membership or mounts changed during observation",
        ));
    }
    observation.check_time()?;
    Ok(constraints)
}

fn observe_scope(
    observation: &mut Observation<'_, impl Access>,
    scope: &Path,
    mount: &Path,
    constraints: &mut Vec<Constraint>,
    include_swap: bool,
) -> io::Result<()> {
    let current = observation.optional(&scope.join("memory.current"), SCALAR_BYTES)?;
    let high = observation.optional(&scope.join("memory.high"), SCALAR_BYTES)?;
    let max = observation.optional(&scope.join("memory.max"), SCALAR_BYTES)?;
    let (current, high, max) = match (current, high, max) {
        (Some(current), Some(high), Some(max)) => (current, high, max),
        (None, None, None) => {
            // At the real hierarchy root memory limits do not exist. Below
            // it, missing files need evidence that the parent did not enable
            // this controller; missing files alone never certify no limit.
            memory_enabled(&observation.read(
                &scope.join("cgroup.controllers"),
                CONTROLLER_BYTES,
                Source::Cgroup,
            )?)?;
            if scope != mount {
                let parent = scope
                    .parent()
                    .ok_or_else(|| invalid("missing cgroup parent"))?;
                let control = parent.join("cgroup.subtree_control");
                let before = observation.read(&control, CONTROLLER_BYTES, Source::Cgroup)?;
                if memory_enabled(&before)?
                    || observation.read(&control, CONTROLLER_BYTES, Source::Cgroup)? != before
                {
                    return Err(invalid("memory controller evidence is missing or changed"));
                }
            }
            return Ok(());
        }
        _ => return Err(invalid("cgroup memory controller evidence is incomplete")),
    };
    let current_after =
        observation.read(&scope.join("memory.current"), SCALAR_BYTES, Source::Cgroup)?;
    let used = counter(&current)?.max(counter(&current_after)?);
    for (field, raw) in [("memory.high", high), ("memory.max", max)] {
        let limit = limit(&raw)?;
        if observation.read(&scope.join(field), SCALAR_BYTES, Source::Cgroup)? != raw {
            return Err(invalid("cgroup memory limit changed during observation"));
        }
        if let Some(limit) = limit {
            constraints.push(Constraint {
                scope: scope.to_path_buf(),
                field,
                used,
                limit,
            });
        }
    }
    if !include_swap {
        return Ok(());
    }
    let swap_current = observation.optional(&scope.join("memory.swap.current"), SCALAR_BYTES)?;
    let swap_max = observation.optional(&scope.join("memory.swap.max"), SCALAR_BYTES)?;
    match (swap_current, swap_max) {
        // Kernels without swap accounting expose neither file. This does not
        // add swap capacity to memory headroom or bypass the host swap guard.
        (None, None) => {}
        (Some(current), Some(max)) => {
            let used = counter(&current)?.max(counter(&observation.read(
                &scope.join("memory.swap.current"),
                SCALAR_BYTES,
                Source::Cgroup,
            )?)?);
            let limit = limit(&max)?;
            if observation.read(&scope.join("memory.swap.max"), SCALAR_BYTES, Source::Cgroup)?
                != max
            {
                return Err(invalid("cgroup swap limit changed during observation"));
            }
            if let Some(limit) = limit {
                constraints.push(Constraint {
                    scope: scope.to_path_buf(),
                    field: "memory.swap.max",
                    used,
                    limit,
                });
            }
        }
        _ => return Err(invalid("cgroup swap controller evidence is incomplete")),
    }
    Ok(())
}

fn scalar(raw: &[u8]) -> io::Result<&[u8]> {
    let value = raw.strip_suffix(b"\n").unwrap_or(raw);
    if value.is_empty() || raw.len() > SCALAR_BYTES {
        return Err(invalid("empty or oversized cgroup counter"));
    }
    Ok(value)
}

fn memory_enabled(raw: &[u8]) -> io::Result<bool> {
    if raw.len() > CONTROLLER_BYTES
        || raw.iter().any(|byte| {
            !byte.is_ascii_alphanumeric() && !byte.is_ascii_whitespace() && !b"_-".contains(byte)
        })
    {
        return Err(invalid("invalid cgroup controller inventory"));
    }
    Ok(raw
        .split(u8::is_ascii_whitespace)
        .any(|name| name == b"memory"))
}

fn counter(raw: &[u8]) -> io::Result<u64> {
    let value = scalar(raw)?;
    if !value.iter().all(u8::is_ascii_digit) {
        return Err(invalid("invalid cgroup counter"));
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| invalid("cgroup counter overflow"))
}

fn limit(raw: &[u8]) -> io::Result<Option<u64>> {
    if scalar(raw)? == b"max" {
        Ok(None)
    } else {
        counter(raw).map(Some)
    }
}

fn path(raw: &[u8]) -> io::Result<PathBuf> {
    if raw.first() != Some(&b'/')
        || raw.len() > PATH_BYTES
        || raw.contains(&0)
        || raw
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(invalid("invalid or traversing cgroup path"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(raw.to_vec())))
}

fn membership_path(raw: &[u8]) -> io::Result<PathBuf> {
    if raw.len() > MEMBERSHIP_BYTES || !raw.ends_with(b"\n") {
        return Err(invalid("cgroup membership is oversized or truncated"));
    }
    let mut unified = None;
    for line in raw[..raw.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.splitn(3, |byte| *byte == b':');
        let id = fields.next().unwrap_or_default();
        let controllers = fields
            .next()
            .ok_or_else(|| invalid("invalid cgroup membership record"))?;
        let member = fields
            .next()
            .ok_or_else(|| invalid("invalid cgroup membership record"))?;
        if id.is_empty()
            || !id.iter().all(u8::is_ascii_digit)
            || (id == b"0" && !controllers.is_empty())
            || member.first() != Some(&b'/')
        {
            return Err(invalid("invalid cgroup membership record"));
        }
        if controllers
            .split(|byte| *byte == b',')
            .any(|name| name == b"memory")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "legacy cgroup memory limits are not observable by this guard",
            ));
        }
        if id == b"0" && controllers.is_empty() {
            if unified.is_some() {
                return Err(invalid("ambiguous cgroup membership"));
            }
            unified = Some(path(member)?);
        }
    }
    unified.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "no unified cgroup membership was observed",
        )
    })
}

fn unescape(raw: &[u8]) -> io::Result<PathBuf> {
    let mut decoded = Vec::new();
    let mut position = 0;
    while position < raw.len() {
        if raw[position] == b'\\' {
            let escape = raw
                .get(position + 1..position + 4)
                .ok_or_else(|| invalid("truncated mountinfo escape"))?;
            decoded.push(match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid("invalid mountinfo escape")),
            });
            position += 4;
        } else {
            decoded.push(raw[position]);
            position += 1;
        }
    }
    path(&decoded)
}

fn hierarchy_mount(raw: &[u8], member: &Path) -> io::Result<PathBuf> {
    if raw.len() > MOUNT_BYTES || !raw.ends_with(b"\n") {
        return Err(invalid("mountinfo is oversized or truncated"));
    }
    let mut selected = None;
    for (index, line) in raw[..raw.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if index >= 4096 || line.len() > 16 * 1024 {
            return Err(invalid("mountinfo exceeded its record budget"));
        }
        let separator = line
            .windows(3)
            .position(|part| part == b" - ")
            .ok_or_else(|| invalid("invalid mountinfo record"))?;
        if line[separator + 3..].split(|byte| *byte == b' ').next() != Some(b"cgroup2") {
            continue;
        }
        let mut fields = line[..separator].split(|byte| *byte == b' ');
        let root = unescape(
            fields
                .nth(3)
                .ok_or_else(|| invalid("missing cgroup mount root"))?,
        )?;
        let mount = unescape(
            fields
                .next()
                .ok_or_else(|| invalid("missing cgroup mount path"))?,
        )?;
        // A bind-mounted subtree hides enforcing ancestors. Do not substitute
        // its headroom for the whole visible hierarchy, even if it contains us.
        if root == Path::new("/")
            && member.starts_with(&root)
            && selected.as_ref().is_none_or(|old: &PathBuf| mount < *old)
        {
            selected = Some(mount);
        }
    }
    selected.ok_or_else(|| invalid("no full visible cgroup-v2 hierarchy mount was observed"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    const MOUNT: &str = "36 25 0:32 / /cg rw,nosuid,nodev,noexec - cgroup2 cgroup rw\n";

    struct Fixture {
        files: BTreeMap<PathBuf, Vec<u8>>,
        replacement: Option<(PathBuf, usize, Vec<u8>)>,
        denied: Option<PathBuf>,
        reads: RefCell<BTreeMap<PathBuf, usize>>,
        now: Cell<Instant>,
        step: Duration,
    }

    impl Default for Fixture {
        fn default() -> Self {
            let mut fixture = Self {
                files: BTreeMap::new(),
                replacement: None,
                denied: None,
                reads: RefCell::new(BTreeMap::new()),
                now: Cell::new(Instant::now()),
                step: Duration::ZERO,
            };
            fixture.put(MEMBERSHIP, b"0::/service\n");
            fixture.put(MOUNTS, MOUNT.as_bytes());
            fixture.put("/cg/cgroup.controllers", b"cpu memory pids\n");
            fixture.put("/cg/cgroup.subtree_control", b"memory\n");
            fixture.scope("/cg/service", 100, b"max\n", b"max\n");
            fixture
        }
    }

    impl Fixture {
        fn put(&mut self, path: impl Into<PathBuf>, bytes: &[u8]) {
            self.files.insert(path.into(), bytes.to_vec());
        }

        fn scope(&mut self, path: &str, used: u64, high: &[u8], max: &[u8]) {
            let path = Path::new(path);
            self.put(path.join("memory.current"), format!("{used}\n").as_bytes());
            self.put(path.join("memory.high"), high);
            self.put(path.join("memory.max"), max);
        }

        fn swap(&mut self, path: &str, used: u64, max: &[u8]) {
            self.put(
                Path::new(path).join("memory.swap.current"),
                format!("{used}\n").as_bytes(),
            );
            self.put(Path::new(path).join("memory.swap.max"), max);
        }

        fn calls(&self, path: &str) -> usize {
            self.reads
                .borrow()
                .get(Path::new(path))
                .copied()
                .unwrap_or(0)
        }
    }

    impl Access for Fixture {
        fn read(&self, path: &Path, _: usize, _: Source) -> io::Result<Vec<u8>> {
            self.now.set(self.now.get() + self.step);
            let nth = {
                let mut reads = self.reads.borrow_mut();
                let count = reads.entry(path.to_path_buf()).or_default();
                *count += 1;
                *count
            };
            if self.denied.as_deref() == Some(path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if let Some((target, at, bytes)) = &self.replacement
                && path == target
                && nth >= *at
            {
                return Ok(bytes.clone());
            }
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }

        fn now(&self) -> Instant {
            self.now.get()
        }
    }

    #[test]
    fn unlimited_hierarchy_is_distinct_from_unreadable_evidence() {
        let mut fixture = Fixture::default();
        assert_eq!(refusal_with(&fixture, 10).unwrap(), None);
        fixture.denied = Some("/cg/service/memory.max".into());
        assert_eq!(
            refusal_with(&fixture, 10).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn byte_headroom_uses_the_tightest_ancestors_own_charge() {
        let mut fixture = Fixture::default();
        fixture.put(MEMBERSHIP, b"0::/service/child\n");
        fixture.scope("/cg/service/child", 10, b"max\n", b"1000\n");
        fixture.scope("/cg/service", 951, b"max\n", b"1000\n");
        let headroom = headroom_with(&fixture).unwrap().unwrap();
        assert_eq!(headroom.scope, Path::new("/cg/service"));
        assert_eq!(headroom.boundary, "memory.max");
        assert_eq!(headroom.boundary_kind, MemoryBoundaryKind::HardLimit);
        assert_eq!(headroom.current_bytes, 951);
        assert_eq!(headroom.available_bytes(), 49);
        assert!(fixture.calls("/cg/service/child/memory.max") >= 2);
        assert!(fixture.calls("/cg/service/memory.max") >= 2);
    }

    #[test]
    fn byte_headroom_preserves_throttle_kind_without_a_percentage_reserve() {
        let mut fixture = Fixture::default();
        fixture.scope("/cg/service", 99, b"100\n", b"1000\n");
        let headroom = headroom_with(&fixture).unwrap().unwrap();
        assert_eq!(headroom.boundary, "memory.high");
        assert_eq!(headroom.boundary_kind, MemoryBoundaryKind::Throttle);
        assert_eq!(headroom.available_bytes(), 1);
        assert!(
            refusal_with(&fixture, 10).unwrap().is_some(),
            "log policy stays independent"
        );
    }

    #[test]
    fn byte_headroom_neither_adds_nor_requires_swap() {
        for (used, max) in [(0, 0), (100, 100), (0, u64::MAX)] {
            let mut fixture = Fixture::default();
            fixture.scope("/cg/service", 900, b"max\n", b"1000\n");
            fixture.swap("/cg/service", used, format!("{max}\n").as_bytes());
            // Byte admission needs only RAM boundaries, even if independent
            // swap counters cannot be inspected at all.
            fixture.denied = Some("/cg/service/memory.swap.current".into());
            assert_eq!(
                headroom_with(&fixture).unwrap().unwrap().available_bytes(),
                100
            );
            assert_eq!(fixture.calls("/cg/service/memory.swap.current"), 0);
            assert_eq!(fixture.calls("/cg/service/memory.swap.max"), 0);
            assert!(
                refusal_with(&fixture, 10).is_err(),
                "log swap policy is unchanged"
            );
        }
    }

    #[test]
    fn byte_headroom_distinguishes_unlimited_zero_and_over_limit() {
        let mut fixture = Fixture::default();
        assert!(headroom_with(&fixture).unwrap().is_none());
        for (used, limit) in [(0, 0), (101, 100), (u64::MAX, 1)] {
            fixture.scope(
                "/cg/service",
                used,
                b"max\n",
                format!("{limit}\n").as_bytes(),
            );
            assert_eq!(
                headroom_with(&fixture).unwrap().unwrap().available_bytes(),
                0
            );
        }
        fixture.denied = Some("/cg/service/memory.max".into());
        assert!(headroom_with(&fixture).is_err());
    }

    #[test]
    fn byte_headroom_uses_later_higher_usage_and_refuses_changed_boundaries() {
        let mut fixture = Fixture::default();
        fixture.scope("/cg/service", 10, b"max\n", b"100\n");
        fixture.replacement = Some(("/cg/service/memory.current".into(), 2, b"99\n".to_vec()));
        assert_eq!(
            headroom_with(&fixture).unwrap().unwrap().available_bytes(),
            1
        );

        for (path, replacement) in [
            ("/cg/service/memory.max", b"200\n".as_slice()),
            ("/cg/service/memory.high", b"50\n"),
            (MEMBERSHIP, b"0::/other\n"),
            (MOUNTS, b"37 25 0:32 / /cg rw - cgroup2 cgroup rw\n"),
        ] {
            let mut fixture = Fixture::default();
            fixture.scope("/cg/service", 10, b"max\n", b"100\n");
            fixture.replacement = Some((path.into(), 2, replacement.to_vec()));
            assert!(headroom_with(&fixture).is_err(), "{path}");
        }
    }

    #[test]
    fn byte_headroom_requires_complete_ancestry_within_the_shared_deadline() {
        let mut fixture = Fixture::default();
        fixture.put(MEMBERSHIP, b"0::/service/child\n");
        fixture.scope("/cg/service/child", 100, b"max\n", b"100\n");
        fixture.denied = Some("/cg/service/memory.max".into());
        assert!(
            headroom_with(&fixture).is_err(),
            "leaf shortfall does not certify complete ancestry"
        );

        let fixture = Fixture {
            step: Duration::from_millis(50),
            ..Fixture::default()
        };
        assert_eq!(
            headroom_with(&fixture).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn ancestor_usage_is_compared_to_its_own_limit_not_child_usage() {
        let mut fixture = Fixture::default();
        fixture.put(MEMBERSHIP, b"0::/service/child\n");
        fixture.scope("/cg/service/child", 0, b"max\n", b"100\n");
        fixture.scope("/cg/service", 951, b"max\n", b"1000\n");
        let refusal = refusal_with(&fixture, 10).unwrap().unwrap();
        assert!(refusal.contains("\"/cg/service\" memory.max"), "{refusal}");
        assert!(refusal.contains("49 of 1000"), "{refusal}");
    }

    #[test]
    fn high_boundary_and_start_margin_are_independent_of_the_hard_limit() {
        let mut fixture = Fixture::default();
        fixture.scope("/cg/service", 89, b"100\n", b"1000\n");
        assert_eq!(refusal_with(&fixture, 10).unwrap(), None);
        assert!(
            refusal_with(&fixture, 15)
                .unwrap()
                .unwrap()
                .contains("memory.high")
        );
        fixture.scope("/cg/service", 91, b"100\n", b"1000\n");
        assert!(refusal_with(&fixture, 10).unwrap().is_some());
    }

    #[test]
    fn exact_memory_threshold_is_allowed_but_zero_and_overage_are_not() {
        for (used, max, refused) in [
            (90, 100, false),
            (91, 100, true),
            (101, 100, true),
            (0, 0, true),
        ] {
            let mut fixture = Fixture::default();
            fixture.scope("/cg/service", used, b"max\n", format!("{max}\n").as_bytes());
            assert_eq!(
                refusal_with(&fixture, 10).unwrap().is_some(),
                refused,
                "{used}/{max}"
            );
        }
    }

    #[test]
    fn disabled_swap_is_not_added_to_ram_or_treated_as_exhausted_swap() {
        for (used, max, refused) in [
            (0, 0, false),
            (1, 0, true),
            (90, 100, false),
            (91, 100, true),
        ] {
            let mut fixture = Fixture::default();
            fixture.swap("/cg/service", used, format!("{max}\n").as_bytes());
            assert_eq!(
                refusal_with(&fixture, 10).unwrap().is_some(),
                refused,
                "{used}/{max}"
            );
        }
        let mut fixture = Fixture::default();
        fixture.scope("/cg/service", 100, b"max\n", b"100\n");
        fixture.swap("/cg/service", 0, b"1000000\n");
        assert!(
            refusal_with(&fixture, 10).unwrap().is_some(),
            "swap cannot back a RAM allowance"
        );
    }

    #[test]
    fn malformed_scalars_and_overflow_are_not_unlimited() {
        for raw in [
            b"".as_slice(),
            b"-1\n",
            b"+1\n",
            b"10 kB\n",
            b"1\n2\n",
            b"18446744073709551616\n",
            b"MAX\n",
            b" 12\n",
        ] {
            let mut fixture = Fixture::default();
            fixture.put("/cg/service/memory.max", raw);
            assert!(refusal_with(&fixture, 10).is_err(), "{raw:?}");
        }
        assert_eq!(counter(b"18446744073709551615\n").unwrap(), u64::MAX);
        assert_eq!(limit(b"max\n").unwrap(), None);
        assert!(counter(b"max\n").is_err());
    }

    #[test]
    fn missing_controller_files_need_disabled_parent_evidence() {
        let mut fixture = Fixture::default();
        fixture.put(MEMBERSHIP, b"0::/service/child\n");
        fixture.put("/cg/service/child/cgroup.controllers", b"cpu\n");
        fixture.put("/cg/service/cgroup.subtree_control", b"cpu\n");
        fixture.scope("/cg/service", 95, b"max\n", b"100\n");
        assert!(
            refusal_with(&fixture, 10)
                .unwrap()
                .unwrap()
                .contains("/cg/service")
        );
        fixture.put("/cg/service/cgroup.subtree_control", b"memory\n");
        assert!(refusal_with(&fixture, 10).is_err());
    }

    #[test]
    fn partial_memory_or_swap_interfaces_are_not_a_disabled_controller() {
        for field in [
            "memory.current",
            "memory.high",
            "memory.max",
            "memory.swap.max",
        ] {
            let mut fixture = Fixture::default();
            fixture.swap("/cg/service", 0, b"max\n");
            fixture.files.remove(&Path::new("/cg/service").join(field));
            assert!(refusal_with(&fixture, 10).is_err(), "{field}");
        }
    }

    #[test]
    fn legacy_memory_and_ambiguous_or_truncated_memberships_are_refused() {
        for raw in [
            b"5:memory:/service\n0::/service\n".as_slice(),
            b"0::/one\n0::/two\n",
            b"0::/service",
            b"",
            b"invalid\n",
            b"0:cpu:/service\n",
        ] {
            assert!(membership_path(raw).is_err(), "{raw:?}");
        }
        assert_eq!(
            membership_path(b"5:cpu:/other\n0::/service\n").unwrap(),
            Path::new("/service")
        );
    }

    #[test]
    fn namespace_traversal_and_hidden_bind_ancestors_do_not_certify_headroom() {
        for raw in [
            b"0::/../outside\n".as_slice(),
            b"0::/a/./b\n",
            b"0::relative\n",
            b"0::/a\0b\n",
        ] {
            assert!(membership_path(raw).is_err(), "{raw:?}");
        }
        let bind = b"36 25 0:32 /service /cg rw - cgroup2 cgroup rw\n";
        assert!(hierarchy_mount(bind, Path::new("/service/child")).is_err());
        assert!(
            hierarchy_mount(
                b"36 25 0:32 / /cg rw - ext4 /dev/x rw\n",
                Path::new("/service")
            )
            .is_err()
        );
    }

    #[test]
    fn escaped_mount_names_and_native_membership_bytes_are_preserved() {
        let raw = b"36 25 0:32 / /cg\\040space rw - cgroup2 cgroup rw\n";
        assert_eq!(
            hierarchy_mount(raw, Path::new("/service")).unwrap(),
            Path::new("/cg space")
        );
        let member = membership_path(b"0::/service-\xff\n").unwrap();
        assert_eq!(member.as_os_str().as_encoded_bytes(), b"/service-\xff");
        for raw in [b"/cg\\".as_slice(), b"/cg\\000x", b"/cg\\777"] {
            assert!(unescape(raw).is_err());
        }
        assert_eq!(
            unescape(b"/cg\\134x")
                .unwrap()
                .as_os_str()
                .as_encoded_bytes(),
            b"/cg\\x"
        );
    }

    #[test]
    fn membership_mount_or_limit_changes_revoke_the_observation() {
        for (path, replacement) in [
            (MEMBERSHIP, b"0::/changed\n".as_slice()),
            (MOUNTS, b"37 25 0:32 / /cg rw - cgroup2 cgroup rw\n"),
            ("/cg/service/memory.max", b"1\n"),
        ] {
            let fixture = Fixture {
                replacement: Some((path.into(), 2, replacement.to_vec())),
                ..Fixture::default()
            };
            assert!(refusal_with(&fixture, 10).is_err(), "{path}");
        }
    }

    #[test]
    fn growing_usage_keeps_the_larger_observation_instead_of_a_stale_allowance() {
        let mut fixture = Fixture::default();
        fixture.scope("/cg/service", 1, b"max\n", b"100\n");
        fixture.replacement = Some(("/cg/service/memory.current".into(), 2, b"99\n".to_vec()));
        let refusal = refusal_with(&fixture, 10).unwrap().unwrap();
        assert!(refusal.contains("1 of 100"), "{refusal}");
    }

    #[test]
    fn absence_and_healthy_results_are_not_cached_between_admissions() {
        let mut fixture = Fixture::default();
        assert_eq!(refusal_with(&fixture, 10).unwrap(), None);
        fixture.scope("/cg/service", 99, b"max\n", b"100\n");
        assert!(refusal_with(&fixture, 10).unwrap().is_some());
        fixture.scope("/cg/service", 1, b"max\n", b"100\n");
        assert_eq!(refusal_with(&fixture, 10).unwrap(), None);
        assert_eq!(fixture.calls(MEMBERSHIP), 6);
    }

    #[test]
    fn deadline_counts_the_first_and_last_read_without_renewal() {
        let baseline = Fixture::default();
        inspect(&baseline, true).unwrap();
        let calls: usize = baseline.reads.borrow().values().sum();
        let step = SCAN_TIME / u32::try_from(calls).unwrap() + Duration::from_nanos(1);
        let fixture = Fixture {
            step,
            ..Fixture::default()
        };
        assert_eq!(
            inspect(&fixture, true).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let fixture = Fixture {
            step: SCAN_TIME,
            ..Fixture::default()
        };
        assert_eq!(
            inspect(&fixture, true).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(fixture.calls(MEMBERSHIP), 1);
        assert_eq!(fixture.calls(MOUNTS), 0);
    }

    #[test]
    fn oversized_inputs_and_deep_ancestry_are_not_complete_observations() {
        for field in [MEMBERSHIP, MOUNTS, "/cg/service/memory.max"] {
            let mut fixture = Fixture::default();
            let size = match field {
                MEMBERSHIP => MEMBERSHIP_BYTES,
                MOUNTS => MOUNT_BYTES,
                _ => SCALAR_BYTES,
            };
            fixture.put(field, &vec![b'x'; size + 1]);
            assert!(inspect(&fixture, true).is_err(), "{field}");
        }
        let mut fixture = Fixture::default();
        let mut member = String::new();
        for _ in 0..MAX_ANCESTORS {
            member.push_str("/a");
            fixture.scope(&format!("/cg{member}"), 0, b"max\n", b"max\n");
        }
        fixture.put(MEMBERSHIP, format!("0::{member}\n").as_bytes());
        assert!(inspect(&fixture, true).is_err());
    }

    #[test]
    fn failed_reads_cannot_evade_the_shared_attempt_limit() {
        let fixture = Fixture::default();
        let mut observation = Observation::new(&fixture);
        for _ in 0..MAX_READS {
            assert!(
                observation
                    .optional(Path::new("/cg/missing"), SCALAR_BYTES)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            observation
                .optional(Path::new("/cg/missing"), SCALAR_BYTES)
                .is_err()
        );
        assert_eq!(fixture.calls("/cg/missing"), MAX_READS);
    }

    #[test]
    fn malformed_controller_tokens_and_invalid_percentages_fail_closed() {
        assert!(memory_enabled(b"memory\0\n").is_err());
        assert!(memory_enabled(b"cpu memory\n").unwrap());
        assert!(!memory_enabled(b"cpu\n").unwrap());
        for percent in [0, 101, u8::MAX] {
            let fixture = Fixture::default();
            assert!(refusal_with(&fixture, percent).is_err());
            assert!(fixture.reads.borrow().is_empty());
        }
    }

    #[test]
    fn native_reader_rejects_non_kernel_files_and_symlinked_components() {
        let temp = tempfile::tempdir().unwrap();
        let regular = temp.path().join("memory.max");
        std::fs::write(&regular, b"max\n").unwrap();
        assert!(Native.read(&regular, SCALAR_BYTES, Source::Cgroup).is_err());
        assert!(Native.read(&regular, SCALAR_BYTES, Source::Proc).is_err());
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(temp.path(), &alias).unwrap();
        assert!(open_cgroup_file(&alias.join("memory.max")).is_err());
    }
}
