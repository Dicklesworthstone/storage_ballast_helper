//! Read-only PSI for tasks in this process's cgroup, not its sibling workloads.
//!
//! Reuse the verified kernel-file reader and bounded namespace resolution used
//! by the RAM admission guard. PSI is a stall measurement, not a byte allowance;
//! this observer neither changes cgroup controls nor grants reclamation rights.

use std::io;
use std::path::Path;

use super::{
    Access, CONTROLLER_BYTES, MEMBERSHIP, MEMBERSHIP_BYTES, MOUNT_BYTES, MOUNTS, Native,
    Observation, PATH_BYTES, SCALAR_BYTES, Source, hierarchy_mount, invalid, membership_path,
};

pub(in crate::platform::linux) const PSI_BYTES: usize = 4096;

/// None means that the existing resolver identified an unsupported hierarchy,
/// or that this process is alone in its cgroup; the caller uses host PSI alone
/// there. A v2 read failure is an error, not a zero-pressure sample. Do not
/// cache paths across process migration.
pub(in crate::platform::linux) fn read() -> io::Result<Option<u64>> {
    read_with(&Native, std::process::id())
}

fn read_with(access: &impl Access, own_pid: u32) -> io::Result<Option<u64>> {
    let mut observation = Observation::new(access);
    let membership = observation.read(Path::new(MEMBERSHIP), MEMBERSHIP_BYTES, Source::Proc)?;
    let member = match membership_path(&membership) {
        Ok(member) => member,
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            if observation.read(Path::new(MEMBERSHIP), MEMBERSHIP_BYTES, Source::Proc)?
                != membership
            {
                return Err(invalid("cgroup membership changed during PSI observation"));
            }
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mounts = observation.read(Path::new(MOUNTS), MOUNT_BYTES, Source::Proc)?;
    let mount = hierarchy_mount(&mounts, &member)?;
    let relative = member
        .strip_prefix("/")
        .map_err(|_| invalid("invalid PSI membership"))?;
    let scope = mount.join(relative);
    let pressure_path = scope.join("memory.pressure");
    if pressure_path.as_os_str().as_encoded_bytes().len() > PATH_BYTES {
        return Err(invalid("cgroup PSI path exceeded its allowance"));
    }
    if holds_only(&mut observation, &scope, own_pid)? {
        if observation.read(Path::new(MEMBERSHIP), MEMBERSHIP_BYTES, Source::Proc)? != membership
            || observation.read(Path::new(MOUNTS), MOUNT_BYTES, Source::Proc)? != mounts
        {
            return Err(invalid("cgroup PSI scope changed during observation"));
        }
        observation.check_time()?;
        return Ok(None);
    }
    // Older kernels do not expose this switch. A readable PSI file is still
    // usable on those kernels, but an explicit zero must not certify health.
    let enabled_path = scope.join("cgroup.pressure");
    let enabled = observation.optional(&enabled_path, SCALAR_BYTES)?;
    if let Some(raw) = &enabled
        && super::counter(raw)? != 1
    {
        return Err(invalid("cgroup PSI accounting is disabled or invalid"));
    }
    let raw = observation.read(&pressure_path, PSI_BYTES, Source::Cgroup)?;
    let avg10 = std::str::from_utf8(&raw)
        .ok()
        .and_then(parse_avg10)
        .ok_or_else(|| invalid("invalid cgroup memory pressure record"))?;
    if observation.optional(&enabled_path, SCALAR_BYTES)? != enabled
        || observation.read(Path::new(MEMBERSHIP), MEMBERSHIP_BYTES, Source::Proc)? != membership
        || observation.read(Path::new(MOUNTS), MOUNT_BYTES, Source::Proc)? != mounts
    {
        return Err(invalid(
            "cgroup PSI scope or accounting changed during observation",
        ));
    }
    observation.check_time()?;
    Ok(Some(avg10))
}

/// Whether `scope` holds this process and nothing else: no other process and
/// no descendant cgroup whose tasks its PSI would also count.
///
/// Such a cgroup's PSI is this process's own stall. A dedicated service at its
/// own MemoryMax reclaims the dentries and page cache its walk charged (ts2,
/// 2026-10-21: sbh.service avg10 2.8% -> 35% within 10 s, host avg10 near 2%),
/// and reading that as workload memory pressure flipped the behavior mode 53-146
/// times an hour and raised 3-8 Critical+Critical emergencies an hour.
fn holds_only(
    observation: &mut Observation<'_, impl Access>,
    scope: &Path,
    own_pid: u32,
) -> io::Result<bool> {
    let procs = observation.read(
        &scope.join("cgroup.procs"),
        MEMBERSHIP_BYTES,
        Source::Cgroup,
    )?;
    let own = own_pid.to_string();
    let alone = std::str::from_utf8(&procs)
        .is_ok_and(|raw| !raw.is_empty() && raw.lines().all(|pid| pid == own));
    if !alone {
        return Ok(false);
    }
    let stat = observation.read(&scope.join("cgroup.stat"), CONTROLLER_BYTES, Source::Cgroup)?;
    std::str::from_utf8(&stat)
        .ok()
        .and_then(|raw| {
            raw.lines()
                .find_map(|line| line.strip_prefix("nr_descendants "))
        })
        .and_then(|count| count.parse::<u64>().ok())
        .map(|count| count == 0)
        .ok_or_else(|| invalid("cgroup.stat has no valid nr_descendants count"))
}

/// Parse the kernel's complete `some` row, shared with host PSI. Invalid,
/// truncated, duplicate or out-of-range data is never coerced to zero. Future
/// keyed fields are allowed without giving them meaning in the current policy.
pub(in crate::platform::linux) fn parse_avg10(raw: &str) -> Option<u64> {
    if raw.len() > PSI_BYTES || !raw.ends_with('\n') || !raw.is_ascii() {
        return None;
    }
    let mut sample = None;
    for line in raw.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("some") {
            continue;
        }
        if sample.is_some() {
            return None;
        }
        let mut averages = [None; 3];
        let mut total = None;
        for field in fields {
            let (key, value) = field.split_once('=')?;
            if key.is_empty() || value.is_empty() {
                return None;
            }
            let slot = match key {
                "avg10" => Some(0),
                "avg60" => Some(1),
                "avg300" => Some(2),
                "total" => {
                    if total.replace(unsigned(value)?).is_some() {
                        return None;
                    }
                    None
                }
                _ => None,
            };
            if let Some(slot) = slot
                && averages[slot].replace(centipercent(value)?).is_some()
            {
                return None;
            }
        }
        let [Some(avg10), Some(_), Some(_)] = averages else {
            return None;
        };
        total?;
        sample = Some(avg10);
    }
    sample
}

fn unsigned(raw: &str) -> Option<u64> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

fn centipercent(raw: &str) -> Option<u64> {
    let (whole, fraction) = match raw.split_once('.') {
        Some((whole, fraction)) if (1..=2).contains(&fraction.len()) => (whole, Some(fraction)),
        Some(_) => return None,
        None => (raw, None),
    };
    let whole = unsigned(whole)?;
    let fraction = match fraction {
        Some(fraction) => unsigned(fraction)? * if fraction.len() == 1 { 10 } else { 1 },
        None => 0,
    };
    whole
        .checked_mul(100)?
        .checked_add(fraction)
        .filter(|value| *value <= 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    struct Fixture {
        files: BTreeMap<PathBuf, Vec<u8>>,
        changed: Option<(PathBuf, Vec<u8>)>,
        denied: Option<PathBuf>,
        reads: RefCell<BTreeMap<PathBuf, usize>>,
        now: Cell<Instant>,
        step: Duration,
    }

    const OWN: u32 = 42;

    fn psi(avg10: &str) -> Vec<u8> {
        format!("some avg10={avg10} avg60=0.00 avg300=0.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").into_bytes()
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                files: BTreeMap::from([
                    (MEMBERSHIP.into(), b"0::/service\n".to_vec()),
                    (
                        MOUNTS.into(),
                        b"36 25 0:32 / /cg rw - cgroup2 cgroup rw\n".to_vec(),
                    ),
                    ("/cg/service/cgroup.procs".into(), b"7\n42\n".to_vec()),
                    ("/cg/service/cgroup.pressure".into(), b"1\n".to_vec()),
                    ("/cg/service/memory.pressure".into(), psi("73.50")),
                ]),
                changed: None,
                denied: None,
                reads: RefCell::new(BTreeMap::new()),
                now: Cell::new(Instant::now()),
                step: Duration::ZERO,
            }
        }
    }

    impl Access for Fixture {
        fn read(&self, path: &Path, _: usize, _: Source) -> io::Result<Vec<u8>> {
            self.now.set(self.now.get() + self.step);
            let mut reads = self.reads.borrow_mut();
            let count = reads.entry(path.to_path_buf()).or_default();
            *count += 1;
            if self.denied.as_deref() == Some(path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if let Some((changed, raw)) = &self.changed
                && changed == path
                && *count > 1
            {
                return Ok(raw.clone());
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
    fn reads_the_process_scope_without_scanning_siblings_or_memory_limits() {
        let fixture = Fixture::default();
        assert_eq!(read_with(&fixture, OWN).unwrap(), Some(7350));
        assert_eq!(fixture.reads.borrow().values().sum::<usize>(), 8);
        assert!(
            fixture
                .reads
                .borrow()
                .keys()
                .all(|path| fixture.files.contains_key(path))
        );
    }

    #[test]
    fn a_cgroup_holding_only_this_process_defers_to_host_psi() {
        let alone = || {
            let mut fixture = Fixture::default();
            fixture
                .files
                .insert("/cg/service/cgroup.procs".into(), b"42\n".to_vec());
            fixture.files.insert(
                "/cg/service/cgroup.stat".into(),
                b"nr_descendants 0\nnr_dying_descendants 3\n".to_vec(),
            );
            fixture
        };
        let fixture = alone();
        assert_eq!(read_with(&fixture, OWN).unwrap(), None);
        let reads = fixture.reads.borrow();
        assert!(!reads.contains_key(Path::new("/cg/service/memory.pressure")));
        assert!(!reads.contains_key(Path::new("/cg/service/cgroup.pressure")));
        assert_eq!(reads.values().sum::<usize>(), 6);
        drop(reads);

        // Its own stall still counts once the cgroup is shared: another
        // process, or a descendant cgroup whose tasks the PSI includes.
        let mut fixture = alone();
        fixture
            .files
            .insert("/cg/service/cgroup.procs".into(), b"42\n43\n".to_vec());
        assert_eq!(read_with(&fixture, OWN).unwrap(), Some(7350));
        let mut fixture = alone();
        fixture.files.insert(
            "/cg/service/cgroup.stat".into(),
            b"nr_descendants 1\nnr_dying_descendants 0\n".to_vec(),
        );
        assert_eq!(read_with(&fixture, OWN).unwrap(), Some(7350));
        assert_eq!(read_with(&alone(), 43).unwrap(), Some(7350));

        // Alone but unprovable is an error, never a quiet Normal.
        let mut fixture = alone();
        fixture.files.remove(Path::new("/cg/service/cgroup.stat"));
        assert!(read_with(&fixture, OWN).is_err());
        for raw in [
            b"nr_dying_descendants 0\n".as_slice(),
            b"nr_descendants x\n",
        ] {
            let mut fixture = alone();
            fixture
                .files
                .insert("/cg/service/cgroup.stat".into(), raw.to_vec());
            assert!(read_with(&fixture, OWN).is_err(), "{raw:?}");
        }
        let fixture = Fixture {
            changed: Some((MEMBERSHIP.into(), b"0::/moved\n".to_vec())),
            ..alone()
        };
        assert!(read_with(&fixture, OWN).is_err());
    }

    #[test]
    fn rechecks_accounting_membership_and_mounts_before_publishing() {
        for (path, raw) in [
            (MEMBERSHIP, b"0::/moved\n".as_slice()),
            (MOUNTS, b"37 25 0:32 / /cg rw - cgroup2 cgroup rw\n"),
            ("/cg/service/cgroup.pressure", b"0\n"),
        ] {
            let fixture = Fixture {
                changed: Some((path.into(), raw.to_vec())),
                ..Fixture::default()
            };
            assert!(read_with(&fixture, OWN).is_err(), "{path}");
        }
    }

    #[test]
    fn disabled_or_invalid_accounting_never_returns_a_healthy_sample() {
        for raw in [b"0\n".as_slice(), b"2\n", b"garbage\n"] {
            let mut fixture = Fixture::default();
            fixture
                .files
                .insert("/cg/service/cgroup.pressure".into(), raw.to_vec());
            assert!(read_with(&fixture, OWN).is_err());
            assert!(
                !fixture
                    .reads
                    .borrow()
                    .contains_key(Path::new("/cg/service/memory.pressure"))
            );
        }
    }

    #[test]
    fn a_kernel_without_the_accounting_switch_still_needs_a_valid_psi_record() {
        let mut fixture = Fixture::default();
        fixture
            .files
            .remove(Path::new("/cg/service/cgroup.pressure"));
        assert_eq!(read_with(&fixture, OWN).unwrap(), Some(7350));
        fixture.files.insert(
            "/cg/service/memory.pressure".into(),
            b"some avg10=0.00\n".to_vec(),
        );
        assert!(read_with(&fixture, OWN).is_err());
    }

    #[test]
    fn inaccessible_or_missing_v2_pressure_is_not_an_unsupported_hierarchy() {
        for path in [
            MEMBERSHIP,
            MOUNTS,
            "/cg/service/cgroup.procs",
            "/cg/service/cgroup.pressure",
            "/cg/service/memory.pressure",
        ] {
            let fixture = Fixture {
                denied: Some(path.into()),
                ..Fixture::default()
            };
            assert_eq!(
                read_with(&fixture, OWN).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        let mut fixture = Fixture::default();
        fixture
            .files
            .remove(Path::new("/cg/service/memory.pressure"));
        assert!(read_with(&fixture, OWN).is_err());
    }

    #[test]
    fn legacy_hierarchy_is_explicitly_host_only_but_malformed_membership_is_not() {
        let mut fixture = Fixture::default();
        fixture
            .files
            .insert(MEMBERSHIP.into(), b"5:memory:/service\n".to_vec());
        assert_eq!(read_with(&fixture, OWN).unwrap(), None);
        assert_eq!(fixture.reads.borrow().len(), 1);
        fixture
            .files
            .insert(MEMBERSHIP.into(), b"invalid\n".to_vec());
        assert!(read_with(&fixture, OWN).is_err());
    }

    #[test]
    fn failed_final_read_cannot_renew_the_original_deadline() {
        let fixture = Fixture {
            step: super::super::SCAN_TIME / 8 + Duration::from_nanos(1),
            ..Fixture::default()
        };
        assert_eq!(
            read_with(&fixture, OWN).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(fixture.reads.borrow().values().sum::<usize>(), 8);
    }

    #[test]
    fn pressure_is_fresh_after_recovery_and_between_process_migrations() {
        let mut fixture = Fixture::default();
        assert_eq!(read_with(&fixture, OWN).unwrap(), Some(7350));
        fixture
            .files
            .insert(MEMBERSHIP.into(), b"0::/next\n".to_vec());
        fixture
            .files
            .insert("/cg/next/cgroup.procs".into(), b"42\n43\n".to_vec());
        fixture
            .files
            .insert("/cg/next/cgroup.pressure".into(), b"1\n".to_vec());
        fixture
            .files
            .insert("/cg/next/memory.pressure".into(), psi("0.00"));
        assert_eq!(read_with(&fixture, OWN).unwrap(), Some(0));
    }

    #[test]
    fn parses_complete_some_rows_in_any_key_order_without_coercion() {
        for (raw, expected) in [
            ("0", 0),
            ("5", 500),
            ("5.1", 510),
            ("12.34", 1234),
            ("100.00", 10000),
        ] {
            assert_eq!(
                parse_avg10(std::str::from_utf8(&psi(raw)).unwrap()),
                Some(expected)
            );
        }
        assert_eq!(
            parse_avg10("some total=18446744073709551615 avg300=0 avg10=12.34 avg60=0 future=1\n"),
            Some(1234)
        );
    }

    #[test]
    fn malformed_percentages_cannot_become_zero_pressure() {
        for raw in [
            "",
            ".5",
            "5.",
            "5.x",
            "5.123",
            "-1",
            "+1",
            "101",
            "100.01",
            "1e2",
            "NaN",
            "18446744073709551616",
        ] {
            assert_eq!(
                parse_avg10(std::str::from_utf8(&psi(raw)).unwrap()),
                None,
                "{raw}"
            );
        }
    }

    #[test]
    fn truncated_duplicate_and_oversized_records_are_unknown() {
        for raw in [
            "some avg10=0.00\n",
            "some avg10=0 avg60=0 avg300=0 total=0",
            "some avg10=0 avg10=99 avg60=0 avg300=0 total=0\n",
            "some avg10=0 avg60=0 avg300=0 total=-1\n",
            "some avg10=0 avg60=0 avg300=0 total=0 total=1\n",
            "some avg10=0 avg60=0 avg300=0 total=0\nsome avg10=99 avg60=0 avg300=0 total=1\n",
        ] {
            assert_eq!(parse_avg10(raw), None, "{raw:?}");
        }
        let mut fixture = Fixture::default();
        fixture.files.insert(
            "/cg/service/memory.pressure".into(),
            vec![b'x'; PSI_BYTES + 1],
        );
        assert!(read_with(&fixture, OWN).is_err());
    }
}
