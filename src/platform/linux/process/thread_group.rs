//! Proof that a whole thread group has entered do_exit (bd-q29t).
//!
//! A task inside do_exit (PF_EXITING) or already a zombie never runs user
//! code again, so its descriptors and mappings will not be used. The proof
//! must cover every live thread of the group, and a `/proc/PID/task` listing
//! cannot. A thread started after the listing is missing from it. When the
//! task the kernel has just emitted is released, `proc_task_readdir` stops
//! early, and the next read resumes by position past a live thread.
//!
//! The group's thread count closes that gap. Stat field 20 is
//! `signal->nr_threads`, which counts every thread not yet released,
//! exiting or not. The proof:
//!
//! 1. lists the group and reads each listed thread, keeping the ones that
//!    read exiting and dropping the ones already released;
//! 2. reads the group's thread count;
//! 3. reads each kept thread again and requires it still present, with the
//!    start time it had in step 1, so a reused thread ID is not mistaken for
//!    it;
//! 4. reads the count again and requires it unchanged.
//!
//! Every kept thread was unreleased at step 2 (it is present in step 3) and
//! exiting by then (step 1). A count equal to the number kept therefore
//! leaves no room for any other thread at step 2. Nothing outside do_exit
//! was left to start a thread after that, so the group never runs user code
//! again. Exit state is permanent, so the listing's own gaps do not matter.
//!
//! Two kernel details need the rest. When a non-leader thread calls execve,
//! `de_thread` gives it the leader's thread ID and start time and releases
//! the leader, so "present again with the same start time" does not prove
//! the leader's ID still names the exiting leader. A count is therefore
//! taken only from a group record that itself shows its task exiting: an
//! exec'ing thread is not. And one stat read takes the state before the
//! count but the flags after it, so a single record could pair a fresh
//! thread's count with a stale exit flag; the second count catches a thread
//! added in that window. A thread that reads running or unreadable, a count
//! that is missing, mismatched or changed, or a kept thread gone or replaced
//! by step 3 leaves the group unproven.

/// Stat fields 3 (state), 9 (flags), 20 (thread count) and 22 (start time,
/// in clock ticks since boot) from a record that names `pid`.
pub(super) struct Stat<'a> {
    pub(super) state: &'a str,
    pub(super) flags: u64,
    pub(super) threads: u64,
    pub(super) start_time: u64,
}

pub(super) fn parse_stat(raw: &str, pid: i32) -> Option<Stat<'_>> {
    let (head, _) = raw.split_once('(')?;
    if head.trim().parse::<i32>().ok() != Some(pid) {
        return None;
    }
    let fields = super::proc_stat_fields_after_comm(raw).ok()?;
    // fields[0] is stat field 3.
    Some(Stat {
        state: fields.first()?,
        flags: fields.get(6)?.parse().ok()?,
        threads: fields.get(17)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
    })
}

/// A thread group larger than this is not walked for exit evidence.
pub(super) const MAX_THREADS: usize = 4096;

/// PF_EXITING: the task is inside do_exit.
pub(super) const PF_EXITING: u64 = 0x0000_0004;

/// Whether a task's state and flags show it inside do_exit or dead.
pub(super) fn exiting(state: &str, flags: u64) -> bool {
    flags & PF_EXITING != 0 || matches!(state, "Z" | "X" | "x")
}

/// What one read of a thread's stat record showed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ThreadState {
    /// A record naming the thread.
    Read { exiting: bool, start_time: u64 },
    /// Released (ENOENT or ESRCH).
    Gone,
    /// Unreadable, oversized, malformed, or naming another task.
    Unknown,
}

/// The thread count of a group record that names `pid` and shows its task
/// exiting (see the module documentation).
pub(super) fn exiting_group_count(raw: &str, pid: i32) -> Option<u64> {
    parse_stat(raw, pid)
        .filter(|stat| exiting(stat.state, stat.flags))
        .map(|stat| stat.threads)
}

impl ThreadState {
    pub(super) fn from_record(raw: &str, tid: i32) -> Self {
        parse_stat(raw, tid).map_or(Self::Unknown, |stat| Self::Read {
            exiting: exiting(stat.state, stat.flags),
            start_time: stat.start_time,
        })
    }
}

/// The procfs reads the proof needs, for one thread group.
pub(super) trait ThreadGroup {
    /// Thread IDs listed under `/proc/PID/task`, or `None` when the listing
    /// failed, held a non-numeric entry, or exceeded the sweep's bound.
    fn tids(&mut self) -> Option<Vec<i32>>;
    /// One read of `/proc/PID/task/TID/stat`.
    fn thread(&mut self, tid: i32) -> ThreadState;
    /// The group's thread count from `/proc/PID/stat` (see
    /// [`exiting_group_count`]), or `None` when the record is unreadable,
    /// does not name the group, or does not show its task exiting.
    fn thread_count(&mut self) -> Option<u64>;
}

/// Whether every thread of the group is proven to be inside do_exit. See the
/// module documentation for the argument.
pub(super) fn whole_group_exiting(group: &mut impl ThreadGroup) -> bool {
    let Some(mut tids) = group.tids() else {
        return false;
    };
    tids.sort_unstable();
    if tids.windows(2).any(|pair| pair[0] == pair[1]) {
        return false;
    }
    let mut kept = Vec::with_capacity(tids.len());
    for tid in tids {
        match group.thread(tid) {
            ThreadState::Read {
                exiting: true,
                start_time,
            } => kept.push((tid, start_time)),
            ThreadState::Gone => {}
            ThreadState::Read { exiting: false, .. } | ThreadState::Unknown => return false,
        }
    }
    let count = Some(kept.len() as u64);
    if kept.is_empty() || group.thread_count() != count {
        return false;
    }
    kept.iter().all(|&(tid, start_time)| {
        group.thread(tid)
            == ThreadState::Read {
                exiting: true,
                start_time,
            }
    }) && group.thread_count() == count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Replays a scripted listing, thread reads and counts, checking order.
    struct Script {
        listing: Option<Option<Vec<i32>>>,
        reads: VecDeque<(i32, ThreadState)>,
        counts: VecDeque<Option<u64>>,
    }

    impl ThreadGroup for Script {
        fn tids(&mut self) -> Option<Vec<i32>> {
            self.listing.take().expect("listed twice")
        }
        fn thread(&mut self, tid: i32) -> ThreadState {
            let (expected, state) = self.reads.pop_front().expect("unexpected read");
            assert_eq!(expected, tid);
            state
        }
        fn thread_count(&mut self) -> Option<u64> {
            self.counts.pop_front().expect("unexpected count")
        }
    }

    fn run(
        listing: Option<Vec<i32>>,
        reads: &[(i32, ThreadState)],
        counts: &[Option<u64>],
    ) -> bool {
        let mut script = Script {
            listing: Some(listing),
            reads: reads.iter().copied().collect(),
            counts: counts.iter().copied().collect(),
        };
        let proven = whole_group_exiting(&mut script);
        assert!(script.reads.is_empty(), "unused reads: {:?}", script.reads);
        assert!(
            script.counts.is_empty(),
            "unused counts: {:?}",
            script.counts
        );
        proven
    }

    const fn exiting(start_time: u64) -> ThreadState {
        ThreadState::Read {
            exiting: true,
            start_time,
        }
    }

    const RUNNING: ThreadState = ThreadState::Read {
        exiting: false,
        start_time: 7,
    };

    #[test]
    fn a_group_whose_every_counted_thread_is_exiting_is_proven() {
        // The 2026-11-14 rust-lld shape: a zombie leader and one thread still
        // unmapping its memory.
        let reads = [
            (1, exiting(5)),
            (2, exiting(6)),
            (1, exiting(5)),
            (2, exiting(6)),
        ];
        assert!(run(Some(vec![2, 1]), &reads, &[Some(2), Some(2)]));
    }

    #[test]
    fn a_thread_the_listing_missed_is_caught_by_the_count() {
        // Started after the listing, or skipped by a truncated one.
        let reads = [(1, exiting(5)), (2, exiting(6))];
        assert!(!run(Some(vec![1, 2]), &reads, &[Some(3)]));
    }

    #[test]
    fn a_thread_added_while_the_group_record_was_read_is_caught_by_the_second_count() {
        let reads = [
            (1, exiting(5)),
            (2, exiting(6)),
            (1, exiting(5)),
            (2, exiting(6)),
        ];
        assert!(!run(Some(vec![1, 2]), &reads, &[Some(2), Some(3)]));
        assert!(!run(Some(vec![1, 2]), &reads, &[Some(2), None]));
    }

    #[test]
    fn a_thread_released_before_the_count_is_not_needed() {
        let reads = [(1, exiting(5)), (2, ThreadState::Gone), (1, exiting(5))];
        assert!(run(Some(vec![1, 2]), &reads, &[Some(1), Some(1)]));
    }

    #[test]
    fn a_leader_id_taken_over_by_an_exec_thread_leaves_the_group_unproven() {
        // de_thread moved the leader's ID and start time onto thread 2 and
        // released the leader, so 2 reads gone. The group record now shows
        // the exec'ing thread, which is not exiting, so no count is given.
        let reads = [(1, exiting(5)), (2, ThreadState::Gone)];
        assert!(!run(Some(vec![1, 2]), &reads, &[None]));
    }

    #[test]
    fn a_kept_thread_gone_or_replaced_after_the_count_leaves_the_group_unproven() {
        // Released before the count, it made room in the count for an
        // unlisted thread; a different start time is a reused thread ID.
        for last in [ThreadState::Gone, exiting(9), RUNNING, ThreadState::Unknown] {
            let reads = [(1, exiting(5)), (2, exiting(6)), (1, exiting(5)), (2, last)];
            assert!(!run(Some(vec![1, 2]), &reads, &[Some(2)]));
        }
    }

    #[test]
    fn any_running_unknown_or_missing_evidence_leaves_the_group_unproven() {
        assert!(!run(
            Some(vec![1, 2]),
            &[(1, exiting(5)), (2, RUNNING)],
            &[]
        ));
        assert!(!run(Some(vec![1, 2]), &[(1, ThreadState::Unknown)], &[]));
        assert!(!run(None, &[], &[]));
        assert!(!run(Some(vec![]), &[], &[]));
        assert!(!run(Some(vec![1, 1]), &[], &[]));
        assert!(!run(Some(vec![1]), &[(1, ThreadState::Gone)], &[]));
        assert!(!run(Some(vec![1]), &[(1, exiting(5))], &[None]));
        assert!(!run(Some(vec![1]), &[(1, exiting(5))], &[Some(0)]));
    }

    #[test]
    fn stat_records_parse_only_for_the_named_task() {
        let record = |pid: i32, state: &str, flags: u64, threads: u64| {
            let mut fields = vec!["0".to_string(); 50];
            fields[0] = state.to_string();
            fields[6] = flags.to_string();
            fields[17] = threads.to_string();
            fields[19] = "4242".to_string();
            format!("{pid} (a) b) {}\n", fields.join(" "))
        };
        let raw = record(7, "R", PF_EXITING, 3);
        let stat = parse_stat(&raw, 7).unwrap();
        assert_eq!(
            (stat.state, stat.flags, stat.threads, stat.start_time),
            ("R", PF_EXITING, 3, 4242)
        );
        assert!(parse_stat(&raw, 8).is_none());
        assert!(parse_stat("7 (a) R 0", 7).is_none());
        assert_eq!(ThreadState::from_record(&raw, 7), exiting(4242));
        let running = record(7, "S", 0, 3);
        assert_eq!(ThreadState::from_record(&running, 7), RUNNING_4242);
        assert_eq!(ThreadState::from_record(&raw, 9), ThreadState::Unknown);
        // A group count only from a record showing its task exiting.
        assert_eq!(exiting_group_count(&raw, 7), Some(3));
        assert_eq!(exiting_group_count(&record(7, "Z", 0, 2), 7), Some(2));
        assert_eq!(exiting_group_count(&running, 7), None);
        assert_eq!(exiting_group_count(&raw, 8), None);
    }

    const RUNNING_4242: ThreadState = ThreadState::Read {
        exiting: false,
        start_time: 4242,
    };
}
