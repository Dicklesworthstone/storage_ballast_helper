//! Bounded buffer negotiation for the native all-process inventory.
//!
//! A size probe is only a hint: processes can start before the filling call.
//! A full response cannot certify completeness. Retry into a genuinely larger
//! initialized slice, and refuse perpetual churn or oversized observations.
//! This module contains no FFI so its production logic also runs in Linux tests.

use std::io;
use std::mem::size_of;

const MAX_PID_SLOTS: usize = 65_536;
const MAX_FILL_CALLS: usize = 8;
const EXTRA_PID_SLOTS: usize = 32;

/// Decode libproc's byte count without losing its zero-on-failure errno.
/// This is an all-process query: the running observer prevents valid emptiness.
pub(super) fn native_byte_count(returned: i32, errno: Option<i32>) -> io::Result<usize> {
    if returned > 0 {
        return usize::try_from(returned).map_err(|_| invalid("PID byte count overflow"));
    }
    match errno {
        Some(code) if code != 0 => Err(io::Error::from_raw_os_error(code)),
        _ => Err(io::Error::other(
            "native process inventory failed without errno",
        )),
    }
}

pub(super) fn collect(
    query: impl FnMut(Option<&mut [i32]>) -> io::Result<usize>,
    observer: i32,
) -> io::Result<Vec<i32>> {
    collect_with(query, observer, MAX_PID_SLOTS, MAX_FILL_CALLS)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn slots(bytes: usize) -> io::Result<usize> {
    if bytes == 0 || bytes % size_of::<i32>() != 0 {
        return Err(invalid("native PID byte count is empty or misaligned"));
    }
    Ok(bytes / size_of::<i32>())
}

fn collect_with(
    mut query: impl FnMut(Option<&mut [i32]>) -> io::Result<usize>,
    observer: i32,
    max_slots: usize,
    max_fills: usize,
) -> io::Result<Vec<i32>> {
    if observer <= 0 || max_slots == 0 || max_fills == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process inventory requires an observer and nonzero budgets",
        ));
    }
    let hint = slots(query(None)?)?;
    if hint > max_slots {
        return Err(io::Error::other(
            "native PID inventory exceeds its buffer budget",
        ));
    }
    let mut wanted = hint.saturating_add(EXTRA_PID_SLOTS).min(max_slots);
    let mut pids = Vec::new();
    for _ in 0..max_fills {
        // reserve() takes an increment relative to LEN, not CAPACITY. The old
        // zero-length Vec reserved its existing capacity on a full response,
        // which could do nothing forever. Resize the initialized slice too;
        // the FFI is given its length, never allocator-dependent spare capacity.
        pids.try_reserve_exact(wanted.saturating_sub(pids.len()))
            .map_err(|_| io::Error::other("cannot allocate native PID inventory buffer"))?;
        pids.resize(wanted, 0_i32);
        pids.fill(0);
        let returned = slots(query(Some(&mut pids))?)?;
        if returned > pids.len() {
            return Err(invalid("native PID response exceeds the supplied buffer"));
        }
        if returned == pids.len() {
            if wanted == max_slots {
                return Err(io::Error::other(
                    "native PID inventory filled its maximum buffer",
                ));
            }
            wanted = wanted.saturating_mul(2).min(max_slots);
            continue;
        }
        // Only the last complete response is published. Never combine a
        // partial earlier list with a later list from a different observation.
        pids.truncate(returned);
        if pids.iter().any(|pid| *pid < 0) || !pids.contains(&observer) {
            return Err(invalid(
                "native PID inventory is invalid or omitted its observer",
            ));
        }
        return Ok(pids);
    }
    Err(io::Error::other(
        "native PID inventory did not stabilize within its query budget",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVER: i32 = 41;

    fn byte_len(slots: usize) -> usize {
        slots * size_of::<i32>()
    }

    #[test]
    fn full_hint_buffer_really_grows_and_only_the_final_inventory_is_returned() {
        let mut lengths = Vec::new();
        let result = collect_with(
            |buffer| {
                let Some(buffer) = buffer else {
                    return Ok(byte_len(1));
                };
                lengths.push(buffer.len());
                assert!(
                    buffer.iter().all(|pid| *pid == 0),
                    "clear stale observations"
                );
                if lengths.len() == 1 {
                    buffer.fill(99);
                    return Ok(byte_len(buffer.len()));
                }
                buffer[..2].copy_from_slice(&[OBSERVER, 42]);
                Ok(byte_len(2))
            },
            OBSERVER,
            128,
            8,
        )
        .unwrap();
        assert_eq!(lengths, vec![33, 66]);
        assert_eq!(result, vec![OBSERVER, 42]);
    }

    #[test]
    fn perpetual_process_growth_stops_after_the_fill_call_budget() {
        let mut lengths = Vec::new();
        let result = collect_with(
            |buffer| {
                let Some(buffer) = buffer else {
                    return Ok(byte_len(1));
                };
                lengths.push(buffer.len());
                buffer.fill(OBSERVER);
                Ok(byte_len(buffer.len()))
            },
            OBSERVER,
            1024,
            3,
        );
        assert!(result.is_err());
        assert_eq!(lengths, vec![33, 66, 132]);
    }

    #[test]
    fn final_allowed_call_can_finish_a_growing_inventory() {
        let mut fills = 0;
        let result = collect_with(
            |buffer| {
                let Some(buffer) = buffer else {
                    return Ok(byte_len(1));
                };
                fills += 1;
                buffer[0] = OBSERVER;
                Ok(byte_len(if fills == 1 { buffer.len() } else { 1 }))
            },
            OBSERVER,
            128,
            2,
        )
        .unwrap();
        assert_eq!(fills, 2);
        assert_eq!(result, vec![OBSERVER]);
    }

    #[test]
    fn maximum_buffer_requires_a_short_response_not_an_exact_fit() {
        for full in [false, true] {
            let mut fills = 0;
            let result = collect_with(
                |buffer| {
                    let Some(buffer) = buffer else {
                        return Ok(byte_len(4));
                    };
                    fills += 1;
                    assert_eq!(buffer.len(), 4);
                    buffer.fill(OBSERVER);
                    Ok(byte_len(if full { 4 } else { 3 }))
                },
                OBSERVER,
                4,
                8,
            );
            assert_eq!(result.is_err(), full);
            assert_eq!(fills, 1);
        }
    }

    #[test]
    fn oversized_size_hints_are_rejected_before_any_fill_allocation() {
        let mut probes = 0;
        assert!(
            collect_with(
                |buffer| {
                    assert!(buffer.is_none());
                    probes += 1;
                    Ok(byte_len(129))
                },
                OBSERVER,
                128,
                8
            )
            .is_err()
        );
        assert_eq!(probes, 1);
    }

    #[test]
    fn zero_or_misaligned_size_hints_never_start_a_fill() {
        for hint in [0, 1, 3, 5, usize::MAX] {
            assert!(
                collect_with(
                    |buffer| {
                        assert!(buffer.is_none());
                        Ok(hint)
                    },
                    OBSERVER,
                    128,
                    8
                )
                .is_err(),
                "hint={hint}"
            );
        }
    }

    #[test]
    fn invalid_returned_byte_counts_are_not_complete_inventories() {
        for count in [0, 1, 3, 5, byte_len(129), usize::MAX] {
            assert!(
                collect_with(
                    |buffer| {
                        let Some(buffer) = buffer else {
                            return Ok(byte_len(1));
                        };
                        buffer[0] = OBSERVER;
                        Ok(count)
                    },
                    OBSERVER,
                    128,
                    8
                )
                .is_err(),
                "count={count}"
            );
        }
    }

    #[test]
    fn discovery_and_later_fill_errors_preserve_the_original_error() {
        for fail_at in 0..=2 {
            let mut call = 0;
            let result = collect_with(
                |buffer| {
                    let current = call;
                    call += 1;
                    if current == fail_at {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "native refusal",
                        ));
                    }
                    let Some(buffer) = buffer else {
                        return Ok(byte_len(1));
                    };
                    buffer.fill(OBSERVER);
                    Ok(byte_len(buffer.len()))
                },
                OBSERVER,
                128,
                8,
            );
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "native refusal");
            assert_eq!(call, fail_at + 1);
        }
    }

    #[test]
    fn missing_observer_or_negative_pids_are_missing_evidence() {
        for values in [[42, 43], [OBSERVER, -1]] {
            assert!(
                collect_with(
                    |buffer| {
                        let Some(buffer) = buffer else {
                            return Ok(byte_len(2));
                        };
                        buffer[..2].copy_from_slice(&values);
                        Ok(byte_len(2))
                    },
                    OBSERVER,
                    128,
                    8
                )
                .is_err()
            );
        }
    }

    #[test]
    fn only_returned_slots_are_read_and_kernel_pid_zero_is_retained() {
        let result = collect(
            |buffer| {
                let Some(buffer) = buffer else {
                    return Ok(byte_len(2));
                };
                buffer.fill(-1);
                buffer[..2].copy_from_slice(&[0, OBSERVER]);
                Ok(byte_len(2))
            },
            OBSERVER,
        )
        .unwrap();
        assert_eq!(result, vec![0, OBSERVER]);
    }

    #[test]
    fn each_call_takes_a_new_inventory_instead_of_reusing_previous_absence() {
        for child in [42, 43] {
            let result = collect(
                |buffer| {
                    let Some(buffer) = buffer else {
                        return Ok(byte_len(2));
                    };
                    buffer[..2].copy_from_slice(&[OBSERVER, child]);
                    Ok(byte_len(2))
                },
                OBSERVER,
            )
            .unwrap();
            assert_eq!(result, vec![OBSERVER, child]);
        }
    }

    #[test]
    fn invalid_observer_or_disabled_budget_stops_before_native_io() {
        for (observer, slots, fills) in [
            (0, 128, 8),
            (-1, 128, 8),
            (OBSERVER, 0, 8),
            (OBSERVER, 128, 0),
        ] {
            assert!(collect_with(|_| panic!("must not query"), observer, slots, fills).is_err());
        }
    }

    #[test]
    fn zero_native_failure_preserves_errno_and_success_ignores_stale_errno() {
        for returned in [0, -1] {
            for errno in [1, 5, 13] {
                assert_eq!(
                    native_byte_count(returned, Some(errno))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(errno)
                );
            }
            for errno in [None, Some(0)] {
                assert!(native_byte_count(returned, errno).is_err());
            }
        }
        assert_eq!(native_byte_count(16, Some(13)).unwrap(), 16);
    }
}
