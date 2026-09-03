# Scanner v1/v2 A/B evidence (2026-09-02)

Measured for bd-rc-master-ajg1.8.3 against the promotion criteria in
`docs/scanner-redesign-event-driven.md` section 7 (bd-xtpv.8). Binary:
release build of `origin/main` at 965c0a6 (v0.5.1), built and run on the
operator workstation (csd, Linux 7.0, `/data` = 5.5 TiB ext4, 46% used).
Everything below was produced and read by one agent session; nothing has
been independently re-run.

## 1. One-shot `sbh scan` (the design doc's capture procedure)

Commands, only the engine override changed:

```bash
SBH_SCANNER_ENGINE=v1 sbh --json scan <root> --top 200
SBH_SCANNER_ENGINE=v2 sbh --json scan <root> --top 200
```

Timed with `/usr/bin/time -f "wall=%es user=%Us sys=%Ss maxrss=%MKB"`; the
CPU column is the JSON's own `process_cpu_micros`.

| Root | Engine | CPU (s) | wall (s) | user / sys (s) | scanned_entries | opaque_pruned_dirs | candidates | total_reclaimable_bytes |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| /data/tmp | v1 | 0.87 | 0.75 | 0.12 / 0.77 | 893 | 0 | 7 | 12,288 |
| /data/tmp | v2 | 0.85 | 0.83 | 0.12 / 0.77 | 760 | 0 | 7 | 12,288 |
| /data/projects | v1 | 13.09 | 8.38 | 1.23 / 11.95 | 15,019 | 0 | 64 | 4,054,454,272 |
| /data/projects | v2 | 44.39 | 9.34 | 2.88 / 41.60 | 11,977 | 53 | 49 | 448,793,174,016 |

Two more pairs were captured through the `rch` hook (`cargo run
--release` directly, then `rch exec -- sh -c '... cargo run ...'`). The
compiles ran on a worker, but the binary executed on this workstation both
times (`hostname` printed from inside the wrapper was this host, the run
line names the local target directory, and the entry counts match the
local runs exactly), so neither is the "one rch VPS" sample the bead asks
for and they are not counted here (v1 0.77 s / v2 0.46 s and v1 0.69 s /
v2 0.78 s CPU on /data/tmp).

What the numbers say:

- On the small tree the engines are equivalent (same 7 candidates, same
  bytes, same decisions, CPU within noise).
- On the 2.1 TB project tree v2 spends **3.4x the CPU of v1** and almost all
  of it is system time: every one of the 53 opaque roots (`target/`,
  `node_modules/`, `.cargo/registry`, `.gocache`) is measured with the
  budgeted allocated-size probe (`opaque_tree_allocated_size`), which stats
  the pruned subtree v2 just declined to walk. v1 reports a shallow estimate
  instead (4 GB vs 449 GB for the same roots), so v2's number is the honest
  one, but the section 7 promise of "no full descent" does not hold for a
  one-shot scan.
- v2 prunes at the opaque root, v1 lists the profile directories beneath it:
  34 of v1's 64 candidates are `target/debug`, `target/release`,
  `target-gate/debug` style children of roots that v2 reports once. 28 of
  v2's 49 candidates are roots v1 never surfaced (`node_modules`,
  `.cargo/registry`, `.gocache`, `.codex-target`).

### Safety parity

- v1 hard-vetoed nothing on either tree (`veto_reason` null on all 64 + 7
  candidates), so the "v2 never approves what v1 hard-vetoes" check is
  vacuous here; it is only covered by the synthetic harness
  (`engine_v1_reclaims_the_same_set_as_v2_at_orange`, the deep-open-file
  opaque-root tests).
- v2 is the more conservative engine on this tree: 19 of its 49 candidates
  are `Review` (certainty `likely`/`unclear`), including
  `/data/projects/frankengit/target` (47.6 GB) and
  `/data/projects/mcp_agent_mail_rust/.codex-target` (343 GB), whose
  children v1 rates `Delete` at `definite`.
- No v2 `Delete` root contains a path that v1 rated anything other than
  `Delete`.

## 2. Daemon steady state (what the criteria are actually about)

Foreground daemon per engine for 300 s, same release binary, identify-only
and `dry_run = true`; pressure injected through the test overlay so that
only the configured root is pressured:

```bash
SBH_TEST_MODE=1 \
SBH_TEST_FS_STATS='{"mounts":[{"path":"/","fs_type":"ext4","total":1000000000000,"free":400000000000},{"path":"/data","fs_type":"ext4","total":6000000000000,"free":720000000000}]}' \
sbh --config <run>/config.toml daemon --pidfile <run>/pid
```

Config: `root_paths = ["/data/projects"]`, `poll_interval_ms = 2000`,
`min_rescan_interval_secs = 20`, `max_scan_duty_cycle_pct = 100`,
`telemetry.cpu_budget_pct = 0` (no throttling, so the loop's own pacing is
what is measured), `max_depth = 6`, `parallelism = 2`, `ballast.file_count =
1` (the 4 KiB minimum). CPU is `utime + stime` from `/proc/<pid>/stat` read
at 300 s; passes are the run's own `scan_complete` events.

| Engine | CPU-s / 300 s | `cpu_budget.used_pct_1m` at end | scan_complete events | walk passes | paths per walk | candidates per walk | `decision` rows written |
|---|---:|---:|---:|---:|---:|---:|---:|
| v1 | 601.7 (270 user + 331 sys) | 200% (two cores) | 3 | 2 full + 1 cut short by shutdown | 231,053 | 5,561 | 5,875 |
| v2 | 92.8 (34 user + 59 sys) | 25% of a core | 575 | 1 (2.6 s, 44 entries, 6 opaque roots, 4 candidates) | 44 | 4 | 1,152 |

v2's other 574 `scan_complete` events are zero-duration passes, about two
per second for the whole run, each of which replays the same two index
records and dispatches them again:

```
[SBH-SCANNER] index replay path=/data/projects/flywheel_gateway/node_modules generation=1 verdict=dispatch score=2.084 certainty=unclear
[SBH-SCANNER] index replay path=/data/projects/beads_rust/target generation=1 verdict=dispatch score=2.400 certainty=unclear
[SBH-EXECUTOR] policy engine approved 2/2 candidates (mode=enforce)
[SBH-EXECUTOR] certainty gate held back 2 candidate(s) below likely (pressure=Orange)
```

(575 occurrences of each line; 0 occurrences of the `no reclaimable
progress ... backing off rescans` message in either run.)

Mechanism, from `src/daemon/loop_main.rs` at 965c0a6:

1. At Orange the v2 walk stops early once it has seen
   `V2_PRESSURE_RECLAIM_BYTES_PER_CANDIDATE x max_delete_batch` of candidate
   bytes (`v2_pressure_candidate_byte_target`). Here that was 5.7 GB after
   44 entries, so the walk never reached the 30 `Delete`-grade roots the
   one-shot v2 scan finds in the same tree.
2. The walk scored `/data/projects/beads_rust/target` as
   `opaque-cargo-target` at `definite` certainty (the executor's dry run
   reported `would_delete=1 ... 5032071168B` on the first pass), but the
   index replay re-classified the same path from the root directory's own
   entries, found none of the markers that live under `debug/`, and scored
   it `unclear`. Every replay was therefore held back by the Orange gate,
   and the scanner thread never learned that.
3. The empty-pass cooldown keys on `dispatched_this_pass == 0`. A replay
   pass dispatches the two records again, so it counts as productive,
   `consecutive_empty_passes` resets, and the next pressure tick rescans
   immediately. The index cooldown (`candidate_in_cooldown`) only arms on
   replay *drops*, not on held-back dispatches.

This is the production failure shape recorded in the reality check (daemon
at its CPU quota, thousands of attempts, nothing reclaimed): with the unit's
`CPUQuota=10%` and `cpu_budget_pct = 25` the loop is throttled rather than
fixed. Filed as bd-8aeq from this capture and fixed the same evening (the
commit carrying that id): the index replay re-classifies opaque records
the way the walk did and scores them with the subtree probe, and the
scanner applies the cell's certainty gate itself, so held-back candidates
are neither dispatched nor counted toward the byte target and the
empty-pass cooldown arms. The capture above predates that fix and has not
been repeated yet.

v1 has no such loop because a pass costs 25 s of wall time and the executor
does reach `would_delete` batches (263 dry-run batches of 4-10 candidates),
but it spends two cores for the whole five minutes doing it.

### After the fix (same capture, same table, dry-run)

| Binary | CPU-s / 300 s | `used_pct_1m` at end | scan_complete events | what the passes did |
|---|---:|---:|---:|---|
| cb7e4d5 (first pass of bd-8aeq) | 322.7 (58 user + 265 sys) | 25% | 127 | 1 walk, then 126 replay passes that each re-probed the 5 GB target subtree and re-dispatched it; dry-run dispatches counted as progress, so the cooldown never armed |
| 8d5f1ea (second pass) | **8.6** (3 user + 6 sys) | 1.4% | 4 | 1 walk (2.2 s, 44 entries, 2 dispatchable candidates), then replays at +20 s, +60 s, +140 s: each replays 7 records in 0 ms, dispatches the definite target, and is paced as an empty pass because the dry-run executor reclaimed nothing (`the last pass dispatched candidates but nothing was reclaimed ... pacing it as an empty pass`, 4 occurrences) |

Against v1's 601.7 CPU-s on the same tree and table, the fixed v2 daemon
spends 70x less CPU over the five minutes, but that is the pacing (four
passes against three) more than the per-pass cost: v2's one real walk
stopped after 44 entries on the pressure byte target, so a forced full
pass has still not been compared engine to engine.

## 3. Verdict against section 7

| Criterion | Result |
|---|---|
| Steady state < 1% of one core (Green, no FS activity) | Not measured (both runs were at Orange by construction). |
| No full descent; >= 50x CPU-s per pass vs v1 on a large tree | **Not demonstrated.** A full v2 walk of the same tree costs 3.4x v1 (section 1). The daemon's v2 pass was 2.6 s against v1's 25 s only because it walked 44 entries instead of 231,053 (early stop), which is different work, not a cheaper pass. |
| Zero `canonicalize` per entry | Not measured here (covered by unit counters). |
| Active-reference check O(open refs + indexed candidates) | Not measured here. |
| Deletion-failure retry bounded by backoff | **Violated before bd-8aeq:** the same two held-back candidates were re-dispatched 575 times in five minutes. After 8d5f1ea the same capture shows 4 passes in five minutes with the empty-pass backoff (20, 40, 80 s) doing the pacing. |
| v2 never approves what v1 hard-vetoes | Vacuous on this tree (v1 vetoed nothing); v2 was strictly more conservative. |
| Docs match code | README and design doc updated with this document on 2026-09-02. |

bd-xtpv.8 therefore stays open. The replay hot loop is fixed and the
re-run above shows the daemon pacing itself; what is still missing for the
promotion criteria is a CPU-per-pass comparison on a forced full pass
(`force_full_scan`, or `SIGUSR1`) so both engines walk the whole tree, and
a Green steady-state measurement.

## 4. Follow-ups noticed

- `stats` cannot report scanner CPU-seconds per day: `scan_complete` carries
  `duration_ms` (wall) only; `process_cpu_micros` exists only in the
  one-shot `scan --json` path.
- The 343 GB `/data/projects/mcp_agent_mail_rust/.codex-target` root is
  worth an operator look regardless of engine.
- Raw captures (JSON, stderr, `/proc` samples) are in the session
  scratchpad under `ab-local/`, `ab-remote/` and `ab-daemon/`; they were not
  committed.
