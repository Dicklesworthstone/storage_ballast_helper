# Design: Event-Driven, Pressure-Gated Scanner (v2)

**Status:** Implemented and the default engine since v0.4.32 (`scanner.engine`
defaults to `"v2"`; `"v1"` is the opt-out rollback). The A/B evidence
measured on 2026-09-02 (section 7) does not yet meet the promotion
criteria · **Author:**
fleet-maintenance investigation, 2026-05-25
**Supersedes the steady-state behavior of:** `src/scanner/walker.rs`, the open-file
path in `OpenPathCache`, and the periodic full-walk model.

---

## 1. Problem: the current scanner pins cores at steady state

Observed on the live fleet (2026-05-25): the `sbh` daemon averaged **78–185% CPU over
multi-day lifetimes** (css: 3d 17h CPU in 2 days; 411% instantaneous across 4
`sbh-scanner` threads). The `tick` self-throttle in `daemon/loop_main.rs`
(`TICK_THROTTLE_*`) governs the **monitor** cadence but **not** scanner work already
dispatched to the walker. Generated systemd/launchd units intend background behavior
(`Nice=19`, idle I/O, lower CPU quota), but the live fleet had an interim
`CPUQuota=100%` override. The design needs an in-process budget even when service-level
limits are relaxed or wrong.

Live `thread apply all bt` on a runaway daemon showed all hot threads in
`__readlink → realpath_stk → __GI___realpath`, `getdents64`, and `statx`, walking
`…/cargo_home_*/registry/src/index.crates.io-…/<crate>/src/…`. The I/O sample showed
**0 read bytes / 0 read syscalls** in the window — i.e. CPU-bound on **cached** dentry
metadata + path canonicalization, not real disk I/O. Wasted work.

### Root defects (file:line)

1. **Descends into opaque package caches.** `process_directory` (`walker.rs:311`)
   recurses every subdir to `max_depth` (default 10) with no pre-descent artifact
   pruning. `.git` / `Cargo.toml` are only recorded as `StructuralSignals`
   (`walker.rs:411-423`); the walker still descends into
   `registry/src/<crate>/…`. With many `cargo_home_*` mirrors present, every pass
   re-enumerates **millions of tiny files**.
2. **`realpath()` on the hot path.** `core::paths::resolve_absolute_path`
   (`core/paths.rs:13`) calls `std::fs::canonicalize` and is invoked across the
   open-file / normalization helpers (`walker.rs:784,818,949,1005,1019,1057,1192`).
   canonicalize is O(path-depth) `readlink` syscalls per call → the realpath storm.
3. **Active-reference checks are still path-heavy and partly duplicated.**
   `walker.rs:656-701` can collect open `(dev, ino)` values from `/proc/*/fd`, but
   the daemon/executor still rebuild path-ancestor state (`walker.rs:858-873`,
   `deletion.rs:211-218`), and the legacy `OpenPathCache::is_path_open_unix`
   helper (`walker.rs:1226`) can recursively descend **up to `MAX_SCAN = 20_000`
   entries per candidate**. The scanner should not carry both models.
4. **Per-file `lstat` for size** (`walker.rs:466`) over those same giant caches.
5. **Hot retry on undeletable items.** css logged **400 failed deletions/hour, 11
   successes**. Current code has a batch circuit breaker and dampens successful
   delete/recreate loops, but it does not durably back off specific paths that fail
   source/protection/open/permission/identity checks.
6. **The Merkle index is not the daemon scanner.** `scanner/merkle.rs` implements a
   persistent index, but current daemon/CLI scan dispatch does not wire it into
   candidate ranking or deletion decisions. The README currently reads more
   strongly than the live code here; v2 must explicitly integrate an index instead
   of assuming this module is active.

Net: a daemon meant to be near-idle runs the equivalent of `find / -exec realpath`
across the worst-possible directory shapes, every few seconds.

---

## 2. Principle inversion

> **Stop polling the world. React to change and to pressure.**
> At green pressure with no filesystem activity, the scanner must be ~0% CPU.

Cost model shift: from **O(files on disk) per pass** → **O(filesystem changes since
last pass)**, with effort gated by disk-pressure level.

---

## 3. Architecture

### 3.1 Event-driven discovery
- Mark configured roots with **`fanotify`** (`FAN_MARK_FILESYSTEM` + FID/`FAN_REPORT_FID`)
  where permitted. If falling back to `inotify`, use watch-budgeted recursive watches
  only for selected roots/subtrees; plain root watches do not observe deep changes. When
  recursive watches exceed budget, mark the root dirty and rely on bounded
  reconciliation. macOS should use FSEvents through the platform layer when a safe
  backend exists; until then it must use reconciliation.
- Maintain a **persistent candidate index** (§3.5). Events mark subtrees dirty; only
  dirty subtrees are re-evaluated.
- Treat event overflow, watch-budget exhaustion, permission loss, and backend restart as
  dirty-root signals that force bounded reconciliation. Events only invalidate cache
  state; they never authorize deletion.
- This crate forbids unsafe code. If fanotify/FSEvents requires lower-level platform
  APIs, use a safe dependency with an audited public API; if none is available, defer
  that backend and keep bounded reconciliation. Do not introduce local unsafe code.

Implementation status for `bd-xtpv.6`: Linux now has a safe recursive `inotify`
event-source abstraction with watch-budget planning, overflow/backend-loss dirty-root
invalidation, and reconciliation fallback. `fanotify` remains an explicit capability
probe marked unavailable until a safe backend is wired. macOS and other platforms remain
reconciliation-only.

Decision (bd-rc-master-ajg1.8.5, 2026-09-02): `fanotify` stays deferred. The safe
wrapper this crate could use does not expose `FAN_REPORT_FID`, filesystem-wide marks
need `CAP_SYS_ADMIN` (absent in the user-scope unit), and the recursive `inotify`
plan with the watch budget covers the cases that matter as long as a root that
exhausts the budget is treated as dirty and reconciled, which it is. macOS is
reconciliation-only by decision, with `pressure.maintenance_interval_secs` and the
pressure-driven passes as the staleness bound; an FSEvents backend via a safe crate
is worth doing only once the macOS CI lane can prove it, so it is not started from a
Linux host. The capability report (`scanner_events:` at startup, `sbh scan --json`)
carries the probe reasons, and `capability_report_is_honest_about_the_platform`
pins them.

Watch budget allocation (bd-rc-master-ajg1.8.4, 2026-09-02): the planner enumerates
directories breadth-first up to four times the budget, always watches every root and
depth-1 directory, and spends the remainder in decreasing observed event rate (a
per-directory EWMA, time constant 10 min, with a directory-mtime prior for never-watched
subtrees). Unwatched directories directly below a watched one are the frontier: each is
its own dirty scan path (a root with more than 256 of them is reconciled whole), and the
rest of the time they rely on the maintenance pass. An incomplete plan is re-allocated
every 15 min once events have been observed; the replacement inotify instance starts
before the old one is dropped. `Q_OVERFLOW` reconciles everything once, then a backoff
window (30 s, doubling per consecutive overflow, capped at 30 min) coalesces further
overflows into a single deferred reconciliation. `allocation_respects_budget_and_mandatory_set`
(proptest) pins the budget/mandatory/coverage invariants,
`overflow_backoff_reconciles_first_then_coalesces_and_doubles` and
`event_source_overflow_bumps_generation_then_backs_off` pin the backoff, and
`linux_replan_moves_watches_to_the_hot_frontier` drives a live replan.

Event-scoped passes (bd-rc-master-ajg1.8.8, 2026-09-03): a path event used to dirty
the configured root, so the next Green pass walked the whole root, and at Green the
main loop only requests maintenance walks, so events waited for the next one. Now
`EventInvalidation::resolve_scan_roots` maps each dirty path to the depth-1 project
directory containing it (the root when the change is at the root, when that directory
classifies as an opaque artifact tree, since the walker evaluates a scan path's
children and never the path itself, or when more than 64 projects are dirty in one
drain; nested scan paths collapse into their ancestor), and the scanner thread polls
the event source every 2 s while idle, issuing its own Green/Yellow request from the
last main-loop request's roots and level. Such a pass is `reason=event` in
`scan_complete` and is paced by the base `min_rescan_interval_secs`, not the
empty-pass exponential backoff. `path_events_resolve_to_project_scan_paths_without_generation_bump`
pins the resolution rules; the daemon e2e `green_event_scopes_the_pass_to_the_changed_project`
shows a file written under a small project producing an event pass that walks a
fraction of the directories the forced full pass walked.

### 3.2 Pressure-gated effort
- Drive everything off the existing cheap `statfs` pressure poll. Effort ladder:
  - **green:** event subscription only + one shallow top-level reconciliation every
    few minutes. No deep work.
  - **yellow:** evaluate dirty candidates from the index; refresh estimates.
  - **orange/red:** rank from the index and feed the deletion executor. Avoid cold full
    walks under pressure; if the index is missing or invalid, run only bounded bootstrap
    work and prefer ballast release / known opaque roots first.

### 3.3 Opaque-tree pruning (name match during `readdir`, no stat)
- A prune-set classifies a directory before descent:
  - `CandidateOpaque`: score as one cleanup unit and never descend.
  - `ProtectedOpaque`: never descend and never delete.
  - `SignalOnly`: record source/cache evidence but keep normal traversal behavior.
- `node_modules`, Cargo registry/cache roots, `target/`, and known build caches can be
  `CandidateOpaque` when path context proves they are regenerable artifact storage.
- `.git` is always `ProtectedOpaque`, never a deletion candidate.
- `vendor`, `site-packages`, `.venv`, and language package stores require context gates:
  they are candidates only under known temp/cache/virtualenv locations; otherwise they
  are source/dependency evidence, not wholesale cleanup targets.
- Reuse / extend the existing classifier in `scanner/patterns.rs` (it already knows
  `node_modules`, build-artifact basenames). Add a prune disposition distinct from
  `Signal`.
- Rationale: a `target/` or cargo registry is a thing to **evaluate as one cleanup
  unit**, not a tree to enumerate for ranking. This removes >99% of the syscalls on
  agent machines while preserving final policy/preflight checks.

### 3.4 Inode identity instead of `realpath`
- Remove `resolve_absolute_path`/`canonicalize` from all scanner hot paths. The helper
  can still exist for config validation and user-facing path normalization.
- Canonicalize the **roots** and the **open-file mount points once** at startup when
  necessary.
  Thereafter compare candidates by `(dev, ino)` from a single `lstat` — symlink-proof,
  one stat. `EntryMetadata` already carries `inode`/`device_id` (`walker.rs:86-87`).

### 3.5 Persistent incremental index with dir-mtime invalidation
- Persist `{path, dev, ino, kind, parent_dev, parent_ino, parent_mtime, candidate_mtime,
  candidate_ctime, size_estimate, prune_decision, score, safety_state, fail_count,
  cooldown_until, event_generation}`.
- Parent-dir mtime validates candidate discovery only: if the parent identity+mtime is
  unchanged, v2 can skip re-listing siblings to rediscover the same artifact root.
  Candidate freshness uses the candidate identity, candidate mtime/ctime, event
  generation, and bounded scheduled size refresh. Do not assume parent mtime captures
  file content changes inside an existing opaque tree.
- This subsumes `scanner/merkle.rs`’s intent (change detection) but at directory
  granularity instead of content hashing the world. Reuse `scanner/merkle.rs` only after
  proving it satisfies daemon scanner persistence, dirty-root, overflow, and migration
  requirements.

### 3.6 Open-file safety: O(1) candidate-root membership, deferred deep check
- Build active-reference evidence **once per pass** from `/proc/*/{fd,maps}` and
  platform mmap/reference APIs where available. The fd half exists today; mmap support
  is platform/PAL work, not a free property of `walker.rs:858`.
- Convert active references into an `active_candidate_ids` set by matching each open
  reference against the current-cycle candidate root table once; the persistent index
  later makes that table durable. This can use bounded path-prefix evidence as an input,
  but it must not recurse through every candidate tree.
- A candidate is "busy" iff its root identity, an indexed descendant identity, or its
  candidate-root identity in `active_candidate_ids` is active.
- Move the strong guarantee to **delete time**: re-stat the root, require identity
  equality, use safe no-follow / descriptor-relative traversal where available, and
  skip if identity or active-reference state cannot be verified. **Drop the 20k-entry
  per-candidate pre-walk.**
- Do not rely on Unix delete calls returning `EBUSY` for open files; unlinking open
  files can succeed. The active-reference index and final identity checks are the
  safety mechanism.

### 3.7 Size estimation; measure only the shortlist
- Bounded/sampled size estimate for scoring (keep `content_size_bytes` lower-bound
  idea from `EntryMetadata`, but do not `lstat` every file in pruned trees).
- Compute exact bytes only for the **top-N** candidates about to be deleted, or record
  exact freed bytes from filesystem deltas/post-delete audit. Estimates are ranking
  evidence, not final accounting.

### 3.8 Real CPU/IO budget + failure backoff
- Single worker at green; small bounded pool only under pressure. Threads at
  `nice 19` + `ionice idle`. (Interim systemd `CPUQuota=100%` is in place fleet-wide
  as of 2026-05-25 — add in-process budget and then reconcile the service docs/unit
  story.)
- Token-bucket CPU budget with cooperative yield and a **resumable cursor**
  (pause/resume; never restart the pass).
- Failed deletions enter exponential-backoff cooldown (`cooldown_until`) — directly
  kills the 400/hr loop.

Implementation status for `bd-xtpv.7`: v2 now skips Green/Yellow recursive work when
there are no dirty event roots, limits dirty-root refreshes to one walker worker, caps
Orange/Red/Critical v2 walker pools to small fixed sizes, ranks persisted index
candidates before any walk under Orange+ pressure, and stops scanning after enough
safe candidate bytes are found for the current deletion batch. It uses the existing
wall-clock/entry scan budget and incremental scan cursor as the in-process budget
mechanism. Executor safety/preflight failures now feed durable candidate-index
backoff, preserving cooldowns for unchanged evidence and retrying only after the
cooldown expires.

---

## 4. Invariants preserved (must not regress)
- `.sbh-protect` subtree markers (`scanner/protection.rs`).
- Hardcoded source-tree refusal + artifact carve-out (`scanner/deletion.rs:368-377`,
  `is_hardcoded_source_tree`).
- Open-file protection, `.git` veto, non-writable-parent veto, `min_file_age`.
- Cross-device guard; never follow symlinks for deletion.
- `.git`, recognized source roots, and context-ambiguous dependency directories are not
  opaque cleanup candidates.
- All destructive actions still go through `DeletionExecutor`, policy mode checks, and
  dual logging/explain evidence.

## 5. Rollout
- Behind typed `scanner.engine = "v1" | "v2"` config (default `v1` during validation;
  promoted to `v2` by default in v0.4.32, with `v1` kept as the rollback), with
  env override and config validation.
- Add v2 shadow mode before enforce-mode deletion.
- Validate on one box (e.g. css — heaviest cargo-cache load) against v1 for a week:
  compare CPU-seconds/day, entries visited, dirs pruned, canonicalize/readlink count,
  active-reference scan time, bytes reclaimed, deletion failure rate, and
  pressure-response latency.
- Reconcile README/service documentation so it does not overstate unused Merkle behavior
  or stale CPU quota behavior.
- Promote to default only after A/B safety parity, then remove the v1 implementation in
  the same cleanup track once rollback artifacts are no longer needed.

Implementation status for `bd-xtpv.8`: the in-repo validation harness now exercises
the core scanner-v2 risk: a synthetic Cargo target tree is walked by both v1 and
v2, and v2 must emit the target as one opaque candidate without descending into its
children while reducing deterministic walker effort by at least 50x. A Linux-only
fixture keeps a file open deep inside that opaque target tree and asserts the
open-descendant evidence hard-vetoes the opaque root. `sbh scan --json` also now
emits `scanner_engine`, `scanner_dispatch`, `opaque_pruning`, `opaque_pruned_dirs`,
`scanned_entries`, and nullable `process_cpu_micros`, so manual v1/v2 scan
artifacts can record the selected engine, pruning behavior, and process CPU
delta without parsing human output. Daemon `scan_complete` activity events now
carry the selected dispatch, pruning state, dirty event-root count, index
generation, index-record count, candidate bytes seen, and timeout state in
`details`, including priority-prescan timeout completions that previously only
reached stderr/report counters. The synthetic validation tests also emit
machine-readable JSON artifacts for the v1/v2 walk-effort and safety-parity case,
event-overflow reconciliation fallback, and memory-pressure transition latency
budget. This is necessary but not yet the full promotion bar above: live fleet
A/B CPU-seconds/day, deletion parity, and pressure-response measurements still
need to be recorded before changing the default engine.

## 6. Bead plan

Epic: `bd-xtpv` — Redesign scanner as event-driven, pressure-gated cleanup engine.

Dependency intent:

```text
bd-xtpv.1  scaffold + config flag
├── bd-xtpv.2  opaque pruning and safe prune taxonomy
├── bd-xtpv.3  remove canonicalize/realpath from scanner hot paths
└── bd-xtpv.4  O(1) active-candidate checks by identity/reference evidence

bd-xtpv.5 depends on .2, .3, and .4
├── bd-xtpv.6  event source and dirty-root invalidation
└── bd-xtpv.7  pressure ladder, budgets, and failed-delete backoff

bd-xtpv.8 depends on .6 and .7
```

Only `bd-xtpv.1` should be ready initially, excluding the parent epic itself. The
persistent index must depend on pruning because the index schema stores prune decisions
and should persist one artifact-root candidate rather than millions of child entries.

## 7. Acceptance criteria
- Steady-state (green, no FS activity): daemon < **1% of one core** averaged over 10 min.
- Under a synthetic cargo-cache tree (1M files): no full descent; CPU-seconds per pass
  drops ≥ 50× vs v1.
- Zero `realpath`/`canonicalize` calls per entry on the hot path (assert via counter).
- Active-reference checking marks busy candidate roots in O(open references + indexed
  candidates), not O(candidate subtree size), and fails closed if reference-to-candidate
  mapping is incomplete.
- Deletion-failure retry rate bounded by backoff (no item retried more than
  `O(log)` times/hour).
- All existing protection/safety tests pass unchanged.
- Event overflow/permission-loss tests force bounded reconciliation instead of trusting
  stale index state.
- Pruning tests prove `.git`, source roots, `vendor`, and `site-packages` are not blanket
  deletion candidates.
- Symlink race tests cannot redirect deletion outside the approved identity.
- README/design docs accurately distinguish current v1 behavior, unused Merkle code, and
  v2 rollout behavior.

Current validation note (2026-05-26): repository tests cover the synthetic
large-tree no-descent case, Linux deep-open-file veto for opaque roots, and
`sbh scan --json` plus daemon `scan_complete` v2 engine/pruning/index/event
metrics. Focused JSON validation artifacts are produced by
`scanner_v2_validation_artifact_is_machine_readable`,
`event_overflow_validation_artifact_records_reconciliation_fallback`, and
`pressure_latency_validation_artifact_is_machine_readable`. Since v0.4.32 the
default is `scanner.engine = "v2"` (see the `ScannerConfig` default in
`src/core/config.rs`); the live A/B artifacts are recorded below, and
`"v1"` remains the rollback.

### Measured (2026-09-02)

Full evidence: `docs/internal/scanner-ab-2026-09-02.md` (release build of
965c0a6 on the operator workstation; self-measured, not independently
re-run).

- One-shot `sbh scan /data/projects --top 200` (2.1 TB project tree): v1
  13.1 CPU-s, 15,019 entries, 64 candidates; v2 44.4 CPU-s, 11,977 entries,
  53 opaque roots pruned, 49 candidates. v2 costs 3.4x v1 because it
  measures every pruned opaque root with the allocated-size probe (449 GB
  measured vs v1's 4 GB shallow estimate). On the small `/data/tmp` tree
  the engines are equivalent (same 7 candidates, CPU within noise).
- Safety: v1 hard-vetoed nothing on either tree, so the "never approves
  what v1 vetoes" check is vacuous outside the synthetic harness; v2 was
  strictly more conservative (19 `Review` roots whose children v1 rates
  `Delete`).
- Daemon steady state at injected Orange, 300 s, identify-only: v1 601.7
  CPU-s (two cores, 2 full passes of 231,053 paths); v2 92.8 CPU-s but as a
  hot loop: 1 walk of 44 entries (the pressure byte-target early stop) then
  574 zero-duration index-replay passes, about two per second, each
  re-dispatching the same two `unclear` candidates that the certainty gate
  holds back. The empty-pass cooldown never armed because a replay pass
  counts as a dispatch, and the replay had downgraded a `definite` opaque
  target to `unclear` by re-classifying it from the root's own entries.
  Filed and fixed the same evening as bd-8aeq (cb7e4d5 + 8d5f1ea: replay
  keeps the opaque classification and the walk's persisted structural
  signals; the scanner applies the certainty gate itself; a dispatch that
  reclaims nothing is paced as an empty pass). The same capture on 8d5f1ea:
  4 passes and 8.6 CPU-s in 300 s, backoff at 20/40/80 s.
- Forced full pass, engine to engine (`sbh daemon scan-now` at injected
  Green, 8b0d4b9): v1 8.6 s / 18.9 CPU-s over 231,162 paths; v2 14.2 s /
  19.1 CPU-s over 150,062 paths with 220 opaque roots pruned and
  re-measured. Parity, not 50x: what v2 saves by not descending it spends
  on the opaque size probes. Over a 300 s Green window each engine ran one
  startup maintenance pass and nothing else (v1 13.9 CPU-s, v2 18.7).
- Verdict: the retry-backoff criterion now holds on the real tree; the
  >= 50x CPU-seconds-per-pass criterion is **not met** on a forced full
  pass, and the Green "< 1% of one core" criterion is not isolated from the
  startup pass yet. bd-xtpv.8 stays open; the operator decides whether the
  per-pass criterion still stands (the pressure-scoped early stop, not the
  per-pass cost, is what makes v2 cheap in practice) or is waived.
- One-command artifact (`sbh scan --ab /data/projects --top 200 --out`,
  2026-09-03, release build, page cache warmed by the untimed v2 pass):
  v1 3.77 CPU-s / 15,181 entries / 64 candidates; v2 12.66 CPU-s / 12,140
  entries / 53 opaque roots pruned / 49 candidates (cpu_ratio 0.30,
  entries_ratio 1.25) — consistent with the 3.4x one-shot finding above.
  The diff flagged one promotion-blocker path for the operator:
  `/data/projects/mcp_agent_mail_rust/.codex-target` (v2 candidate, v1
  hard-veto). Summarized artifact:
  `docs/internal/scanner-ab-2026-09-03.json`.

Live A/B capture procedure (one command):

`sbh scan --ab PATH` runs v1 then v2 in-process over the same roots — the page
cache is warmed by an untimed v2 pass first, so both measured passes see the
same cache state — and emits the comparison artifact (schema version 1): per
engine `scanned_entries`, `opaque_pruned_dirs`, `elapsed_seconds`,
`process_cpu_micros`, the candidate list (`path`, `score`, `action`) and the
hard-veto list (`path`, `reason`), plus the diff `only_in_v1`, `only_in_v2`,
`v2_candidates_vetoed_by_v1`, `cpu_ratio_v1_over_v2`, and
`entries_ratio_v1_over_v2`.

```bash
sbh scan --ab /data/projects --top 200                  # human summary
sbh scan --ab /data/projects --top 200 --json --out ab.json   # artifact JSON
```

Archive the artifact beside the daemon `scan_complete` activity events from
the same window; `sbh stats --json` aggregates those events into the
`scanner` block (`cpu_seconds_by_day`, `passes`, `entries_scanned`,
`opaque_pruned_dirs`) using the `process_cpu_micros=` key in the event
`details`. Promotion remains blocked unless `v2_candidates_vetoed_by_v1` is
empty, event-overflow or backend-loss windows force reconciliation instead of
stale index reuse, and the live CPU-seconds/pass reduction supports the >= 50x
target.
