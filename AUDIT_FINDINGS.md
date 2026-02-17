# SBH Codebase Audit — Consolidated Findings

Rescued from session `5e0cd37c` (CopperFern) where 11 audit subagents hit context limits.
Two waves: Wave 1 (5 exploration agents) + Wave 2 (6 deep audit agents), plus parent findings.
All findings verified against current source by extraction agents.

**Date:** 2026-02-15
**Total unique findings:** ~72 (4 CRITICAL, ~39 IMPORTANT, ~29 MINOR)
**Already fixed by parent (5):** JSONL rotation, DFS doc, dry-run logging, NaN guard, Instant panic

---

## CRITICAL (4)

### C1. Launchd plist updater replaces ALL `<string>` elements
- **File:** `src/cli/bootstrap.rs:1085-1105`
- **Source:** ac50306 (CLI installer audit)
- The plist binary path updater finds and replaces `<string>` elements globally, not scoped to the `ProgramArguments` array. Overwrites unrelated string values in the plist (e.g., Label, WorkingDirectory).

### C2. Ballast fallocate skips `sync_all()` — header not durable
- **File:** `src/ballast/manager.rs:394-404`
- **Source:** a029101 (ballast audit), verified by wave1 agent
- On the fallocate path (ext4/xfs), the header is written and then fallocate extends the file, but `sync_all()` is never called. A crash during or after fallocate can leave a file with an unwritten header. The non-fallocate (random data) path does call `sync_all()`.

### C3. Ballast fallocate uses total file size instead of remaining length
- **File:** `src/ballast/manager.rs:447-458`
- **Source:** a029101 (ballast audit)
- `fallocate()` is called with the full `file_size_bytes` as the length, but the offset should account for the already-written `HEADER_SIZE` bytes. This over-allocates by 4096 bytes per file.

### C4. `ballast status` panics on usize underflow
- **File:** `src/cli_app.rs:2422,2473`
- **Source:** a677f87 (CLI audit)
- If the actual inventory count exceeds the configured `file_count` (possible after config change), subtraction underflows `usize`, causing a panic.

---

## IMPORTANT — Daemon & Core (13)

### I1. EWMA receives `free_bytes` but PID receives `available_bytes`
- **File:** `src/daemon/loop_main.rs:455,467-469`
- **Source:** Parent agent + ab3dde7
- EWMA rate estimator gets `stats.free_bytes` (includes root-reserved blocks), PID controller gets `stats.available_bytes` (user-available only). On ext4 with 5% reserved, these differ by several GB. The EWMA's `predicted_seconds_to_red` is calibrated against one metric but fed to a PID calibrated against another.

### I2. `PressureLevel::Unknown` sorts higher than `Critical`
- **File:** `src/logger/stats.rs:103-111`
- **Source:** a42a700 + parent
- Derived `Ord` on enum makes `Unknown` the highest severity. Any parse failure produces `Unknown`, corrupting `worst_level_reached` stats.

### I3. Config reload (SIGHUP) is mostly broken
- **File:** `src/daemon/loop_main.rs:682-718`
- **Source:** ab3dde7
- SIGHUP re-reads the config file but doesn't propagate changes to: PID controller thresholds, EWMA estimator parameters, FS collector paths, ballast manager config, or scanner scoring weights. Only the config struct is updated; all consumers keep the original values.

### I4. Scanner thread scoring config not updated on reload
- **File:** `src/daemon/loop_main.rs:722-745`
- **Source:** ab3dde7
- Scanner thread was spawned with initial config; channel-based design means new config can't reach it without a restart.

### I5. SQLite permanently disabled after 3 failures — no recovery
- **File:** `src/logger/dual.rs:252-261`
- **Source:** ae02f4a (daemon+logger audit)
- After 3 consecutive SQLite write failures, `sqlite = None` with no recovery path. Transient disk pressure (ironic for this tool) permanently kills structured logging.

### I6. Logger shutdown uses blocking `send()` on bounded channel
- **File:** `src/logger/dual.rs:131`
- **Source:** ae02f4a
- `ActivityLoggerHandle::shutdown()` uses blocking `self.tx.send()`. If the 1024-slot channel is full, shutdown hangs indefinitely.

### I7. Webhook JSON template has no value escaping
- **File:** `src/daemon/notifications.rs:514-518`
- **Source:** ae02f4a
- Template uses `replace("${SUMMARY}", &summary)` without JSON-escaping. Mount paths or messages containing `"` produce malformed JSON payloads.

### I8. Only first `root_path` gets pressure monitoring
- **File:** `src/daemon/loop_main.rs:438-445`
- **Source:** ab3dde7
- `check_pressure()` only monitors `config.scanner.root_paths.first()`. Multiple watched paths on different filesystems won't trigger pressure response.

### I9. PID error clamped at 0 prevents integral wind-down
- **File:** `src/monitor/pid.rs:116-117`
- **Source:** accc4d2
- When free space exceeds target (recovery phase), error is clamped to 0 instead of going negative. The integral term can't decrease, so urgency stays elevated even after pressure resolves.

### I10. EWMA residual computed against already-updated rate
- **File:** `src/monitor/ewma.rs:97-103`
- **Source:** accc4d2
- The residual (prediction error) is computed as `|inst_rate - self.ewma_rate|` AFTER `self.ewma_rate` was updated. This biases confidence upward because the residual is always smaller than the true prediction error.

### I11. `project_time` discards quadratic correction for negative acceleration
- **File:** `src/monitor/ewma.rs:207-209`
- **Source:** accc4d2
- When disk consumption is decelerating (negative second derivative), the quadratic term correction is discarded, making time-to-threshold estimates overly pessimistic.

### I12. `PRAGMA journal_mode = WAL` failure silently ignored
- **File:** `src/logger/sqlite.rs:300-309`
- **Source:** a42a700
- WAL mode is set via `execute_batch`, which doesn't check if the PRAGMA succeeded. If WAL fails (e.g., read-only filesystem), SQLite falls back to DELETE journal mode with worse concurrent-read behavior.

### I13. `SQLITE_OPEN_NO_MUTEX` with public `connection()` accessor
- **File:** `src/logger/sqlite.rs:31-36`
- **Source:** a42a700
- The SQLite connection is opened with `NO_MUTEX` flag (no internal locking), but `connection()` returns a reference. If any code path accesses the connection from multiple threads, this is a data race. Currently safe because the logger thread owns the connection, but the public API is a footgun.

---

## IMPORTANT — Ballast (5)

### I14. Replenish recreates ALL missing files at once
- **File:** `src/ballast/release.rs:143-150`
- **Source:** a029101
- `replenish()` delegates to `provision()` which creates ALL missing files in one call. The design doc says "recreate one file at a time" to avoid re-exhausting disk. Each replenish cycle can write `file_count * file_size_bytes` all at once.

### I15. Release tier documentation doesn't match implementation
- **File:** `src/ballast/release.rs:1-8,66-78`
- **Source:** a029101, wave1 ballast agent
- Doc says tiers are 0.0-0.3/0.3-0.6/0.6-0.9/0.9-1.0 with actions 1/3/half/all. Code implements shifted tiers and no "half" tier. Implementation is internally consistent but doc is wrong.

### I16. `BallastFile.released` field is dead code
- **File:** `src/ballast/manager.rs:71,140,147,221,321`
- **Source:** wave1 ballast agent
- The `released` field is always `false`. Release works by deleting files and rescanning — the flag is never set. Multiple `filter(|f| !f.released)` calls are no-ops.

### I17. Unsigned underflow when `file_size_bytes < HEADER_SIZE`
- **File:** `src/ballast/manager.rs:398`
- **Source:** a029101
- `file_size_bytes - HEADER_SIZE` underflows if config allows files smaller than 4096 bytes.

### I18. `expected_count()` returns actual count, not configured count
- **File:** `src/ballast/coordinator.rs:68-71`
- **Source:** a029101
- Method named `expected_count` returns the inventory length (actual on-disk files), not the configured `file_count`. Misleading API.

---

## IMPORTANT — Scanner (5)

### I19. TOCTOU in `is_path_open_linux` — path-based comparison
- **File:** `src/scanner/deletion.rs:347-381`
- **Source:** wave1 scanner agent
- Uses path canonicalization + string comparison against `/proc/*/fd` targets. Should use inode+device comparison for correctness.

### I20. Config glob patterns don't protect subtrees
- **File:** `src/scanner/protection.rs:259-264`
- **Source:** wave1 scanner agent
- Marker files protect entire subtrees via ancestor walking, but config glob patterns are exact-match only. A pattern `/data/production-*` protects the directory but not its children.

### I21. Merkle `update_entries` depth inconsistency
- **File:** `src/scanner/merkle.rs:440`
- **Source:** wave1 scanner agent
- Full build uses walker's relative depth; incremental update recalculates from absolute path components. Depths are inconsistent after incremental updates.

### I22. No validation/normalization of user-provided scoring weights
- **File:** `src/scanner/scoring.rs:102-116`
- **Source:** accc4d2
- Individual weights can be negative. The sum-to-1.0 check passes with e.g., weights {2.0, -1.0, 0.0, 0.0, 0.0}, producing inverted scoring behavior.

### I23. Merkle `diff()` mutates health but not snapshots
- **File:** `src/scanner/merkle.rs:286-368`
- **Source:** accc4d2
- Creates partial mutation — health data is updated but snapshot references aren't, leading to inconsistent state for callers.

---

## IMPORTANT — CLI (7)

### I24. `run_check` ignores user config entirely
- **File:** `src/cli_app.rs:3612-3694`
- **Source:** a677f87
- Uses `Config::default()` instead of loading the user's config file. `sbh check && cargo build` won't use the configured thresholds.

### I25. `tune --apply` auto-executes without confirmation
- **File:** `src/cli_app.rs:1996-2013`
- **Source:** a677f87
- In JSON/non-TTY mode, `--apply` writes config changes without user confirmation.

### I26. `run_status` reports stale daemon as "running"
- **File:** `src/cli_app.rs:2681-2685`
- **Source:** a677f87
- Reads state.json but doesn't check file modification time. A crashed daemon's last state.json will show "running" forever.

### I27. Interactive clean skips open-file re-check
- **File:** `src/cli_app.rs:3485-3497`
- **Source:** a677f87
- After user confirms deletion, the open-file check is not re-performed. A process could open the file between scan and deletion.

### I28. Launchd plist — all `<string>` elements affected
- **File:** `src/cli/bootstrap.rs:1085-1105`
- **Source:** ac50306
- (Same as C1, listed here for completeness in the CLI section)

### I29. `git clone` fails when destination exists
- **File:** `src/cli/from_source.rs:367-406`
- **Source:** ac50306
- `from_source` install attempts `git clone` into a directory that may already exist from a prior install attempt.

### I30. Heuristic JSON injection via `rfind('}')`
- **File:** `src/cli/integrations.rs:521-550`
- **Source:** ac50306
- Shell integration uses `rfind('}')` to find insertion point in JSON config files. A JSON value containing `}` causes insertion at the wrong position.

---

## IMPORTANT — Config & Stats (5)

### I31. Negative pressure thresholds accepted
- **File:** `src/core/config.rs:520-529`
- **Source:** a42a700
- No range check on threshold values. Negative or >100% values pass validation.

### I32. Negative scoring weights accepted
- **File:** `src/core/config.rs:573-582`
- **Source:** a42a700
- Sum-to-1 check doesn't reject negative individual weights.

### I33. `BallastReplenished`/`Provisioned`/`Emergency` events not written to SQLite
- **File:** `src/logger/dual.rs:537-538`
- **Source:** a42a700
- These events are logged to JSONL but not inserted into SQLite tables. Stats queries for these events always return 0.

### I34. `u64 as i64` wraps values > `i64::MAX` to negative in SQLite
- **File:** `src/logger/dual.rs:447,452,488,513`
- **Source:** a42a700
- Large byte counts (>8 EiB) wrap to negative when cast to `i64` for SQLite storage.

### I35. `min_score`/`calibration_floor` cross-validation missing
- **File:** `src/core/config.rs:570-571`
- **Source:** wave1 core agent
- Each validated independently in [0,1] but no check that `min_score <= calibration_floor`. Env var overrides can create contradictory state.

---

## IMPORTANT — Monitor (3)

### I36. `recommended_free_target_pct` broken for high free_pct
- **File:** `src/monitor/predictive.rs:266-270`
- **Source:** wave1 monitor agent
- `lerp(current_free_pct.max(15.0), current_free_pct.max(25.0), progress)` — when free_pct is already 80%, both max() calls return 80%, making the lerp useless. The `.max()` calls should be `.min()` or the constants should be applied differently.

### I37. `PredictiveConfig.min_samples` is dead config
- **File:** `src/monitor/predictive.rs:39,185-221`
- **Source:** wave1 monitor agent + accc4d2
- The field is stored but never read by `evaluate()`. EWMA's own `min_samples` provides indirect gating, but this separate config field misleads operators.

### I38. PID urgency boost thresholds hardcoded
- **File:** `src/monitor/pid.rs:127-135`
- **Source:** wave1 monitor agent
- 60s/300s/900s thresholds are hardcoded while `action_horizon_minutes` is configurable. Changing the horizon doesn't affect the PID's escalation curve.

---

## MINOR (29)

| # | File | Description |
|---|------|-------------|
| M1 | manager.rs:231 | `bytes_freed` uses config size, not actual file size |
| M2 | manager.rs:193 | `total_bytes` uses config size, not actual allocated |
| M3 | coordinator.rs:144-176 | Non-UTF-8 mount path silently falls through to defaults |
| M4 | release.rs:129-134 | Redundant guard (downstream of dead `released` field) |
| M5 | manager.rs:378-413 | Partial file not cleaned up on write error |
| M6 | stats.rs:364-365 | Negative i64 wraps to huge u64 in stats aggregation |
| M7 | stats.rs:462-476 | Time from last sample to "now" not counted in level % |
| M8 | dual.rs:221 | `dropped_events` counter zeroed by logger thread |
| M9 | pal.rs:330-332 | `unescape_mount_field` only handles `\040` |
| M10 | pal.rs:303-308 | `parse_meminfo` blindly multiplies all values by 1024 |
| M11 | config.rs:349-355 | `stable_hash` uses non-stable `DefaultHasher` |
| M12 | stats.rs:242-243 | NULL `size_bytes` rows appear as 0 in top_deletions |
| M13 | config.rs:91-92 | `false_positive_loss`/`false_negative_loss` not validated |
| M14 | merkle.rs:563 | `built_at_nanos` truncated from u128 to u64 |
| M15 | protection.rs:146 | Doc now says DFS (fixed by parent) |
| M16 | walker.rs:207-208 | Marker check uses `exists()`, misses dangling symlinks |
| M17 | scoring.rs:267-274 | Vetoed items report inconsistent fallback/calibration |
| M18 | patterns.rs:355-366 | Overly broad "Contains" patterns ("cache", "tmp") |
| M19 | pid.rs:118 | Derivative kick if target_free_pct changed at runtime |
| M20 | ewma.rs:46 | Confusing sample count semantics (first update = seed) |
| M21 | self_monitor.rs:429-442 | Missing `fsync` before rename in state atomic write |
| M22 | self_monitor.rs:342-348 | u64→u32 truncation in `avg_scan_duration()` |
| M23 | policy.rs:207 | `transition_log` Vec grows unbounded |
| M24 | loop_main.rs:569-575 | Emergency logs hardcoded `free_pct: 0.0` |
| M25 | loop_main.rs:486-501 | Dead dummy `PressureReading` in log function |
| M26 | config.rs:288,302 | Silent fallback to `/tmp` when HOME unset |
| M27 | config.rs:146-154 | Mount path not normalized (trailing slash mismatch) |
| M28 | cli_app.rs:4093-4100 | `truncate_path` panics on multi-byte UTF-8 |
| M29 | cli_app.rs:4061-4078 | `format_bytes` uses binary math but decimal labels |

---

## Top Priority Fix Clusters

1. **Pressure system data inconsistency** (I1 + I9 + I10 + I11) — EWMA/PID use different metrics, integral can't wind down, residual biased, predictions pessimistic during deceleration. The entire pressure response system has systematic errors.

2. **Config reload is broken** (I3 + I4) — SIGHUP reloads the config struct but doesn't propagate to any consumer. Users must restart the daemon for config changes to take effect.

3. **Ballast file creation durability** (C2 + C3 + I17) — fallocate path has no fsync, wrong length calculation, and potential underflow. Files may be corrupt or oversized after creation.

4. **Stats engine queries nonexistent data** (I33 + I2) — Key events never written to SQLite; Unknown pressure level corrupts worst-level stats.

5. **CLI operational issues** (I24 + I26 + C4) — `sbh check` uses wrong config, status shows stale daemon as running, ballast status can panic.

---

## False Positives Confirmed by Verification

- PID hysteresis thresholds (intentional: recovery must exceed target-state threshold + buffer)
- JSONL rotation off-by-one (rotation logic is correct)
- PID integral windup (`.clamp()` correctly applied)
- Watchdog heartbeat interval (half of watchdog interval is per systemd docs)
- `parse_meminfo` HashMap key bug (Rust HashMap uses value equality)
- `Option<Option<String>>` for rollback (standard clap v4 pattern)
- `free_bytes` field "unused" (used extensively across codebase)

## Resolution Update (2026-02-16)

- **I3 (Config reload):** Fixed. Added `DiskRateEstimator::update_params` and `MountMonitor::update_config` to ensure EWMA parameters are propagated during SIGHUP reload.
- **Verification:** All other Critical (C1-C4) and Priority Fix Cluster issues were verified as already fixed in the current codebase.
