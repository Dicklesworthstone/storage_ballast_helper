# Changelog

All notable changes to `storage_ballast_helper` (`sbh`) are documented here.

Versions with published GitHub Release assets are marked **[release]**. Versions without that marker were tagged or referenced in commit messages but not published as GitHub Releases. `scripts/changelog_check.sh --all` audits the markers against GitHub, and the Release workflow refuses to publish a tag that has no marked heading here. Commit links point to the canonical repository at `https://github.com/Dicklesworthstone/storage_ballast_helper`.

---

## Unreleased

Compare: [`v0.5.1...HEAD`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.5.1...HEAD)

### Added — incident replay: `sbh dashboard --replay <activity.jsonl>` (bd-rc-master-ajg1.4.13)

- The cockpit can be driven from a captured activity log instead of a daemon: every screen shows the log's events up to a moving cursor, the Overview shows a state reconstructed from them (counters, per-mount pressure, ballast counts, last scan), and the header carries `REPLAY <file> t=<ts> i/n <speed>`. `--speed 1x|10x|max` sets how fast log time runs, `--from <RFC 3339>` starts later; `Space` pauses/resumes, `,`/`.` step one event, `Home`/`End` seek (the keys the bead named, `[`/`]`, stay screen navigation). Lines that do not parse are skipped and counted; ballast actions are refused with a hint. No daemon, socket, or database is touched.

### Added — Diagnostics thread health and a live VOI overlay (bd-rc-master-ajg1.4.11)

- The Diagnostics screen's Runtime pane lists the daemon's four threads from `state.json` (`running`/`stalled`/`dead` with the heartbeat age), or says the daemon did not report thread health.
- `state.json` carries a `voi` block (enabled, budget and its use by the last plan, exploration split, fallback state, calibration windows and recent MAPE, paths tracked, when the last maintenance plan was made and its top paths). The VOI overlay (`v`) renders it instead of the literal "5 paths/cycle, 80/20" it used to print, flags a stale state file, and explains when a daemon predates the block or no state is loaded.

### Added — the dashboard's Log Search screen searches (bd-rc-master-ajg1.4.10)

- Screen 6 was a read-only mirror of the Timeline with a `<not-yet-editable>` query line. It now has one: `/` edits the query inline (Enter runs it, Esc cancels, and the editor owns every key meanwhile), `n`/`p` page through results, `c` clears, `Enter` opens the selected entry on the Timeline. The grammar is free words (every word must appear in the entry's path, event type, severity, message, error code, pressure level or details, case-insensitively) plus `type:<event>`, `level:<info|warning|critical>` (a minimum), `path:<prefix>`, `id:<decision-id>` and `since:<15m|1h|24h|7d>`; the header shows the active filters, the page, and the backend that answered.
- Data: the telemetry adapters gained `search_events`. SQLite answers with `WHERE` clauses (`LIKE` with escaped wildcards for words and the path prefix, `timestamp >=` for `since:`) and `LIMIT/OFFSET` paging; JSONL filters a bounded tail in memory; the composite prefers SQLite and falls back to JSONL, and says which one answered.

### Changed — test counts in the docs are generated (bd-rc-master-ajg1.1.5)

- `scripts/test-census.sh` counts every cargo test target with `cargo test <target> -- --list` (library with the default features and with the lean set, the binary, every integration file) plus the e2e shell cases the suite defines, and prints a Markdown table; `docs/testing-and-logging.md` embeds it between `sbh-census` markers, `--check` fails on drift, `--write` rewrites it, `--self-test` checks the counting. The hand-typed summary it replaces was stale by 35–270 % per row. The quality gate runs `--check` as the SOFT `test-census` stage.
- `scripts/quality-gate.sh --write-stages` rewrites the stage table embedded in `docs/quality-gate-runbook.md` and `docs/testing-and-logging.md` (the "N stages: H HARD, S SOFT." line included), `--check-stages` fails on drift, and the SOFT `stage-docs` stage runs that check; with `docs-drift` and `test-census` the gate has 30 stages (21 HARD, 9 SOFT).

### Added — `sbh docs`: README tables generated from the code (bd-rc-master-ajg1.12.2, first slice)

- `sbh docs` prints a versioned JSON document built from the binary's own tables: every `SBH_*` environment variable (a registry a test keeps equal to the names the code reads, each config override naming its `config.toml` key), every command and flag from clap, the dashboard's screens, keymap, palette actions and playbook, and the default configuration as TOML. `--section <name>` prints one section's Markdown.
- `sbh docs --render <file>` rewrites the regions a file marks with `<!-- sbh-docs:begin <section> -->` … `<!-- sbh-docs:end -->`; `--check <file>` exits 1 naming the drifted regions. README's environment-variable table, dashboard keybinding tables, palette list and triage playbook are such regions now; `scripts/ci_docs_update_check.sh` runs the check and the quality gate has a `docs-drift` stage.
- Contract tests: the keymap resolves every global and overlay binding in its context and no global key shadows a documented screen key; every `sbh <command>` in README's Command Reference exists in clap; README's generated regions match the build.

### Changed — the quality gate cannot pass vacuously (bd-rc-master-ajg1.1.3)

- `scripts/quality-gate.sh` counts the tests each stage executed (the sum of its `test result:` lines; the e2e suite's `summary pass=N fail=M` line) and records a test stage that exits 0 having selected no test as `vacuous`, a failure of that gate; `summary.json` carries `executed_tests` per stage and in total, and the console shows the count next to each PASS.
- The stages are one table in the script; `--print-stages [--markdown]` prints it and `docs/quality-gate-runbook.md` and `docs/testing-and-logging.md` embed the Markdown output between `sbh-qg:stages` markers. `--self-test` checks the accounting and the vacuous path against fixtures without cargo.
- The TUI and fallback stages pass `--features tui` explicitly (it is a default feature since 4.7, so the nine TUI stages and `fallback` that used to select zero tests now execute 900+ and 42). New stages: `cli-exit-codes`, `decision-e2e` (split from `decision-plane`), `explain-ledger`, `dashboard-pty`, and `daemon-e2e` (SOFT: its idle-CPU case is load-sensitive). 27 stages: 21 HARD, 6 SOFT.

### Added — dashboard ballast actions execute (bd-rc-master-ajg1.4.15)

- On the Ballast screen `Shift-X` releases every available file on the selected volume and `p` replenishes it, each behind the confirmation modal; `x` stays the global one-file quick-release. Enter performs the action: through the running daemon's control socket (scoped to the selected mount), or directly on the pool when no daemon holds it, the way `sbh ballast release`/`replenish` do; a daemon without a control socket is a refusal, not a race. The outcome (files released or recreated, bytes, a free-space floor holding files back, an already-full pool) or the daemon's refusal is the notification, and the dashboard refetches state.
- Operator-driven releases and replenishes through the control socket are now logged like the daemon's own (`ballast_release` with `pressure = "control"`, `ballast_replenish`), so they appear on the Timeline and in `sbh stats`, and the release controller is told so an operator's release is not refilled at once.
- `state.json` carries `ballast_pools`, one record per mount (mount, pool directory, filesystem, strategy, available/total files, releasable bytes, skipped and why), sorted by mount. The Ballast screen lists those instead of a single volume synthesized on whichever monitored mount came first, so a release is scoped to a mount that has a pool; quick-release lands on a volume with files to give. A state file from an older daemon still parses (the list is empty and the aggregate volume is synthesized as before).
- `tests/dashboard_pty.rs` drives the shipped binary under a pseudo-terminal against a sandbox daemon: screens 1–7 draw their headers, `x` then Enter releases one ballast file (the daemon's event and pool count prove it), and `q` exits cleanly.

### Changed — the cockpit ships in the default build (bd-rc-master-ajg1.4.7)

- `tui` is a default feature: `cargo install`, the release workflow, and CI all build the same feature set (`cli,daemon,sqlite,tui`), so `sbh dashboard` is the frankentui cockpit on every shipped binary. A lean build still exists with `--no-default-features --features cli,daemon,sqlite`.
- The pre-cockpit crossterm dashboard (`src/cli/dashboard.rs`) moved behind the off-by-default `legacy-crossterm-dashboard` feature; `sbh dashboard --legacy-dashboard` remains the plain live status view.
- `sbh dashboard --start-screen <overview|timeline|explainability|candidates|ballast|log_search|diagnostics|remember>` opens the cockpit on that screen for the session without touching the saved preference; an unknown name is a usage error listing the choices.
- `REDUCE_MOTION` (any value but `0`/`false`/`no`/`off`) selects reduced motion the same way `NO_COLOR` disables color; the README's preferences path is the real `~/.config/sbh/preferences.json`.
- Enter on the ballast release confirmation (quick-release `x`, or the Ballast screen's release keys) now performs the release through the daemon's control socket, scoped to the selected mount (one file, or every available file for release-all), and refetches state; the result, or the daemon's refusal, is the notification.
- Without an interactive terminal the cockpit route degrades to the live status view with one stderr line; an explicit `--new-dashboard`/`--start-screen` on a pipe is refused with a "stdout is not a TTY" error. The e2e dashboard cases run the cockpit under a PTY (`script`) and quit it with `q`.

### Added — build metadata in every build path (bd-rc-master-ajg1.5.4)

- A `build.rs` records the git sha (with `-dirty` when the tree has uncommitted changes, or the packager's `SBH_BUILD_GIT_SHA` outside a checkout), the target triple, the profile and a reproducible RFC 3339 timestamp (`SOURCE_DATE_EPOCH`, else the commit time, else the build time). `sbh version --verbose` and the `sbh_info` metrics line read them; a build with none of the sources still says `unknown` instead of failing.

### Changed — the dashboard reads the decision ledger (bd-rc-master-ajg1.3.3)

- The TUI's SQLite telemetry adapter reads `decision_log` for the Explainability screen (real decision ids, factors, veto reasons, policy mode, and the full record for the detail pane) instead of projecting `artifact_delete` rows; a database without the ledger, or with an empty one, falls back to the activity-log projection and is marked partial with the reason. Timeline `artifact_delete` rows carry the id of the decision that approved them (joined from the ledger for SQLite rows, from the line for JSONL) and `Enter` on such a row opens that decision on the Explainability screen. The `tui` feature also compiles again: its `LogEntry` fixtures had missed the `quarantined` field.

### Added — the daemon's own files against the volumes it reclaims (bd-rc-master-ajg1.7.4)

- At startup the daemon checks whether the activity database, the JSONL log and `state.json` share a mount with a scan root, a special location or a ballast pool. It logs one `logging.on_monitored_fs=... device=... paths=[...]` line, carries the result in `state.json` under `logging`, and `sbh status` warns; `sbh doctor --system` gains `logging.on_monitored_fs` (WARN, FAIL while that mount is at Orange or worse). While the mount is pressured, every JSONL line is mirrored to the RAM fallback (capped like the fallback) and the daemon says so once per level change.
- `state.json` is padded to a fixed 64 KiB; when the atomic temp-file write cannot allocate on a full volume, the file is rewritten in place, so status keeps updating exactly when the disk is full.

### Changed — one logging degradation chain (bd-rc-master-ajg1.7.2)

- The daemon's JSONL settings are now a single definition (`JsonlConfig::for_daemon`): rotation at 50 MiB keeping 5 files, fsync every 30 seconds, and the RAM-backed fallback enabled (`/dev/shm/sbh-<uid>.jsonl` on Linux, `$TMPDIR/sbh.jsonl` elsewhere), never rotated and truncated at 16 MiB. An idle timer in the logger thread fsyncs lines written before a quiet spell once the interval passes. SQLite trips after 3 consecutive write failures and is retried every 50 events, which is what the code always did; the README said 50 failures. At open, a database whose `auto_vacuum` is not FULL is converted only when it is larger than 64 MiB.

### Added — reserve sizing from observed write bursts (bd-rc-master-ajg1.2.18)

- The daemon measures, per mount, the peak used-bytes growth inside each reaction window (an EWMA of poll + scan + reclaim latency, five-minute prior) and keeps the samples in a t-digest persisted as `burst_stats.bin` beside `state.json`. The reserve target is the 0.99 quantile of those windows: the digest's own quantile after 50 windows, a generalized Pareto tail fit above the 0.9 quantile from 10 windows, and never below two ballast files. `state.json` carries it per mount as `reserve_state.burst` (`recommended_bytes`, `q99_bytes`, `windows`, `reaction_window_secs`, `method`, `horizon_minutes` at the burst rate); `metrics.prom` exports `sbh_reserve_recommended_bytes` and `sbh_burst_q99_bytes`.
- `sbh tune` recommends `file_count = ceil(reserve / file_size)` per pool (`ballast.file_count` for a single un-overridden pool, `ballast.overrides.<mount>.file_count` otherwise) and `sbh doctor --system` gains `ballast.reserve_coverage`, which FAILs when a pool's releasable bytes fall short of that reserve. `sbh status` shows the required bytes, the estimate method and the window count in the reserve column.

### Changed — event-scoped Green passes (bd-rc-master-ajg1.8.8)

- A filesystem event no longer dirties the whole configured root: it resolves to the project directory below the root that contains the change (the root itself when the change is at the root, when that directory is an artifact tree, or when more than 64 projects are dirty at once). The scanner polls the event source every 2 seconds while idle and runs the scoped pass itself at Green or Yellow, reported as `reason=event` in `scan_complete` and paced by the base `min_rescan_interval_secs` only. Before, Green passes only happened on the maintenance interval and walked everything.

### Changed — inotify watch budget allocation (bd-rc-master-ajg1.8.4)

- The scanner's recursive inotify plan always watches every root and depth-1 directory and spends the rest of `scanner.event_watch_budget` on the most active directories (per-directory event-rate EWMA, directory-mtime prior for never-watched subtrees). Directories left unwatched under a watched parent are reconciled as their own scan paths instead of dirtying the whole root, and an incomplete plan is re-allocated every 15 minutes from observed rates without losing events.
- inotify queue overflows reconcile everything once and then back off (30 s, doubling per consecutive overflow, capped at 30 min); overflows inside the window are coalesced into one deferred reconciliation. `scan_complete` details gained `event_overflows` and `event_watch_replans`; the `scanner_events:` log lines gained `frontier_dirs`, `overflows`, `backoff_secs` and `replans`.

### Added — daemon control socket

- The daemon serves `control.sock` beside `state.json` (mode 0600, per-boot token in `daemon.lock`, JSON line in / JSON line out). `sbh daemon ping|scan-now|reload|shutdown` and `sbh policy status|promote|demote` talk to it; `sbh status --json` asks a running daemon to rewrite `state.json` first and reports `"source": "socket"`. Promotions persist `[policy] initial_mode` after a config backup. `[core] control_socket_enabled = false` turns the socket off.

### Added — Prometheus textfile export

- The daemon writes `metrics.prom` beside `state.json` with every state write (atomic, world-readable) for node_exporter's textfile collector: daemon identity/uptime/CPU/RSS/budget, per-mount free ratio, pressure level, fill rate, forecast, reclaim capability, controller state and ballast bytes, plus scan/deletion/byte counters, policy mode and thread liveness. `sbh metrics` prints it; `[telemetry] metrics_enabled = false` turns it off and removes a stale file.

### Fixed — daemon scanner hot loops at Orange (bd-8aeq)

- A definite cargo `target/` replayed from the scanner index was re-classified from the root directory's own entries and downgraded to `unclear`, so the Orange cell held it back forever while the replay re-dispatched it twice a second. Index records now persist the walk's structural signals (checkpoint version 2; an old index is walked once more) and replays score with them.
- The scanner applies the behavior cell's certainty gate itself: held-back candidates are neither dispatched nor counted toward the pressure byte target, and a pass whose dispatches reclaimed nothing (dry-run, observe mode, dampened or failed batches) is paced like an empty pass. Measured on the operator workstation at injected Orange: 575 passes / 92.8 CPU-s per five minutes before, 4 passes / 8.6 CPU-s after.

### Changed — status and check JSON schema 2

- `status --json` and `check --json` carry `"schema_version": 2`; each mount's `platform` block is keyed by filesystem family (`darwin.apfs` on APFS, `linux { fs_type, is_ram_backed, is_readonly, device_id }` on Linux, `{}` elsewhere) and the APFS-only mount keys, including `free_excludes_purgeable`, appear only on APFS.

### Added — diagnostics and recovery

- `sbh doctor --service [--user]` diffs the installed systemd unit or launchd plist against the generator (hardening directives, `Type=`, binary, drop-ins, condition gates); `sbh service --systemd reinstall-unit [--purge-dropins]` rewrites the unit with a backup beside it.
- `sbh explain --why-not DIR [--counterfactual]` scores a directory now and names the first rail that stops it; `sbh explain --replay ID` re-scores a recorded decision with the current code.
- `sbh emergency --min-age MINUTES` (default 5) is emergency mode's only age floor; emergency prints a decision id per candidate.

---

## v0.5.1 **[release]**

### Fixed — rch target dirs are reclaimed on idle time, not birth time (regression from v0.5.0)

v0.5.0 widened reclaim to key on `CACHEDIR.TAG` rather than directory name.
Cargo writes `CACHEDIR.TAG` into every target dir, so rch's remote
`CARGO_TARGET_DIR` trees — previously invisible to the name matcher — became
first-class candidates. Being the largest directories on a build host, they
scored highest.

They were also removed **while builds were writing to them**, because
`EntryMetadata::effective_age_timestamp` ages directories by *birth* time. That
is deliberate and correct for ordinary caches (a directory's `mtime` bumps on
every child add/remove, so an active `target/` looks perpetually young), but it
inverts for an rch pool dir: a warm cache created days ago and rebuilt into ever
since still reports an age of days, so it scores as maximally abandoned exactly
when it is busiest. On one host this removed an 18.9 GB and a 12.3 GB pool dir
in a single sweep.

Removing a pool dir does not reclaim reusable space. It forces every subsequent
dispatch sharing those build dimensions to rebuild the whole crate graph from
cold.

Reclaim of rch-managed dirs now mirrors rch's own contract
(`rch-common/src/stale_target_reap.rs`):

- scope is exactly rch's `REAP_GLOBS` — the `-job-`, `-pid-` and `-pool-`
  marker shapes under `.rch-target-`. Bare `rch_target_*` and `target` trees
  keep their existing scoring.
- eligibility is **recursive tree idleness**, tested with an early exit on the
  first fresh file, not the directory's own timestamp.
- idle floors match rch: 12 h for per-job and per-pid dirs, 168 h (7 days) for
  pooled ones, which rch treats as warm caches rather than short-TTL targets.
- an indeterminate result (unreadable subtree, or a tree past the traversal
  guard) vetoes rather than removes, deferring to rch's own reaper.

Vetoed candidates are never plannable in any mode, including emergency
escalation.

### Fixed — `sbh stats` no longer looks broken when the daemon runs as root

The activity database lives under the invoking user's data dir. With the usual
root-owned daemon, an unprivileged `sbh stats` correctly found nothing and
reported a bare `no_database`, which reads as a malfunction. It now detects the
root-owned database and points at `sudo sbh stats` (JSON output gains `hint` and
`root_db_path`).

---

## v0.5.0 **[release]**

### Changed — build-cache reclaim is now keyed on `CACHEDIR.TAG`, not directory name (bd-k0t3r)

**This widens what the reclaim daemon will delete. Read before rolling out.**

Previously a regenerable build cache was recognised only by directory *name*
(`rch_target_*` plus a fixed set of `target`-like patterns) together with
structural markers (`deps/`, `incremental/`, `.fingerprint`) that live one level
down under `debug/` and `release/`. Cargo target dirs under arbitrary names —
`srw`, `p4-verify`, `*bld`, the shared `cargo-target` — matched no name pattern
and exposed no markers at their own root, so they were never reclaimed. They
were also the largest consumers, and drove `/` to ~98%, at which point the host
starts killing in-flight builds.

Reclaim now detects cargo's canonical `CACHEDIR.TAG` marker, **with signature
validation**, so a file merely *named* `CACHEDIR.TAG` cannot mark a directory
reclaimable.

Operationally: directories that were previously invisible to the sweeper are now
eligible. That includes isolated `RCH_TARGET_BASE` target dirs. Verify on a
canary host before fleet rollout.

### Fixed

- Scanner duty cycle is bounded so a productive pass cannot pin a core.
- Scanner/walker error mapping, symlink handling, and diagnostics refined.
- Five exhaustive struct literals that `cargo test --lib` never compiled.
- `clippy -D warnings` clean, including the two deletion fail-safes, which keep
  their deliberate negative-first form (`if !complete { skip } else { delete }`)
  under an annotated `#[allow(clippy::if_not_else)]` rather than being inverted.

### Notes

- Lib tests: 1404 passed, 0 failed. Run them as a **non-root** user — as root,
  `fallback_when_primary_dir_unwritable` cannot exercise its fallback because
  root can create the "unwritable" path, producing ~20 environmental failures
  that are not defects (see #19).

## v0.4.40 **[release]**

Tag: [`v0.4.40`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.40) | Compare: [`v0.4.39...v0.4.40`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.39...v0.4.40) | 2026-08-16

### Fixed — interactive clean/emergency deletions use the full preflight veto stack

- Adversarial review of the v0.4.39 emergency escalation found that the interactive `clean` and `emergency` paths (no `--yes`) removed accepted candidates through a bare `remove_dir_all`, bypassing the source-tree floor, active-lease, open-file, and marker vetoes the `--yes` batch path enforces. Both now go through the same preflight stack ([`0dde89a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0dde89ae3356570d5e08bd08057c362f784a7373)).

## v0.4.39 **[release]**

Tag: [`v0.4.39`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.39) | Compare: [`v0.4.38...v0.4.39`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.38...v0.4.39) | 2026-08-15

### Added — process-scoped active-target leases

- A live cargo/build target is neither marker-protected nor an open file, so it could be reclaimed mid-build. A build can now hold a process-scoped lease on its target that survives `exec`; leases are probed on canonical paths so symlink ancestors cannot fail open, and a watchdog keyed on the process group releases them when the process dies ([`8ed845b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8ed845b4daa24e8d75b8ee682cfb0e9151ff28f0), [`37111db`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/37111dba9bd2c38d1286f33b2fbfaf27d8d88e85), [`430b7dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/430b7dd4ef6552d7407a4f591d8ff30855324368), [`fd9298f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fd9298f2cac6d92888ddc430db6e54dbb129f6f1)).

### Changed — emergency mode acts on `Review` candidates

- `sbh emergency` only admitted `Delete` decisions, so a corpus that scored entirely as `Review` made the last line of defence a no-op on a full disk. Review candidates are now eligible in emergency mode, with every hard safety rail unchanged ([`1923bc8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/1923bc898da3b9b0afe000dc7fac2f372b097f8b)).

### Fixed — every skip is attributed

- A run reporting 221 candidates, 221 skipped, and 0 bytes freed with no reason was indistinguishable from a malfunction. `clean` and `emergency` reports now attribute each skip (`skipped_by_reason`) and flag a stalled run, on the no-candidates path too ([`8e10858`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8e10858b5ca794a489e255b22a95103fcb0539f5), [`b00ca43`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b00ca43bac83b6f6779f5fc128ae1a878b83df6b), [`c47ce06`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c47ce06289281da1957b22ec6b5882accf7a1789)).
- Local builds use the parallel rustc front-end (`-Z threads=4`) ([`94fa77a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/94fa77a85355b50f0092c899be6e02a91966a994)).

## v0.4.38 **[release]**

Tag: [`v0.4.38`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.38) | Compare: [`v0.4.37...v0.4.38`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.37...v0.4.38) | 2026-08-11

### Performance — protected sacred verdicts are memoized across daemon passes

- Re-proving sacred overlaps every pass recursively walked known-protected `/data/tmp` candidates and pegged a core. Only *protected* verdicts are cached (never "clean", which would fail open if a marker appeared later): TTL 600 s, capacity 4096, invalidated when the root's mtime changes ([`12fd99e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/12fd99e355cb6aea3f874a399ca4a3a15843a870)).

## v0.4.37 **[release]**

### Fixed — sparse files are sized by allocated blocks (#17)

The walker sized every entry with `meta.len()` (`st_size`, the *apparent*
logical length) in `entry_metadata`, and accumulated directory content size the
same way via `child_meta.len()`. A sparse file therefore contributed its full
logical size rather than the space it actually occupies: a 20 GiB `set_len`
image with zero allocated blocks was reported as 21474836481 bytes, and a
real-world store directory holding one sparse disk image reported 927 GiB of
usage that did not exist on the device.

Entries are now sized by allocated blocks (`st_blocks * 512`) on Unix, which is
what a ballast/reclaim tool has to reason about — reclaiming a sparse file
returns only its allocated extents, not its logical length. Apparent length is
still available where the logical size is the meaningful quantity.

### Also in this release

- Ballast health reporting: `Unconfigured` now outranks `Indeterminate`, an
  unreadable reserve is never reported as empty, and the unreadable tally is
  surfaced instead of being silently folded into the healthy count.

---

## v0.4.36 **[release]**

Tag: [`v0.4.36`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.36) | Compare: [`v0.4.35...v0.4.36`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.35...v0.4.36) | 2026-08-02

### Performance — ancestor canonicalization is memoized

- `resolve_absolute_path` called `canonicalize` once per path, one `readlink` per component, re-resolving the same ancestor chain for every descendant. Ancestors are now memoized, which ends the scanner's readlink storm on wide trees ([`74e52a9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/74e52a95b32c2daae49ba4ab4b8bd3b9f4c4a991)).

### Fixed — macOS zombie processes

- `command_output_with_timeout` dropped a timed-out child before reaping it, leaking one zombie per timed-out command for the life of the process ([`3508685`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/35086853bc69b87250d2fcdf25c2b37abd7068be)).

## v0.4.33 **[release]**

Tag: [`v0.4.33`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.33) | Compare: [`v0.4.32...v0.4.33`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.32...v0.4.33) | 2026-07-02

### Added — safe `/root` build-artifact backstop

- A stale 241 GB `/root/cass-ft-target` filled a worker because `/root` is a hard system-path veto and the artifact-basename rule had no `*-target`/`*_target` suffix. A narrow, safety-gated backstop now reclaims regenerable build targets under `/root` ([`1389645`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/13896455a4c3c8ef7a29e6cd6240f32234325da0)).
- `Cargo.lock` completed with ftui's transitive `fsqlite-*` dependencies so `--locked` source builds resolve ([`7298046`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7298046e627d1cc4f07f23b0a663a173782df1c2)).

## v0.4.32 **[release]**

Tag: [`v0.4.32`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.32) | Compare: [`v0.4.30...v0.4.32`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.30...v0.4.32) | 2026-06-30. The v0.4.31 version bump below was never tagged; this release carries it.

### Added — Go caches are reclaimable; scanner v2 is the default engine

- `GOCACHE`/`GOMODCACHE` trees (tens of GB under arbitrary names; module dirs ship a `go.mod` and are mode `0555`) are now recognized, pass the source-code veto, and can be removed. The v2 scanner engine is the default ([`7e50e27`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7e50e2787b077d1a2447a27b3818d8ee2559105c)).

### Fixed

- The daemon's multi-volume ballast coordinator ignored `[paths] ballast_dir` and always used `<mount>/.sbh/ballast` ([`0e8f703`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0e8f703b42deb6b50ec6ed70091296f5dba6a08c)).
- `ftui` is sourced from git instead of a local `/dp` path so `cargo install --git` works off the build host (#12) ([`0f534d8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0f534d8c9c4a20e90eb626b946e74a9bda0248b9)); the empty-pass no-progress fix landed via #13 ([`8591776`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8591776757b425f24dcd03dfbb71f62c505527cd)).

## v0.4.31

Never tagged; shipped in v0.4.32 above.

### Added — kernel writeback (dirty-page) tuning

sbh already runs its daemon at `Nice=19` + `IOSchedulingClass=idle`, but the worst
interactive-latency stalls on busy build hosts come from *kernel* writeback behavior that no
per-process nice/ionice can fix. On a high-RAM box the default percentage-based
`vm.dirty_ratio`/`vm.dirty_background_ratio` knobs let many GB of dirty pages accumulate before
writeback throttles (e.g. ~24 GB at `dirty_ratio=10` on a 247 GB host); they then flush in bursts
through kernel writeback threads (`btrfs-endio-write` and friends) that ignore the producing
process's ionice class, so the interactive terminal stalls behind each multi-GB flush. The fix is
to replace the ratio knobs with absolute byte limits (`vm.dirty_bytes`/`vm.dirty_background_bytes`)
sized for continuous, gentle writeback.

sbh now models this cross-platform and applies it on Linux:

- **`sbh tune`** gained a `KernelWriteback` recommendation category. It sizes the byte limits from
  the backing device's **measured write bandwidth** (a short, bounded, non-destructive on-volume
  micro-benchmark with random data; `--no-benchmark` falls back to an NVMe/SSD/HDD device-class
  heuristic). At a typical ~512 MiB/s SSD with the default 1 s background-drain target and 4:1 hard
  ratio this lands on `vm.dirty_background_bytes=512 MiB` / `vm.dirty_bytes=2 GiB`. `--apply`
  (root) writes the live `/proc/sys/vm` knobs **and** persists a backup-first, self-documenting
  `/etc/sysctl.d/99-sbh-writeback.conf`, validates it with `sysctl -p`, and warns about any
  later-loading `sysctl.d` file that would override the byte limits with a ratio.
- **`sbh tune --revert-writeback`** (root) restores the most recent backup of the sbh snippet (or
  removes it) and reloads sysctl.
- **`sbh doctor --system`** adds a `system.writeback_tuning` check that WARNs when the RAM-derived
  dirty pool exceeds `system_tuning.writeback_pool_warn_bytes` (default 4 GiB), escalated for
  copy-on-write filesystems (btrfs/zfs). It is read-only (heuristic only, never benchmarks) and
  returns PASS/not-applicable on platforms without tunable writeback limits (macOS).
- **`sbh install`** applies + persists the tuning automatically when run as root
  (`system_tuning.writeback_auto_apply_on_install`, default on); non-root installs print the
  `sudo sbh tune --apply --yes` hint.

This is **never applied by the daemon at runtime** — the hardened system-scope unit sets
`ProtectKernelTunables=true` (so the daemon cannot write `/proc/sys`), and silently mutating global
kernel state from a background daemon would violate sbh's explainability/least-surprise principles.
All mutation is operator-invoked, root-gated, backup-first, and reversible.

New `[system_tuning]` config section (with `SBH_SYSTEM_TUNING_WRITEBACK_*` env overrides):
`writeback_enabled`, `writeback_auto_apply_on_install`, `writeback_target_drain_secs`,
`writeback_hard_ratio`, `writeback_min_background_bytes`, `writeback_max_background_bytes`,
`writeback_benchmark_enabled`, `writeback_benchmark_bytes`, `writeback_pool_warn_bytes`,
`writeback_sysctl_path`.

New PAL surface: `writeback_state()`, `block_device_for()`, `apply_writeback_runtime()`
(Linux reads `/proc/sys/vm` + `/sys/block`; other platforms return not-applicable). New
platform-agnostic `tuning` module (`tuning::writeback`, `tuning::bandwidth`) holds the sizing,
assessment, `sysctl.d` rendering, conflict detection, and bandwidth estimation, fully unit-tested.

---

## v0.4.30 **[release]**

Compare: [`v0.4.29...v0.4.30`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.29...v0.4.30)

### Fixed — empty-pass cooldown now keys on reclaim *progress*, not candidates *surfaced* (+ exponential backoff)

v0.4.29's B6 empty-pass cooldown only armed when a scan surfaced **zero** candidates
(`candidates_found == 0`). On a disk parked below the green free-space threshold whose
candidates are *all protected* — e.g. `/data/tmp` test fixtures full of `*.sqlite-wal`,
`.git/`, `.beads/` sacred markers — every ~50s scan surfaces hundreds of candidates that
are then all skipped, so `deleted == 0 / freed == 0` yet `candidates_found > 0`. The
cooldown was therefore cleared on every pass and never engaged: the scanner re-walked the
same tree back-to-back and pinned a core 24/7 (observed on ts2 — ~100 CPU ticks/s for
~2 days, contained only by the `CPUQuota` cap).

- **Cooldown now keys on reclaim progress.** `dispatch_top_candidates` reports how many
  candidates it handed to the deletion executor; a pass arms the cooldown when it
  dispatched **nothing** (`dispatched_this_pass == 0`) — covering both "found nothing" and
  the hot-loop case "found candidates but all protected/dampened".
- **Exponential backoff for sustained no-progress.** Each consecutive no-progress pass
  doubles the rescan interval, capped at 32× `min_rescan_interval_secs` (90s → … → 2880s),
  resetting to the base interval on the first productive pass. A perpetually-pressured-but-
  nothing-to-reclaim disk decays from one scan per base interval to one per ~32× instead of
  re-walking continuously.

Red/Critical pressure still bypasses the cooldown (disk-safety floor unchanged); the
deletion path and all protection logic are untouched. Verified live on ts2: daemon CPU
~100 → ~1.5 ticks/s, with backoff log lines firing (`… 427 candidates, 0 dispatched;
backing off rescans (consecutive=2, … ≥180s)`).

---

## v0.4.29 **[release]**

Compare: [`v0.4.28...v0.4.29`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.28...v0.4.29)

### Fixed — scanner hot-loop: bounded marker sub-walk, device-affinity gate, empty-pass cooldown

Ships the scanner fixes from PR #11 (`sbh-scan-affinity-and-bounded-marker-walk`, merged to
`main` as `13c5005` / `34957b6`). These landed **after** the published v0.4.28 release, so the
0.4.28 binary running fleet-wide never contained them — and on 2026-06-12 the scanner was found
hot-looping at ~100% of a core 24/7 on every orchestrator (one host's pass walked 218,186
entries / 7,160 top-level `/data/tmp` dirs in 356s, then immediately rescanned on a 5s poll).
Three independent fixes, **none of which touch the deletion path or weaken any safety floor**:

- **Bounded sacred-marker sub-walk.** The "protected candidate skipped" containment check that
  walks a candidate looking for sacred markers (`.beads/`, `.git/`, `*.sqlite3`, `*.db-wal`, …)
  previously ignored `scanner.max_depth` and full-walked million-file trees every pass. It now
  caps at `max_entries` (20k) with early-exit and **fails closed to PROTECTED on truncation** — a
  truncated walk can only strengthen protection, never weaken it.
- **Device-affinity gate.** Aggressive scanning triggered by pressure on a device is suppressed
  when no configured `root_path` actually lives on that device (e.g. `/` is full but every
  `root_path` is on `/data`), a situation the scanner can never relieve and would otherwise spin
  on forever.
- **Empty-pass cooldown.** New `scanner.min_rescan_interval_secs` (default 90s) enforces a
  cooldown after a pass that produced no deletions, so a steady state of all-protected candidates
  no longer triggers back-to-back rescans.

Verified on the trj canary (2026-06-02): CPU settles to 0–3% (was pinned ~100%), the
device-affinity backoff fires in production logs, `sbh clean --dry-run` enumerates 38,922 dirs in
10s with 0 candidates, and zero `auditd` DELETE events occur under `/data/projects`. 2,275 library
tests pass.

> Operational note: hosts that accumulate *thousands* of marker-bearing ephemeral test dirs under
> `/data/tmp` should still keep that directory pruned — the bounded walk caps cost per candidate,
> but a very large top-level dir *count* is still real work per pass. A periodic `/data/tmp`
> janitor and a longer `poll_interval_ms` are complementary operational mitigations.

---

## v0.4.28 **[release]**

### Added — `rch-cargo-home-*` cleanup matcher

rch (the remote compilation helper) stages an isolated `CARGO_HOME` per build in a
`rch-cargo-home-<host>-<pid>-<uuid>` directory; as of rch 1.0.38 these land under
`$TMPDIR`/`/data/tmp` and are left behind when a build dies. sbh had no matcher for
this prefix (`cargo-home-` and `.tmp_cargo_home_` did not cover `rch-cargo-home-`),
so these abandoned dirs were never reclaimed. Added a basename `Prefix("rch-cargo-home-")`
matcher (`ArtifactCategory::TempDir`, confidence 0.92), mirroring the existing
`cargo-home-prefix` rule. Matching is by basename, so it fires regardless of the
parent (`/tmp` vs `/data/tmp`). The narrow source-tree carve-out
(`is_obvious_build_artifact_basename`) was deliberately **not** extended, so the
hard `is_hardcoded_source_tree()` refusal still gates these dirs under any protected
source root — the matcher only affects scoring/age in tmp-like roots. Reviewed
adversarially: cannot match a source/repo/`.git` dir (trailing-hyphen prefix); no
change to deletion-scope floors.

---

## v0.4.27 **[release]**

Tag: [`v0.4.27`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.27) | Compare: [`v0.4.26...v0.4.27`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.26...v0.4.27) | 2026-05-27

- One commit over the unpublished v0.4.26 tag: the macOS active-reference mock paths are normalized so the platform test lane passes; no runtime change ([`53a7475`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/53a747501846319c24de314f97882fdc8a48d235)). For what v0.4.26 itself changed over v0.4.25, see the compare link.

## v0.4.25 **[release]**

Compare: [`v0.4.24...v0.4.25`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.24...v0.4.25)

### Safety floor — source-code deletion is now impossible regardless of config

**Background.** The 2026-05-16 fleet carnage wiped ~87 working trees under `/data/projects` on trj when the scanner's name-heuristic gave source-crate directories high artifact-like scores. The carnage repeated on a smaller scale on 2026-05-22 when sbh was re-enabled on the vmi worker fleet: synced source-crate stubs (1–10 KB, no `Cargo.toml` yet) were classified as deletable artifacts and `frankenterm/crates/frankenterm-core`, `frankenterm/crates/frankenterm-alloc`, `frankenterm/crates/frankenterm-topo`, and ~25 other crate dirs were deleted across vmi1149989/vmi1153651/vmi1156319/vmi1167313 before the operator caught it. No primary source was lost (vmis hold synced ephemeral copies and re-sync from trj on next rch job), but the bug means an operator who points sbh at `/data/projects` on a primary dev machine can lose actual source.

**Fix.** Two hardcoded safety layers were added to `scanner::deletion::preflight_check` that cannot be disabled via operator configuration:

- **`SkipReason::HardcodedSourceTree`** (preflight step 0, runs BEFORE the existence check) refuses paths inside well-known source-tree locations — `/data/projects/`, `/home/<user>/projects/`, `/Users/<user>/projects/` — UNLESS the candidate's basename clearly identifies it as a disposable build/cache artifact (see the carve-out list below). It also refuses, unconditionally with no carve-out, any path with an ancestor directory literally named `.git` (including the candidate itself being named `.git`). The match list is hardcoded and cannot be disabled by config.
- **`SkipReason::LooksLikeSourceCode`** (preflight step 5b, runs after the existing cargo-manifest veto) refuses any directory that directly contains a source manifest (`Cargo.toml`, `package.json`, `pyproject.toml`, `setup.py`, `go.mod`, `pom.xml`, `build.gradle`, `tsconfig.json`, `Gemfile`, `Pipfile`, `mix.exs`, `Project.toml`, etc.) OR direct-child source files (`*.rs`, `*.py`, `*.ts`, `*.go`, `*.cpp`, `*.swift`, `*.rb`, `*.java`, `*.kt`, `*.ex`, `*.exs`, `*.ml`, `*.hs`, `*.c`, `*.h`, `*.hpp`, `*.scala`, `*.clj`, `*.cljs`, `*.lua`, `*.jl`, etc.). Catches synced stubs that lack `Cargo.toml` and so slip past the existing `ContainsCargoManifest` veto. Direct-child only (no recursion). The check applies everywhere — even outside the hardcoded source-tree paths — so a stray `package.json` in an unexpected location still triggers a veto.

Both new skip reasons are routed through the existing "normal safety veto" log-noise filter so they don't flood the activity log with expected refusals.

### Artifact-basename carve-out — keeps sbh useful inside source trees

The broad source-tree refusal would otherwise block sbh from doing its main job inside operator-configured source roots (the setup wizard adds `/data/projects` to `root_paths` precisely so target/ etc. can be cleaned). The carve-out is a narrow allow-list of basenames that are unambiguously disposable:

**Exact match** (alphabetized): `.cargo-target`, `.next`, `.nuxt`, `.parcel-cache`, `.pytest_cache`, `.rch-target`, `.rch_target`, `.target`, `.tox`, `.turbo`, `.venv`, `__pycache__`, `build`, `dist`, `node_modules`, `rch-target`, `rch_target`, `target`, `venv`.

**Prefix match (each requires the trailing separator):** `target-*`, `target_*`, `.rch-target-*`, `.rch_target_*`, `rch-target-*`, `rch_target_*`, `.cargo-target-*`.

The separator requirement matters — an earlier draft used `.rch-target` as a prefix (no trailing `-`), which would have falsely matched names like `.rch-targetfoo` and exempted them from the protection. Each prefix matcher in the implementation requires its separator; bare basenames without suffixes are in the exact-match list instead.

A path under a protected root whose basename matches one of these IS deletable; any other basename is vetoed. This means `/data/projects/franken_node/target` gets cleaned, but `/data/projects/franken_node/src` (or `/data/projects/frankenterm/crates/frankenterm-core`, the actual 2026-05-22 incident) stays protected.

The `.git`-ancestor refusal is NOT subject to the carve-out — `/srv/code/.git/target` is still vetoed because the `.git` ancestor wins. The whole purpose of refusing under-.git paths is to protect git metadata; allowing artifact-named children would defeat that.

### Default scan roots are now safe out of the box

`ScannerConfig::default()` shipped with `["/data/projects", "/tmp", "/data/tmp", "/var/tmp", "/home", "/root"]` — three of those six entries hold source code or personal files. A fresh install that inherited defaults was unsafe. New default:

- `root_paths = ["/tmp", "/data/tmp", "/var/tmp"]` — only ephemeral temp paths.

`excluded_paths` is unchanged. `/data/projects` is intentionally NOT added to default `excluded_paths`: the setup wizard (`cli/wizard.rs`) actively adds `/data/projects` to `root_paths` when run, so excluding it would silently break wizard-generated configs (the walker would refuse to descend into the configured root). The hardcoded preflight refusal at deletion time — combined with the artifact-basename carve-out — is the real defense.

### Operator implications

Once v0.4.25 is deployed and sbh is re-enabled:

- The setup wizard's auto-added `/data/projects` root continues to be useful: `target/`, `node_modules/`, `.rch-target-*/`, etc. under it ARE cleaned up.
- Arbitrary basenames under `/data/projects/`, `/home/*/projects/`, or `/Users/*/projects/` (e.g., `src/`, `docs/`, `crates/`, `frankenterm-core/`) are refused at preflight even if the scorer marks them as candidates. This is the carnage-prevention guarantee.
- `LooksLikeSourceCode` (step 5b) provides a second-layer defense even outside the protected paths: any dir containing source manifests or top-level source files is refused regardless of where it sits.

If the carve-out list misses a basename you'd like sbh to clean (or includes one you'd like protected), it's an additive edit to the constant list inside `is_obvious_build_artifact_basename` in `src/scanner/deletion.rs` — no API change.

### Tests

Hardcoded source-tree refusal:

- `hardcoded_source_tree_matches_data_projects` / `_home_projects` / `_users_projects` — non-artifact basenames under each protected root are refused.
- `hardcoded_source_tree_skips_unrelated_paths` — `/tmp/junk`, `/home/ubuntu/.cache`, `/home/ubuntu/project` (singular), etc. pass through unchanged.
- `hardcoded_source_tree_matches_git_ancestor` — paths with `.git` ancestor (including the leaf case `/srv/code/.git` and `/.git`) are unconditionally refused.

Artifact-basename carve-out:

- `obvious_build_artifact_basename_exact_matches` — every entry in the exact-match list is recognized (covers all 19 bare names including the bare `.rch-target`, `.rch_target`, `rch-target`, `rch_target` variants).
- `obvious_build_artifact_basename_prefix_matches` — `target-*`, `target_*`, `.rch-target-*`, `.rch_target_*`, `rch-target-*`, `rch_target_*`, `.cargo-target-*` patterns recognized.
- `obvious_build_artifact_basename_negatives` — confusables (`targets` plural, `my-target`, `untargeted`, `nodemodules` without underscore, etc.) and real source basenames (`src`, `lib`, `tests`, `docs`, `frankenterm-core`, etc.) do NOT match. Includes regression cases for the prefix-without-separator class (`.rch-targetfoo`, `rch-targetfoo`, `rch_targetfoo`, `.cargo-targetfoo`, `targetfoo`) that an earlier permissive prefix matcher would have wrongly exempted.
- `obvious_build_artifact_basename_handles_no_basename` — `/` and empty paths return false.

Hybrid behavior:

- `hardcoded_source_tree_allows_target_under_data_projects` — `target/`, `node_modules/`, `.next/`, `__pycache__/` under `/data/projects/foo/` are NOT vetoed.
- `hardcoded_source_tree_allows_rch_targets_under_data_projects` — full rch per-job target paths are recognized via the prefix-match list.
- `hardcoded_source_tree_allows_target_under_users_projects` / `_under_home_projects` — carve-out applies equally to all three protected roots.
- `hardcoded_source_tree_still_vetoes_source_basenames_under_protected_root` — `src`, `docs`, `legacy_code`, working-tree root names, and the actual 2026-05-22 incident target (`frankenterm-core`) all STAY vetoed.
- `hardcoded_source_tree_git_check_overrides_artifact_carveout` — `/srv/code/.git/target` and `/srv/code/.git/objects/pack/target` are refused despite the artifact basename, because the `.git` ancestor check runs after the carve-out.

Source-code marker veto:

- `looks_like_source_code_detects_cargo_toml` / `_rust_files` / `_package_json` / `_python_files` / `_go_files` — positive triggers across languages.
- `looks_like_source_code_ignores_build_artifacts` — pure cargo `target/` dir is NOT classified as source.
- `looks_like_source_code_skips_unreadable_dir` — `read_dir` failure returns false (matches existing helper behavior).

Preflight wiring:

- `preflight_vetoes_hardcoded_source_tree` — step 0 fires for `/data/projects/frankenterm/crates/frankenterm-core`.
- `preflight_vetoes_source_code_dir` — step 5b fires for a dir with `package.json` + `index.ts`.
- `preflight_cargo_manifest_still_takes_precedence_over_source_marker` — locks in step 5 (ContainsCargoManifest) firing before step 5b (LooksLikeSourceCode) when a dir matches both, so a future refactor that swaps the order is visible in test diffs.

### Fleet status as of this release

This crate version is not yet built or deployed. The je fleet currently runs v0.4.24 with operator-patched `/etc/sbh/config.toml` (`root_paths = ["/tmp", "/data/tmp"]`). The config patch alone is sufficient to prevent the recurring scenario (walker never descends into `/data/projects`); v0.4.25 lets operators safely add `/data/projects` back to `root_paths` because the in-code defenses fire at deletion time — refusing source-shaped paths while permitting `target/` and friends.

## v0.4.24 **[release]**

Tag: [`v0.4.24`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.24) | Compare: [`v0.4.23...v0.4.24`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.23...v0.4.24) | 2026-05-17

### Fixed — release artifacts are verified against their matrix target

- v0.4.23 shipped the macOS aarch64 binary inside the Linux x86_64 tarball, so every Linux self-update failed with `Exec format error`. The release workflow now verifies each tarball's binary matches its matrix target before upload ([`b15e1e0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b15e1e0da3ac4cc8362f3e2af1a955bcd28a30ac)).

### Changed — log truncation sees the measured free space

- The v0.4.23 truncation hook mapped pressure levels to synthetic free percentages; it now receives the measured `free_pct` and opens files defensively ([`19d8814`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/19d88147ff7dc9e197c687718a74f01a6127fafb)); the non-UTF-8 filename test is gated to Linux ([`5854496`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/58544962980f0a6b9a8806c40f8c21399c8c2a32)).

## v0.4.23

Tag: [`v0.4.23`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.23) | Compare: [`v0.4.22...v0.4.23`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.22...v0.4.23) | 2026-05-14. A GitHub Release exists but carries no assets: the artifacts were mispackaged (see v0.4.24).

### Added — truncate-in-place for active append-only logs

- The 2026-05-13 fleet incident drove three hosts to 99% because the open-file veto refused to touch `~/.codex/log/codex-tui.log` while codex held it open (318 GB, 132 GB, and 81 GB). Active append-only logs are now truncated in place under pressure ([`508fe4c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/508fe4ca36c5f2d1b84994cba886142d8b733fe5)); the macOS docs record the v0.4.22 release ([`13abf49`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/13abf49953f98863c3e64a738c09dcc7d89583f1)).

## v0.4.22 **[release]**

Tag: [`v0.4.22`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.22) | Compare: [`v0.4.21...v0.4.22`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.21...v0.4.22) | 2026-05-12

- The release publisher and Homebrew tap updater download only `sbh-*` build artifacts, keeping the archive contract to the four build artifacts plus checksum sidecars. v0.4.21 had proven the gates and the signed, notarized builds but failed at publish ([`d8bfa92`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d8bfa924a511ac02ad0644639ce8cf529d589144)).

## v0.4.14 **[release]**

Tag: [`v0.4.14`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.14) | Compare: [`v0.4.13...v0.4.14`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.13...v0.4.14) | 2026-05-12

### Fixed — macOS cross builds

- `libproc` generated its Darwin bindings with host-side cfg checks, so Linux cross builds for `aarch64-apple-darwin` failed before linking. Its process-list, pidpath, rusage, and region-path calls moved behind the existing `sbh_mach` platform crate ([`079553d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/079553d2cf14b99877f046ec1cd0836469978983)).

## v0.4.8 **[release]**

Tag: [`v0.4.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.8) | Compare: [`v0.4.7...v0.4.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.7...v0.4.8) | 2026-05-11

### Changed — macOS release trust verification

- The release workflow's raw `spctl` gate is replaced by validation of Apple's accepted notary log; the Unix installer and the self-update verifier require `codesign` structural validity plus the expected Developer ID Application authority and TeamIdentifier ([`081d3e7`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/081d3e7024f046ca6e67a62f614f637cae13608e), [`52b4c3d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/52b4c3d31399a08d8f671444e746e2f98a99ed4a)).

## Unreleased

Compare: [`v0.4.6...HEAD`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.6...HEAD)

### macOS

- **Document the macOS cleanup wins in concrete operator terms.** The Unreleased macOS docs now explain the real before/after space-recovery cases instead of only listing implementation details. Before this work, a Mac operator had to infer what was safe from Linux-flavored artifact language; after it, the release notes call out the exact macOS cleanup shapes and tradeoffs: `sbh` can rank a stale 12 GB Xcode DerivedData child after 24 hours without deleting the broad `~/Library/Developer/Xcode/DerivedData/` root, surface a 64 GB Time Machine local snapshot retention case with the exact `sudo tmutil thinlocalsnapshots / 9999999999999999 4` reclaim command, classify regenerated Electron caches such as `Cache`, `Code Cache`, `GPUCache`, `IndexedDB`, `Service Worker/CacheStorage`, and `vm_bundles` so an idle 8 GB app cache can be cleaned while active app state remains guarded, and detect forgotten `~/release-work/*[-_]buildroot` staging trees after 7 days. The real incident example is preserved: `~/release-work/mcp_agent_mail_rust_buildroot` sat idle for 11 days and held 39 GB.
- **Tie the release note back to the operator trust docs.** The macOS changelog now points readers to `docs/cleanup-rules-macos.md` for the exhaustive cleanup contract and `docs/macos.md` for platform behavior such as APFS retained snapshots, launchd service expectations, and Full Disk Access checks.

### Scanner

- **Recognize bare in-tree `.rch-target/` as a first-class rch artifact pattern.** Previously the bare directory names (without a per-job suffix) only hit the generic suffix rules — `target-suffix` (`Suffix("-target")`, 0.88) for the hyphen variants and `underscore-target-suffix` (`Suffix("_target")`, 0.92) for the underscore variants — so they inherited moderate confidence. Stats grouping in `extract_pattern_label` was also lossy: `.rch-target`/`rch-target` landed in the generic `*-target` bucket while `.rch_target`/`rch_target` fell through to the catch-all `unknown` bucket (the existing `*-target` and prefix-based rch checks didn't cover them). Adds four explicit `Exact` patterns — `.rch-target` (0.95), `.rch_target` (0.94), `rch-target` (0.93), `rch_target` (0.93) — with confidences set above BOTH conflicting suffix matchers so `classify()` picks them deterministically. Updates `extract_pattern_label` to group all four with their per-job siblings under `rch_target_*`.

### Daemon

- **In-tree `.rch-target/` dirs now bypass the tmp-only path gate during Orange/Red pressure.** A 117 GB `.rch-target/` under `/data/projects/franken_engine/...` left vmi1167313 stuck at 100% disk because (a) the directory wasn't under `/tmp`/`/data/tmp`, and (b) its mtime was bumped continuously by active rch builds — so the age veto fired forever. `should_fast_track_temp_age` now consults a new `is_named_in_tree_rch_target()` helper that whitelists the four bare rch patterns added above, letting the age fast-track apply to in-tree project mounts as well. The open-file check in the executor remains the real safety net for in-flight builds.

### Tests

- Adds 7 tests covering the new behavior end-to-end: classification of all 4 bare variants, pattern-label grouping, fast-track under Red pressure outside `/tmp`, no fast-track below Orange, and the negative case (a generic `target-suffix` match in-tree must NOT fast-track).
- Adds a static changelog coverage test for the macOS examples above so future release-note edits keep the concrete Xcode, Time Machine, Electron-cache, release-work, documentation, and Full Disk Access operator details.

---

## [v0.4.6] -- 2026-05-02 **[release]**

Tag: [`v0.4.6`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.6) | Compare: [`v0.4.5...v0.4.6`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.5...v0.4.6)

Fresh-eyes review of the v0.4.5 incident-fix commit caught two bugs:

### Daemon

- **Fix wrong remediation command in `[SBH-CONFIG-WARNING]` text**. The v0.4.5 message instructed operators to "Run `sbh service install`" — but no such subcommand exists. The actual command is `sudo sbh install --systemd --auto`. Anyone hitting the warning would have been sent on a wild goose chase. Updated to reference the real subcommand for both system- and user-scope installs.

### Tests

- **`deletion_report_tracks_not_writable_paths` skips when running as root**. POSIX `access(W_OK)` always succeeds for root regardless of mode bits, so `chmod 555` doesn't actually deny write — the assertion `report.items_skipped == 1` would fail. CI runs as non-root so the test still exercises the path; on root-owned shells it skips cleanly.

---

## [v0.4.5] -- 2026-04-30 **[release]**

Tag: [`v0.4.5`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.5) | Compare: [`v0.4.4...v0.4.5`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.4...v0.4.5)

Three independent bugs combined to let `ts1` (a 1.9 TB build host) silently hit 100% disk on 2026-04-30. SBH's daemon was running, scanning, and finding candidates — but every delete was failing with `NotWritable`, the scanner was timing out before enumerating the giant directories, the dampener refused to retry recently-deleted paths even as pressure climbed, and pressure tracking missed the root mount entirely. This release fixes all four root causes, surfaces the misconfiguration as an actionable warning, and ships safer defaults.

### Daemon

- **Surface `NotWritable` skips as a single actionable `[SBH-CONFIG-WARNING]`** instead of one log line per candidate. When the systemd unit's `ProtectSystem=strict` + `ReadWritePaths=` whitelist excludes a scanner root, every delete fails silently. The warning is rate-limited to once per hour per executor and includes concrete remediation (re-run `sudo sbh install --systemd --auto` or strip `ProtectSystem=strict`). Adds `not_writable_paths` to `DeletionReport`.
- **Repeat-deletion dampener now also bypasses on imminent danger** (urgency ≥ 0.85), not just at Red pressure. On TBs of disk under high build throughput, free space can drop from Yellow (14% free) to Critical (~0%) in a single poll interval, skipping Red entirely. The predictive controller's high-urgency signal now triggers the bypass — the dampener no longer sits idle while disk fills.
- **`check_pressure()` always includes `/` alongside configured `scanner.root_paths`**. When a user configured `root_paths = ["/tmp", "/data/tmp", "/data/projects"]`, the daemon stopped monitoring `/` directly. If those subdirs don't drive pressure (e.g. `/tmp` is tmpfs), the root mount could fill silently. Per-mount dedup makes this free when `/` is already implied.

### Scanner

- **Default `scan_time_budget_secs` raised from 300 → 900**. On agent-swarm hosts, `/data/tmp` can hold 10K–48K stale test artifacts (frankenlibc/fr_live_oracle fixtures, beads_mem temp DBs, etc). 300s let the scanner enumerate ~3% of such directories before aborting, so the actual disk hogs were never identified as candidates.

### Installer / Service

- **`default_read_write_paths` now probes for `/data` and `/data/tmp`** (only adds them if the directory exists, so unit doesn't break on hosts without `/data`). Universal on the agent-fleet machines this tool was built for.
- Auto-detect release asset format (raw binary vs tar.xz) so the installer works regardless of how the release was packaged ([`9a5782a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9a5782adeb50cbe268863e6076e92dd753f6db07))

### Tests

- Two new dampener tests: `repeat_dampening_high_urgency_bypasses_at_yellow` (regression) and `repeat_dampening_low_urgency_at_yellow_still_dampens` (sanity).
- New `deletion_report_tracks_not_writable_paths` test verifies the new bucket on Unix hosts (uses `chmod 555` on a tempdir parent).

---

## [v0.4.4] -- 2026-04-18 **[release]**

Tag: [`v0.4.4`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.4) | Compare: [`v0.4.3...v0.4.4`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.3...v0.4.4)

### Installer

- systemd's ignore-error prefix (`ExecStart=-/usr/local/bin/sbh`) is parsed to the binary path, and the user-scope error path reports correctly ([`7225f38`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7225f38e3fdcdc70cd3ecb3b695f72c7df1073a8)).
- After a `--user` install, a system unit whose `ExecStart` points at a different binary is detected and synced, since most fleet machines run the system unit at `/usr/local/bin/sbh`; adds a rustfmt pre-commit hook ([`9a446b9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9a446b90e512c002b69b98184ce82a7e0837326b)).

---

## [v0.4.3] -- 2026-04-16 **[release]**

Tag: [`v0.4.3`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.3) | Compare: [`v0.4.2...v0.4.3`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.2...v0.4.3)

### Scanner

- Structural rescue uses graduated confidence: 0.75 with three or more cargo markers (`.fingerprint`, `deps`, `incremental`, `build`) versus 0.55 for fewer, and `.rch-target-` is a recognized pattern ([`6323bd8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6323bd8deb709bf719b2c1909a1832d861c636ae)).
- `cmd_result_to_artifact` is gated behind the `tui` feature ([`0e3506b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0e3506b0ce0743173bd431501398ab0496d4027f)); the alternate `target-local/` cargo target directory is ignored ([`a99cfd6`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a99cfd61720fc0ad5d8b6db7e29b3fc8c08f5ddb)).

---

## [v0.4.2] -- 2026-04-07 **[release]**

Tag: [`v0.4.2`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.2) | Compare: [`v0.4.1...v0.4.2`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.1...v0.4.2)

First published release after the v0.3.x series; v0.4.0 and v0.4.1 were tagged only.

- `x86_64-apple-darwin` builds on `macos-13` (Intel), since `macos-latest` became ARM64; `fail-fast: false` so one target's failure no longer cancels the others ([`e50bac0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e50bac0324840e9bf38d49cfc6ea46a563617d23)).

---

## [v0.3.17] -- 2026-04-01 **[release]**

Tag: [`v0.3.17`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.3.17) | Compare: [`v0.3.16...v0.3.17`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.3.16...v0.3.17)

### Installer

- The installer hardcoded `.tar.xz`, but v0.2.8+ shipped raw binaries. It now probes the GitHub API for the actual asset format, handles both, and falls back to `cargo install` when no artifacts exist (closes #8) ([`9a5782a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9a5782adeb50cbe268863e6076e92dd753f6db07)).
- The `SHA256SUMS.txt` lookup matches the asset name as an exact field so `sbh-linux-x86_64` cannot match `sbh-linux-x86_64-musl` ([`0367ca3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0367ca3a89d20b75e9995ecd8afa755aee8135fc)).
- The nightly toolchain is unpinned to rolling latest for this verification release ([`2e7d05c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2e7d05c10da781baccc8b088862abcdff4683743)).

---

## [v0.3.16] -- 2026-03-15

Tag: [`v0.3.16`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.3.16) | Compare: [`v0.3.15...v0.3.16`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.3.15...v0.3.16)

This tag has no corresponding GitHub Release. It decouples the CI release pipeline from the quality gate so releases are no longer blocked by unrelated gate failures.

### CI / Build

- Decouple release builds from quality gate ([`44f26a4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/44f26a40792268ad6e40148bd5d36a90fc7968c9))
- Bump version to 0.3.16 for release ([`0d85778`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0d8577845bb2bb69ee2de8c23d3343123b6b544d))

---

## [v0.3.15] -- 2026-03-12

Tag: [`v0.3.15`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.3.15) | Compare: [`v0.2.8...v0.3.15`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.8...v0.3.15)

This tag has no corresponding GitHub Release. It covers all development from v0.2.8 through v0.3.15 -- a rapid series of production-tuning point releases (v0.3.0 through v0.3.15) that were not individually published. Version numbers v0.3.6 and v0.3.9 were skipped. The intermediate version bumps are noted in subsection headers below.

### Prediction Engine (v0.3.0)

- **Burst detection in EWMA rate estimator**: two-factor burst detection (rate acceleration + magnitude) prevents the predictor from extrapolating transient spikes into false exhaustion forecasts ([`6516579`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6516579b58ce5496e72a1aea0b390840b56c0b06), [`e00c4e3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e00c4e3ee36cd757c148a316d8dff1399b97425e))
- **Prediction scorecard**: tracks prediction accuracy over time, solving the self-defeating prophecy problem where successful interventions make the predictor look wrong ([`c0dcc23`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c0dcc239a14e36a6d82f3b20be81fb96037303c1))
- **Burst-aware prediction gating**: predictions during detected bursts are suppressed or confidence-degraded ([`392a250`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/392a250ce0c4b9e2c08b96b45bc4fbf276719b8d))
- Move `burst_min_confidence` to `PredictionConfig` for cleaner configuration hierarchy ([`061e33d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/061e33dba15ca2203a284c153d97160a29a6c82e))
- Make `CalibrationBreach` advisory-only, lower escalation threshold to Yellow ([`7f121e5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7f121e50493d5d86342338ef3ee1d4a1a3b76ec9))
- Exclude TUI feature from CI/release builds and enable `workflow_call` ([`61efc64`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/61efc6425268ef5ec66aae9099266403eddb885e))

### Production Stability (v0.3.1)

- **False-alarm suppression**: daemon no longer fires notifications or escalates policy during genuinely idle periods ([`120a5b9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/120a5b9555a5d49aa14f64586575decb59917fc7))
- Scan timeout tracking and circuit breaker backoff log ordering fix ([`55857bf`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/55857bf9a1c3c1fdd02337c38b1ffc034faec6c1))
- Operational improvements for scan efficiency ([`57e8bf5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/57e8bf54785dc19359a2993842b16784871b88db))
- Add missing `reason` field in predictive policy and fix boundary condition ([`4f18448`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/4f1844899e3b9015f04cf6b8a7d5fe2309460c0c))
- Regression test for green-pressure fallback recovery ([`194fce3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/194fce30555d56469476388f092f4bee8835362c))

### Calibration Guard Hardening (v0.3.2)

- Suppress calibration breach log spam and guard trigger deadlock ([`161ac4a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/161ac4a102ffd6b595974b87151f13dd795645de))

### Predictive Warning Gates (v0.3.3)

Five incremental fixes to prevent the predictive warning system from triggering false alarms on healthy disks:

- Implied-rate sanity gate + breach log suppression ([`b35eabc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b35eabcd135da3a39534c0928e2cd9d4c3418094))
- Hard gate for predictions showing >50% free space ([`9cc27a1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9cc27a1f551732579714bdc4585d333a8a43a44d))
- Persist `recalibration_count` across clean windows ([`e07c6d4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e07c6d4f98e1553bfcf8e793371d2fdb717fe63c))
- Move hard gate before burst-aware path ([`5c2553d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5c2553d7836f6b145b9efbfe3cbb1c42bf891e55))
- Gate `check_predictive_warning` on predictive policy result ([`a052990`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a052990a42a1ceb9c0703ff0a5da9f0f46e30be6))

### Burst Detection + Guard (v0.3.4)

- **MAD-based burst detection**: uses Median Absolute Deviation instead of standard deviation for robust outlier identification ([`ded16b5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ded16b561b86abd8aefb7b157add63d1a488ecb4))
- Burst-aware guard with median-rate cross-check to prevent false guard triggers during legitimate activity spikes

### Decision-Theoretic Guard (v0.3.5)

- **Multi-level PressureLevel enum**: replaces boolean `pressure_is_green` with Green/Yellow/Orange/Red/Critical levels for fine-grained policy scaling ([`7e5dfe2`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7e5dfe2a2f8dd27fdbc23b63035f622c28be5eca))
- Decision-theoretic guard override breaks policy rejection deadlock where the guard penalty prevents all deletions even under rising pressure ([`647c574`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/647c574e7388595755eb5cc779ee4b56bd9ec869))
- Rate-limit guard observations to prevent high-frequency tick flooding ([`00e2f78`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/00e2f78a33d2a68093ae13854c150e57d3f85209))

### Yellow Pressure Fixes (v0.3.7 / v0.3.8)

- Fix Yellow-pressure rejection deadlock and suppress Green false alarms ([`d969599`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d96959981dbcf15edad91fcb8bf9f3dc2246aeb4))
- Extend prediction and guard-trigger suppression to Yellow pressure ([`dce72c6`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/dce72c625e812bb5ecf64209dae6cf1b0ec7d304))
- Reduce guard penalty deadlock at Yellow pressure and suppress false alarm notifications ([`a00c77b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a00c77ba66138c6e73c7e0d339bdba8d5a79e86b))
- Tune guard penalty scaling, suppress Green-pressure predictions, reduce log noise ([`97df2d0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/97df2d020aaa366458f271afaa95f76bfad1c125))

### Calibration + Diagnostics (v0.3.10 -- v0.3.12)

- **Directional calibration guard**: only triggers on predictions in the dangerous direction, ignoring benign miscalibrations ([`0e150dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0e150ddc5770715ae2989722941f4bcbe0b6a0f2))
- Widen idle noise threshold and bound `rate_danger_ratio` denominator to prevent division-by-near-zero ([`17bc885`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/17bc88598f0606fa0aa61e18541b6c550bc450bc))
- Double `min_observations` to 60 and fix scanner candidate count reporting ([`a188332`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a1883327a823467b512503780698c5822f8d841b))
- Reduce log noise and improve e-process penalty scaling ([`181518d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/181518da26887575f5631be271977d134d8d19c8))

### Scanner Hardening (v0.3.13 -- v0.3.15)

- Suppress `HOME`-not-set warning under systemd where `$HOME` may be unset ([`33a973a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/33a973a2e6d7b45455f9beb638bf947b870b5175))
- **Scanner never treats git project roots as deletion candidates**: directories containing `.git` are unconditionally protected regardless of scoring ([`bc15173`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bc1517363c276879ec65a9399bf7dae7ebbec919))
- Add Claude session cache pattern (`~/.claude/`) and improve deletion diagnostics ([`582f365`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/582f3658a4eff7c0ccc6e41c4a8068296bd5c3dd))
- **Depth-3 artifact scanning**: walker descends up to 3 levels into directories for pattern matching with breakdown logging ([`ea8e5c0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ea8e5c00d6c7039478a679a5367f3567449cc6d3))
- Optimize git directory detection cache and suppress cross-platform dead-code warnings ([`75b3716`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/75b3716fe7b27f6cb3b20aa205d8dfd07c0c3698))
- **Heartbeat, cancellation, and backpressure in directory walker**: prevents unbounded memory growth during large scans and allows clean daemon shutdown ([`9c3ba84`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9c3ba84508d090dc2388faa379a2058180fba8cc))

---

## [v0.2.8] -- 2026-03-01 **[release]**

Tag: [`v0.2.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.2.8) | Compare: [`v0.2.1...v0.2.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.1...v0.2.8)

Critical production fix release. The daemon was becoming non-functional on most deployed machines due to a cascade of safety mechanisms triggering during green pressure (plenty of free disk space), which paradoxically blocked cleanup when pressure eventually rose.

Version numbers v0.2.2 through v0.2.7 were skipped; development proceeded directly from v0.2.1 to v0.2.8.

### Policy Engine

- **Green-pressure suppression**: guard-triggered FallbackSafe entries suppressed when disk pressure is green -- miscalibrated predictions are harmless when no deletions would occur ([`474f700`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/474f7009694c7c33dc25b47bed9a820c74174e4b))
- **FallbackSafe deadlock broken**: emergency escalation to Enforce mode with grace period when FallbackSafe has persisted too long under sustained pressure ([`8ddddb0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8ddddb07651a40f70b930cbe3c54a85afebeaecf), [`103957e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/103957eb843c3ad61caa2c8f40103880f53446a3), [`006ef34`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/006ef342f947b35bb6baacc7c94ff750a9ff1727))
- **Anti-thrash cooldown**: rapid mode oscillation (canary/FallbackSafe) dampened with minimum dwell times ([`82f9d9d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/82f9d9d122ec4a00d8b4b4bf566d4949cc946a2d))
- Canary budget exhaustion pauses deletions until next hour instead of locking down the entire engine ([`82f9d9d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/82f9d9d122ec4a00d8b4b4bf566d4949cc946a2d))

### Scanner + Patterns

- Recognize `rch_target_*`, `rch-target-*`, and `target_codex*` build artifact directories from remote compilation and Codex agents ([`bf03a78`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bf03a782c1ca681ce8cf775989366e5685a5f2f1))
- Add `/data/tmp` and `/var/tmp` to default scan root paths ([`1f706dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/1f706dd324809a6baca54a7ebe28ffcf2ae41aeb))
- Configurable `scan_time_budget_secs` (default doubled from 60s to 120s) ([`1f706dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/1f706dd324809a6baca54a7ebe28ffcf2ae41aeb))

### Daemon

- **Zram false-positive fix**: high zram usage with plenty of free RAM is normal compressed-memory behavior, not disk thrashing ([`9b81294`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9b81294b8213f772574eca7fc2ca45a7c5f0e66f))
- Correct swap thrash detection inversion and add prediction jitter confidence tracking ([`7999715`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7999715a91de716a612b529232af539470615cb2))
- Cap predictive warning severity by confidence level -- 1% confidence no longer triggers CRIT ([`3130ce1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3130ce1cf3d843210a400baf4626ecd20f38ae86))
- Rate-limit scanner saturation messages to once per 60 seconds ([`9b81294`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9b81294b8213f772574eca7fc2ca45a7c5f0e66f))

### CLI

- **`sbh log` subcommand**: read and tail the JSONL event log with `--follow` and `--type` filtering ([`9e46a58`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e46a586aadf5cca5c2d15e19e0fd0870c9ce616))
- Cross-user daemon detection via systemd/process scan when config paths differ between root daemon and non-root CLI user ([`9e46a58`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e46a586aadf5cca5c2d15e19e0fd0870c9ce616))

### Platform + Service Management

- Gate `--systemd`/`--launchd` by platform before ballast provisioning ([`c49ec5d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c49ec5d81dbca1708ece01ca4f55c534cf4a3f72))
- Require root for system-scope systemd with clear guidance ([`14e4596`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/14e45966217579706c6f01f491c92a434c7fe2b2))
- Auto-detect non-root on macOS and use user-scope launchd ([`3615ed5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3615ed5444e435fef2f7b111ef165ed70e17e6e5))
- Use `root:wheel` for chown recommendation on macOS ([`9d37d47`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9d37d47ac5b0e081cf83acd540c03ce9a6d2b076))

### TUI

- TUI gated behind optional feature flag + walker cancellation token ([`97ea033`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/97ea03311dfd57446039a77875770bea08ece7ff))
- Signal interception for TUI terminal session ([`39ea6a0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/39ea6a046e3345ac511cf3d17bae3840f113c66b))
- Explicit lifetime annotations on TUI styled rendering functions ([`134833c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/134833c2422f217e09e51519941e728da06e588d))
- Switch ftui dependency from local paths to crates.io v0.2.1 ([`f41259c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f41259c86d5c012cb1efc38d9123baab6b6c04f2))

### Licensing

- License updated to MIT with OpenAI/Anthropic Rider ([`658fe36`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/658fe363b81fcde40e3ad8ad4e6799238898aa0c))

---

## [v0.2.1] -- 2026-02-17 **[release]**

Tag: [`v0.2.1`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.2.1) | Compare: [`v0.2.0...v0.2.1`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.0...v0.2.1)

### Predictive Cleanup

- **Predictive cleanup policy**: per-event throttling in the daemon prevents redundant scans ([`fb601b3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fb601b369d11aa1014af3fa8ce451388e4bbe13d))
- Suppress bogus predictions and fix wrong mount path in state/logs ([`28e0c4e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/28e0c4eab8ea56c161e321e5072fc41d86300421))

### TUI

- **TUI rendering overhaul**: enhanced theme, widget styling, and dashboard rendering ([`b5d7794`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b5d77940bce1f19e0519825b388ad4619859bf3e))

### Agent Integration

- Agent skill definition (`.claude/skills/sbh`) for AI agent integration ([`ddd5045`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ddd5045c5f4838e0982443f8637db33108a73f35))

### Bug Fixes

- Resolve clippy lints, compilation errors, and swap-thrash logic bug ([`fde0f2b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fde0f2bc7120c9118bd55569355938ad84328616))

### Tests

- Merkle index integration and symlink loop reproduction tests ([`a7eefac`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a7eefac4c8c320ddddcc68ee854a4df6b8b1bfe6))

---

## [v0.2.0] -- 2026-02-16 **[release]**

Tag: [`v0.2.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.2.0) | Compare: [`v0.1.0...v0.2.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.1.0...v0.2.0)

Massive release adding the interactive TUI dashboard, extensive hardening from deep code audits, cross-platform fixes, and a full test suite overhaul. 170+ commits between v0.1.0 and v0.2.0.

### TUI Dashboard

- **Full interactive TUI** with 7 screens: Overview cockpit, Timeline, Explainability, Scan Candidates, Ballast Operations, LogSearch, and Diagnostics ([`429c1a3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/429c1a3de91a45015602ee997c18f2ee90c1ceee), [`dd8a8c1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/dd8a8c1d57a3529723b89c5cb7f8e8628a5257e1), [`40a219d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/40a219d6876e41d2e6885772a2193caaa1cc7dca), [`f1b7dfc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f1b7dfc3b38bc3aec561476d7df0c29456ad914d), [`054ed6a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/054ed6ad5fd33faae94f7cb833c759f7b0198a7a))
- TUI compiled unconditionally at the time; it has since become the optional `tui` cargo feature, off by default ([`25388e8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/25388e80cc4de24ec24ca43629695ff5bf123aaf))
- Migrated from crossterm to ftui with layout engine, theme system, and rich overview rendering ([`4cc1010`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/4cc1010e1fb7513c71f20bcfc295270bc4665c14))
- Panic-safe terminal guard prevents TUI crashes from corrupting the terminal ([`c0d305a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c0d305adf6a52358f08418ae38dcd1a2b7c142dd))
- Frame-based rendering pipeline ([`0d0b5d2`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0d0b5d2c3ee2f147c6ab9f8068d42e9733c4b3f8))
- Guard against zero-width terminal panics ([`b9f118d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b9f118dbd5f1f7790876f1e90a2e9f37f5f10576))
- Synthesize ballast volumes from daemon state for inventory display ([`daeac2c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/daeac2c4f795e3378b61fd9506e180f657554b3d))
- Interactive pane navigation with mouse support ([`429c1a3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/429c1a3de91a45015602ee997c18f2ee90c1ceee))
- Schema-shielding layer for dashboard data models ([`373803c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/373803c933ef097c51343744c8e105b724795502))
- User preferences model for dashboard ([`bf54cf8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bf54cf8905f7fdc90e8cc718b221d259125b3716))
- Incident workflow shortcuts with playbook overlay ([`167d46c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/167d46c78bda169e739054d9aaa819ddf5d9863f))
- Responsive layout builders for all dashboard screens ([`2de84f3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2de84f325205eee5956afbe6f5a8f5233659e60c))
- Command palette and breadcrumb rendering ([`c4a41e4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c4a41e4abb81eb5ae02503b14c527560b1fd8d04))

### Scanner + Scoring

- **Production 0-deletion bug fixed**: rebalanced Bayesian decision thresholds that caused no deletions across the entire fleet ([`d6bbd81`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d6bbd814f8c4c47ed66e916b481f34d15d5914b6), [`e5987f9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e5987f909fb8d4172c33614bcbfb4b16c55bbc0f))
- **Queue starvation fix**: 15K entries/0.5s vs 17/60s ([`3bb9232`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3bb9232de1a3cb7cf848589abf54ca0bae32d573))
- Cap per-dir iteration at 2000 entries + deferred child dispatch ([`fd1e197`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fd1e19799bdad38805d36d4f471394a20949e32c))
- Parallelize `/proc` scan, optimize walker hot path ([`96ed3da`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/96ed3dad9c0d814f53b5d74d422835c509c2db5c))
- Reorder location checks so `.tmp_` and `.target` match before generic `/target` ([`f2b0b7d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f2b0b7d9488b67651bac02b8009cb882d7567c3d))
- Consolidate and simplify builtin artifact patterns ([`5e93e15`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5e93e158b81abe3eb974b95a6febc62c0d03d069))
- Case-insensitive pattern matching ([`9e789f3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e789f37f44b086b27bba5651c4a8d9eca487175))
- Defer open-file checks to post-scoring for faster scan startup ([`dd2ccc2`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/dd2ccc2ff9c00e856d25aa9acee712a5c515a445))
- Populate per-root scan duration for VOI scheduler IO cost ([`ae6808d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ae6808dda8b1f0283922644c6252b68ef4c3847d))
- Improve pattern confidence scores and predictive warning escalation ([`db2acc4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/db2acc44022225ed3e1534237eec6e536c572028))
- Memory/swap diagnostics and expanded artifact detection patterns ([`139a70d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/139a70d07a6a9260dd9b4c97364a92a1424edc27))

### Daemon + Policy Engine

- **Scanner deadlock resolved** that caused 0 scans on all production machines ([`7d87a75`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7d87a75620eb204de17ce5302209d2bffd0ac120))
- Per-mount release tracking, incremental release logic, and project-root protection ([`ea36631`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ea36631b07a312aff3d4aac5ff614e96893ea1d5))
- Gradual ballast replenishment and cumulative release targets ([`2b1309e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2b1309e9d79dd44e7693a81514a5a7c6a10ba91c))
- Repeat-deletion dampening to break agent rebuild loops ([`ffb7fdf`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ffb7fdf2f3a926c17c3b31ea89b491f1346cae64))
- Swap-thrash detection and temp artifact fast-track deletion under pressure ([`301543e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/301543e07ea7ec56452c58ca3cd1b93b9c47a9b0))
- PID slow-decay hysteresis steps one level at a time instead of jumping to raw ([`e3b8087`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e3b8087654026cf7b0446b45fb4fe6aad20ca0cc))
- Propagate `poll_interval`, prediction disable, and notification config on SIGHUP reload ([`f6124d8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f6124d8812a12bcbea30440628a1c99c8dcdc20d))
- Trigger root filesystem scan on special location pressure ([`fd683b3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fd683b30f4fad79e4be4d5a4642e51f26064e356))
- Production reclaim failure resolved ([`c289bca`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c289bcafbc55650f55d263ea28157621a06f6247))
- Constructor sets correct `pre_fallback_mode` and `fallback_reason` for kill_switch ([`fbd3070`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fbd30704d8fce980aadfdff040e7297516f9851f))

### Security + Hardening

- Hyphen injection guard, ancestor-set open-file detection, composite index ([`5e0a2db`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5e0a2dbd15fef1027b5a0812ca3f3aacb9721f80))
- Security hardening: ballast release rework, walker streaming, idiomatic Rust modernization ([`745d119`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/745d1192874d95946b2c5a30abf1f60f20721cd7))
- Multi-volume ballast, inode-based open-file detection, Cow allocation reduction ([`31b165c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/31b165cf3628cfdec3764f8b1350a495843ef90a))
- Correct `glob_to_regex` for `**/` pattern boundary matching ([`817028c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/817028c2bda2b5c7b686f708f266868c97ebd40d))
- VOI config extraction, decision record `effective_action` ([`9e789f3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e789f37f44b086b27bba5651c4a8d9eca487175))
- Design-level hardening from deep audit: notification throttling, atomic config writes, PID derivative low-pass filter ([`c67fc37`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c67fc37aa0a9eaec42516b43b4765571211b0cb1))
- Handle JSONC block comments in root-brace parser ([`e39e9d1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e39e9d1ba1f6d39f05e9def65c3967cb420de0d7))

### CLI

- Cap help text width at 100 columns ([`a18b8fd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a18b8fd1f565cf44d816fa16788259d86d1383fb))
- Cosign v2 identity flags + `is_writable` parent dir check ([`4ca87af`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/4ca87afb3019aa57dd5521c9ea9cbc48f6697835))
- Implement actual curl-based asset download and robust build-dir creation ([`14f0afc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/14f0afc2176b58e19329232d33638a7f90f1e982))
- 6 bugs from deep audit: mount check, zombies, template, deprecated keys, `bytes_freed`, writable ([`0306e6b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0306e6bb87f73d9ff8bf05221c8b132126052a33))

### Logging

- Circuit-breaker logic improvements and rotation resilience ([`80708cd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/80708cd945eb9fe65adf667b44b1038a91bb7058))
- Failure-injection test suites for self_monitor and JSONL logger ([`11bfb22`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/11bfb22ad843b3bcb3c2e4e892f57168f19d357d))
- `.tmp_target` pattern, shutdown sentinel, auto_vacuum conversion ([`a50adb8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a50adb85d8cdb86a97f420e887a27c0de295fe90))

### Platform

- Stats module: push pattern extraction into SQLite custom function for server-side aggregation ([`caed1d1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/caed1d1057e0f41fce74978e856945bb483df1cb))
- Backup dir fallback, UTF-8 path truncation, RateHistory div-by-zero fix ([`748283f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/748283f46a199d95d55b8a5ebef19b1dfde7abaf))
- CoW filesystem fallocate bypass + VOI budget=1 fix ([`2e00c1a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2e00c1a8d14942a6d9dcd72f6341a7ed16939e36))

### Tests

Extensive test suite expansion as part of the TUI dashboard rollout:

- 37 snapshot/golden tests for dashboard screens ([`af667b5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/af667b5d5ca7f77a3b75ef84556903b627a89463))
- 44 fallback/rollback verification tests ([`0b44620`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0b4462097b50ef82df5e817fca90a5c5fd30a986))
- 31 integration tests for dashboard CLI and state-file contract ([`f4978e8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f4978e833e2362cd28126321a8ee4fe6dac2d59b))
- 22 unit tests with 10 duplicate test name fixes ([`5343369`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/53433691fe18b72129e34c6b493d34773db03221))
- 8 property tests for scheduler/overlay/history/detail invariants ([`7088195`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/708819583fa0b70dbd02dfd65d4f516795508924))
- Property-based tests for reducer invariants ([`ae3925a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ae3925a89e0c45a145d551210d0c23301ef6252c))
- Stress/performance test suite ([`81557a6`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/81557a66d7e6f854e9e9f4eaf7b1088579cc11d9))
- Deterministic replay regression suite ([`5491318`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/549131863426935ddf18ddf7dc1065901e2aa43e))
- Parity harness covering all 18 contracts ([`43f24ae`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/43f24ae70dcf8e22779d4826b7c8879d241f09b1))
- 9 comprehensive e2e dashboard test cases ([`a3f093a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a3f093abd7a371a6f55d2b33b7c045f5fc4b57cc))
- Scenario-driven dashboard e2e drills ([`ef0c42d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ef0c42d4c43c03572038cfc582e9b44abecccd46))
- Operator workflow benchmark validation ([`0ade1bf`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0ade1bf135e9e24dd8221ede8f3cf1932e5f4862))

---

## [v0.1.0] -- 2026-02-15 **[release]**

Tag: [`v0.1.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.1.0) | Compare: [`91a5e28...v0.1.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/91a5e28...v0.1.0)

Initial release of Storage Ballast Helper -- a cross-platform disk-pressure defense system for AI coding workloads. 60+ commits from repository initialization to first tagged release.

### Core Monitoring

- **Continuous disk pressure monitoring** with EWMA forecasting and PID controller
- **Three-pronged defense**: ballast file pools, artifact scanner, special location monitor
- **Predictive cleanup** with configurable confidence thresholds
- Self-monitoring with health integration ([`76ae80c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/76ae80c186af5117db6b29e69f60138f1f041a0c))

### Scoring + Safety

- **Multi-factor scoring engine** for safe artifact cleanup with deterministic ranking
- **Decision-plane policy engine** with shadow/canary/enforce modes and evidence ledger ([`52a0877`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/52a087791b4eb606bfcc132fa80e4eb86c9f24c0))
- **Hard safety vetoes**: `.git` directories, protected paths, too-recent files, open files
- Canonicalize paths in protect/unprotect to prevent symlink traversal ([`b4e9412`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b4e9412060c70c3a06eab47e92107a8c8f14e80b))
- Guard ballast size calculation against integer overflow ([`5ef86fe`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5ef86fe03eb424e1dd2af5c944c53fcafabd28cd))
- 0o600 permissions on ballast files, log files, state files, merkle checkpoints ([`b7ebeb4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b7ebeb4eb7b2499dd6c2e96e15daf0ac30a6ba5e), [`848211d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/848211d80e3adf5a7dae8dcdb4ebd26eaab58ac8), [`49a01f8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/49a01f8badf1e4e118e5af04a7a5994156e1e3ee), [`fe765c9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fe765c98a7ecda457eb18e5d5b7f1cc4afb3f316))
- Reject ballast `file_size_bytes` below 4096-byte header size ([`07654a4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/07654a4a7ff1e165d7da08dcde4e52d3e2ffdc42))
- Validate protected_paths glob patterns at config load time ([`6d9813e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6d9813e8c3bc33c3373bf86a5dce57f1d4bd4d87))

### CLI Commands

- `sbh check` -- inspect pressure and forecast
- `sbh scan` -- run cleanup scan and review candidates
- `sbh clean` -- execute safe cleanup with confirmation
- `sbh emergency` -- zero-write emergency recovery mode
- `sbh ballast provision` / `release` / `replenish` / `verify` -- per-volume ballast management
- `sbh protect` / `unprotect` -- project protection via `.sbh-protect` markers
- `sbh explain` -- show decision evidence and rationale
- `sbh stats` -- storage trend statistics
- `sbh blame` -- identify top space consumers
- `sbh dashboard` -- text-mode dashboard with pressure gauges and sparklines ([`c5992fc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c5992fc4e56efe0a3bf73a3b09e448b40dc8eb90))
- `sbh install` / `uninstall` -- systemd/launchd service integration
- `sbh setup` / `bootstrap` -- migration self-healing and VOI scan scheduler ([`d4da084`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d4da08410c3bb038537ec3466b93d47d4a317b2d))
- `sbh tune` -- tuning recommendations
- `sbh update` -- sigstore bundle verification and install/update with backup/rollback/prune ([`7f57b7f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7f57b7fa63e012027137b334b2c43ba9e5c705f9), [`6c81f3a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6c81f3ace37b1f90118c423b85d8c061edc5713d))
- Asset management and from-source build modules ([`0560d66`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0560d66de886aae15b22f88eedd7a9b890829dc2))
- Deterministic offline bundle builder with strict path-safety guards ([`e00b892`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e00b89253c6df5c6cdee753612026b1ab97bcbca))

### Daemon

- Systemd and launchd service manager integration ([`62ba3e1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/62ba3e183d0e8e9617afee1f64d429db424a0ab0))
- Coordinator for scan/cleanup/ballast orchestration ([`5f0176b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5f0176b8405cafc86c92b80d6db8ba31c2d171bd))
- Worker reporting, shared config, rendezvous channels ([`32d1fae`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/32d1fae41b2dafe76a6c2b7ed4b54281dfbe7e9b))
- Stale daemon detection, early ballast release, recursive inode scanning, predictive target floor ([`83603d7`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/83603d7be423aa3e5f17c7df1100dc5cf5fa182e))
- Poll interval validation, prediction bounds, monotonic heartbeat ([`c5e53d5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c5e53d57fc2c6f6b8f398d8c8c103a4cb3c69c4e))

### Observability

- Dual logging: SQLite + JSONL with full explainability
- Decision records with traceable evidence and rationale
- SQLite recovery mechanism and new activity event types ([`af00f9b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/af00f9bd8f74da3a9fd8a1b3e7cd37cc4fbdaa99))
- Dropped log event surfacing in state.json ([`98891e8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/98891e81d3cfa90a9379099bad3e5a2f3ce5d03e))

### Platform Abstraction

- macOS `statvfs` type mismatch fix for cross-platform builds ([`e78e3a1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e78e3a1cfaa62895a904eca82970c9e848cf8a43))
- Parse meminfo unit suffix instead of assuming kB ([`085238b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/085238b68ee469a8f299e4b711b6e88856baac77))
- Decode all octal escape sequences in mount paths ([`0156847`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/01568478042c67c655d51e01fb37e11e59c256e6))
- Windows PowerShell installer ([`3bcd099`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3bcd099c26d15956206b12ffd032f7fb933d6b48))

### Build + Safety Constraints

- `#![forbid(unsafe_code)]` in both `lib.rs` and `main.rs`
- No async runtime -- OS threads with `crossbeam-channel` and `parking_lot`
- Pedantic + nursery Clippy lints enabled project-wide
- Deterministic builds: `opt-level = "z"`, LTO, `codegen-units = 1`, `panic = "abort"`, stripped
- Linux x86_64 and macOS arm64 release artifacts

### Tests

- Decision-plane proof harness with 26 tests ([`a3eaade`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a3eaadee8d494c3b257ef8562bb1f3b0d582ca05))
- Full-pipeline integration tests ([`972ab33`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/972ab33bbe2a26109bcef01bcc9041466203869e))
- 105 unit tests across 5 installer/CLI modules ([`2c94431`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2c9443161987a5676e8e9ccaf5b693a7f4d6e3c4))
- 8 extreme-pressure stress scenarios ([`f38b96f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f38b96f01001c0e93c473c3f4d2b1cb8b0b07cc7))
- Comprehensive E2E test suite ([`85f96ea`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/85f96eaa0a4a997346821ba860acfc956e4a8c6a))
- Deep code audit fixes across scoring, deletion, PID, EWMA, PAL, bootstrap, guardrails ([`822e5ce`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/822e5ce4d01f8e21e44d2e3e5b7d86ebdeefbd0a), [`aeb873c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/aeb873c5316329e80bfb7114f31abc62f9509957))

### Repository Initialization

- Repository scaffold and source modules ([`91a5e28`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/91a5e28f315d9869b37add11caeaa9ab27cd64f7))
- Core CLI commands and scanner subsystems ([`61332bc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/61332bc4ba1a2edd8d3b2149b6c3c713bf091dc0))
- Merkle scan index ([`3bcd099`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3bcd099c26d15956206b12ffd032f7fb933d6b48))
- VOI scan scheduler ([`d4da084`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d4da08410c3bb038537ec3466b93d47d4a317b2d))
- Uninstall with safe cleanup modes ([`bf36edd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bf36eddf073a2d2fc869031796494c50097288fb))

---

## Statistics

| Metric | Value |
|--------|-------|
| Total commits | 904 (as of 2026-09-02) |
| Tags | 51 (v0.1.0 through v0.5.1) |
| GitHub Releases with assets | 28, each marked **[release]** above (`scripts/changelog_check.sh --all` audits this) |
| GitHub Releases without assets | 1 (v0.4.23) |
| Tags without GitHub Releases | 22 (v0.3.15, v0.3.16, v0.3.18, v0.3.19, v0.4.0, v0.4.1, v0.4.7, v0.4.9--v0.4.13, v0.4.15--v0.4.21, v0.4.26, v0.4.34, v0.4.35) |
| Development period | 2026-02-14 to present |
| Intermediate point releases (in-tree only) | v0.3.0 through v0.3.14; v0.4.31 |
| Skipped version numbers | v0.2.2--v0.2.7, v0.3.6, v0.3.9 |

[v0.3.16]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.3.15...v0.3.16
[v0.3.15]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.8...v0.3.15
[v0.2.8]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.1...v0.2.8
[v0.2.1]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.1.0
