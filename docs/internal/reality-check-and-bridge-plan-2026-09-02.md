# Reality Check and Bridge Plan — 2026-09-02

Status: living document (revised in place). Source of truth for the follow-up
beads created from it; once those beads exist they carry all of this context.
See also the independent, same-day analysis `docs/internal/reality-check-2026-09-01.md`
and section 5b for how the two bead trees were consolidated.

## 0. Method and evidence base

- Read in full: `README.md`, `AGENTS.md`, `docs/scanner-redesign-event-driven.md`,
  `docs/post-rollout-monitoring-and-handoff.md`,
  `docs/internal/macos-parity-completion-audit.md`, `CHANGELOG.md` (head),
  `SESSION_REPORT_EXPLORATION.md`, `Cargo.toml`.
- Seven read-only subsystem audits (daemon/control loop, scanner/safety,
  ballast/logging/config, CLI wiring, install/update/service/release, macOS
  parity, tests/TUI/gates), each verifying README claims against code with
  file:line evidence.
- Host inspection of the operator's primary Linux workstation (the one this
  repo lives on): systemd unit, config, ballast dir, state file, 300 MB of
  daemon activity logs (JSONL + SQLite) covering 2026-06-21 → 2026-08-30.
- Shipped reality: GitHub releases v0.4.28 → v0.5.1, workflow states, the
  Homebrew tap, a byte-level inspection of the v0.5.1 macOS binaries.
- Quality gates run at HEAD `320d04d`: `cargo fmt --check` (clean),
  `cargo test --workspace` (0 failures; 1,419 lib + 122 bin + ~230
  integration), `cargo clippy --all-targets -- -D warnings` (62 errors).
- Three controlled daemon runs in a sandbox with synthetic stale / fresh /
  git-protected cargo targets.
- Beads: the tracker DB was on schema v7 with a corrupt index; it was rebuilt
  from `issues.jsonl` (418 records, zero unsynced changes lost). Counts:
  410 closed, 4 open, 3 in progress.

## 1. Executive verdict

The code base is large and mostly real: 133k lines of Rust, 2,833 tests,
almost no stubs, every major subsystem in the README has a genuine
implementation behind it. The bead tracker says 410 of 418 beads are closed.

Measured against the vision ("continuously monitors storage pressure,
predicts exhaustion, and safely reclaims space"), the shipped product does
not deliver on the operator's own machine, and several load-bearing promises
in the README describe things that do not exist in any binary a user can
obtain:

1. **The daemon does not reclaim until it is nearly too late.** With normal
   memory pressure, the default behavior matrix (`src/daemon/policy.rs`,
   `DEFAULT_BEHAVIOR_CELLS`) maps Yellow and Orange to `IdentifyOnly` with
   no ballast release. Deletion and ballast release begin only at Red
   (< 10 % free by the real defaults). At Green the daemon never scans at
   all unless the predictive policy fires. The README table that says
   "Orange: begin ballast release + cleanup" is not what the code does.
2. **On the operator's workstation the daemon is disabled by a hand-made
   kill switch** (`/etc/sbh/HOTLOOP_DISABLED`, re-created 2026-08-30 after
   fleet config sync removed it) because it spun at its CPU quota while
   unable to do anything: the root volume is at 12 % free, its ballast pool
   was never provisioned (20 % provisioning floor), and no configured
   `root_paths` entry lives on that device, so the device-affinity gate backs
   off every tick. The host has been unprotected since 2026-08-30 and
   effectively inert since at least 2026-08-20.
3. **Deletion success collapsed.** Across the retained logs the daemon
   attempted 22,652 deletions and succeeded 7,065 times (31 %); in August it
   went 0 for 844. Two thirds of failures are `NotWritable` while running as
   root, which points at the btrfs volume being read-only or ENOSPC at the
   moment sbh finally acted.
4. **`sbh explain`, `sbh bootstrap`, `sbh uninstall --dry-run/--keep-data`,
   and `sbh dashboard --start-screen` do not exist.** Decision records are
   built and discarded; `bootstrap.rs` (2,860 lines) and the 5-mode uninstall
   planner (1,246 lines) are unreachable library code.
5. **`sbh dashboard` errors on every distributed binary** ("TUI feature not
   enabled"); the `tui` feature is off in releases, the installer, Homebrew,
   and `cargo install --git`. The 150-line README dashboard section documents
   a build nobody gets.
6. **The updater cannot find current releases.** v0.5.0/v0.5.1 ship raw
   `sbh_linux_amd64`-style binaries plus `SHA256SUMS`; the Rust updater
   constructs `sbh-v<tag>-<triple>.tar.xz` and never probes. Any future
   `sbh update` on the fleet 404s. The macOS v0.5.1 binaries are ad-hoc /
   unsigned, so the macOS one-liner refuses them unless `--no-verify`.
7. **Delivery infrastructure is off.** All three GitHub workflows are
   `disabled_manually`; CI has been red at the clippy gate since 2026-08-14
   and silent since 2026-08-20; the Release workflow last succeeded for
   v0.4.28; the Homebrew tap is frozen at v0.4.28; local clippy fails with
   62 errors.
8. **The README configuration example silently misconfigures.** The loader
   has no `deny_unknown_fields`; `[monitor]`, `[logging]`, `[guardrails]`,
   `[scoring.weights]`, `[policy] mode`, `per_volume_*`, `file_size_mb` are
   all ignored. Writing `mode = "observe"` from the README leaves the daemon
   in the default `Enforce`.
9. **Observability is partly fictional.** `sbh status` reports
   `daemon_running: true` for a dead daemon (any process whose command line
   contains "sbh" and "daemon" matches); `check --predict` and the status
   "rate estimates" read a state key the daemon never writes; ballast and
   policy events are never persisted so `sbh stats` ballast figures are
   always zero; non-root `stats`/`tune`/`log` fail against a system install.
10. **No open bead covers any of the above.** The four open and three
    in-progress beads are the macOS parity epic, scanner v2 validation, a
    release-asset audit, and release engineering. Several closed beads were
    closed without their deliverable shipping (`bd-izu.2` explain command,
    `bd-2j5.21` bootstrap migration, `bd-2s9` watchdog heartbeat,
    `bd-xzt.5.3` rollout controls).

What IS working, verified: the scoring engine, protection registry, 8-point
preflight and lease system, ballast provisioning/release mechanics, notification
channels, JSONL/SQLite writers, the Linux PAL, `sbh blame`, `sbh check`,
`sbh scan`, `sbh emergency` zero-write semantics, the systemd/launchd
generators, kernel writeback tuning, the wizard, the from-source installer,
the raw-asset-aware `scripts/install.sh`, the Linux inotify-backed v2 index,
and 2,833 tests with 0 failures.

## 2. Vision checklist

Status key: WORKING · PARTIAL · STUB · UNPROVEN · MISMATCH (code differs from
the promise) · NOT_STARTED · REGRESSED · NO_BEAD (no open bead covers it).
Every row below except those in the macOS epic and scanner-v2 epic is
NO_BEAD.

### A. Core defense loop

| # | Goal | Source | Status | Evidence |
|---|------|--------|--------|----------|
| A1 | Continuous monitoring, 1 s polls | README "operator perspective" | MISMATCH | default `poll_interval_ms = 5000` (`config.rs:628`) |
| A2 | EWMA + PID predictive control | README "control loop" | PARTIAL | implemented and tested, but alpha *decreases* with burstiness (`ewma.rs:199`), setpoint is `green_min_free_pct` = 20 not 18 (`loop_main.rs:865`), Critical is `< red_min` not `red_min/2` (`pid.rs:314`), 0.70 boost applies at ≤ 15 min not 30 (`pid.rs:120-127`) |
| A3 | Predict, then act: reclaim *before* critical | README principles; AGENTS.md pressure table | MISMATCH | behavior matrix: Yellow/Orange → `IdentifyOnly`, ballast `None` at normal memory (`policy.rs:318-345`); only Red/Critical delete/release |
| A4 | Routine maintenance cleanup at Green | README PID table (Green scans at base interval) | NOT_STARTED (by design) | Green arm dispatches a scan only for predictive/fallback (`loop_main.rs:2852-2915`); sandbox: 0 scans in 60 s at Green under v1 and v2 |
| A5 | Frees space on the exact filesystem under pressure | README TL;DR | WRONG_APPROACH on mixed hosts | device-affinity gate returns for the whole tick when the pressured mount has no root_path (`loop_main.rs:2812-2839`); sandbox: 0 scans of a healthy root while `/` is Orange |
| A6 | Ballast: pre-allocated sacrificial space per volume | README | PARTIAL | provisioning refuses below 20 % free (`manager.rs:36`), so the volume that needs it most never gets a pool; host `/` pool empty (5 of 5 missing); daemon's `<mount>/.sbh/ballast` pools invisible to CLI; ballast events never logged |
| A7 | Zero-write emergency mode with Review escalation | README | WORKING | `run_emergency` (`cli_app.rs:9613-9852`), no config/log/state writes; `include_review: true` |
| A8 | Multi-factor scoring with hard vetoes | README | PARTIAL | weights and Bayesian layer as documented; age curve is monotonic (README's non-monotonic curve removed, `scoring.rs:853-867`); location tiers hardwired to `/data/projects/` (`:780-785`); 50 built-in patterns not "hundreds"; sandbox: textbook stale cargo target scores 0.65 → **Review**, never deleted |
| A9 | Eight-point preflight, circuit breaker, protection | README safety layers | PARTIAL | preflight real (`deletion.rs:595-684`) but breaker default 5 not 3 (`:76`), stowaway sacred check lives outside the executor, v2 index replay dispatches synthetic `Delete` candidates skipping score-time vetoes (`index.rs:245-283`, `loop_main.rs:4312-4333`) |
| A10 | Observe → canary → enforce with automatic fallback | README | MISMATCH | default `initial_mode = Enforce` (`policy.rs:149`); `promote()` has no caller; calibration breach advisory only; canary exhaustion never demotes; hidden FallbackSafe → Enforce escalation after 5 min at Yellow+ (`:788-823`) |
| A11 | Guardrails / e-process drift | README | WORKING | constants differ (min_obs 60, window 500, reward ln(2/3), clamp [-5, 3.5]) |
| A12 | VOI scan scheduling | README | STUB in situ | `VoiScheduler::schedule()` never called; daemon always scans all roots (`loop_main.rs:2845`) |
| A13 | Special-location monitoring | README | PARTIAL | table matches; percent-only thresholds produced 35,692 `critical` error events in 3 days on a 5.5 TB volume at 13.9 % free; no rate limit (`loop_main.rs:3271`) |
| A14 | Repeat-deletion dampening | README | WORKING | plus undocumented urgency ≥ 0.85 bypass |
| A15 | Temp artifact fast-track | README | WORKING | broader than documented |
| A16 | Daemon robustness: threads, respawn, watchdog, shutdown | README | PARTIAL | logger never respawned; `READY=1` never sent while system unit is `Type=notify` (`systemd.rs:121-127`); watchdog heartbeats disabled (no `--watchdog-sec`, `WATCHDOG_USEC` unread); no final state write on shutdown; `ShutdownCoordinator` dead code; thread health absent from `state.json` |
| A17 | Near-idle daemon (no hot loops) | scanner redesign §7 | REGRESSED on host | `/etc/sbh/HOTLOOP_DISABLED`; 33 s CPU over 5 min at Orange with nothing to do (pinned to `CPUQuota=10%`) |
| A18 | Scanner v2 event-driven, pressure-gated | `docs/scanner-redesign-event-driven.md` | PARTIAL | inotify index path is real; **default is already v2** (`config.rs:670`) while README/engine.rs say v1; fanotify stub; macOS reconciliation-only; index-replay safety gap |
| A19 | Swap-thrash detection | README | WORKING | README wording inverted (code flags swap ≥ 70 % *and* available < 8 GiB) |
| A20 | Log truncation, process I/O history, memory × disk behavior matrix | (undocumented) | WORKING | `log_truncator.rs`, `process_io_history.rs`, `policy.rs:318+` |

### B. Observability and explainability

| # | Goal | Source | Status | Evidence |
|---|------|--------|--------|----------|
| B1 | `sbh explain --id` with evidence ledger | README (6 places), AGENTS.md, installer hints | NOT_STARTED | no `Explain` command; records discarded at `loop_main.rs:5585-5589`; nothing in `src/logger` knows decisions |
| B2 | `sbh status` truthful daemon state | README | MISMATCH | `detect_daemon_running_fallback` matches any `/proc/*/cmdline` containing "sbh" and "daemon" (`cli_app.rs:7031-7070`); observed `true` with a dead daemon; `policy_mode` read from a stale file; no `memory_rss_bytes`; Linux mounts nested under `platform.darwin.apfs` |
| B3 | `sbh stats` / `sbh blame` | README | PARTIAL | non-root `stats`/`tune` fail on root-owned DB ("attempt to write a readonly database"); shipped 0.5.1 `sudo sbh stats` looks in `/root/.local/share` (fix `32f1550` unreleased); ballast/policy rows never written; `blame` WORKING via `io_history.bin` |
| B4 | Seven-screen TUI dashboard | README | NOT SHIPPED | `tui` feature off everywhere; quick-release `x` is a dead end (`update.rs:401`, no Enter arm); `--start-screen` missing; prefs file is `preferences.json`; `REDUCE_MOTION` unread; "legacy" = clear-screen `status` loop; `src/cli/dashboard.rs` dead |
| B5 | Four notification channels | README | WORKING | file channel path has no `~` expansion |
| B6 | Dual logging with degradation chain | README | PARTIAL | SQLite trips after 3 failures not 50 (`dual.rs:305`); daemon disables `/dev/shm` fallback and uses 50 MiB / 30 s (`loop_main.rs:1675-1684`) |
| B7 | `sbh log` | (undocumented) | WORKING | non-root cannot read root log |
| B8 | `sbh check --predict`, status rate estimates | README | STUB | reads `state.rates.*` which the daemon never writes; `rate_bps` hard-coded `None` (`self_monitor.rs:381`) |

### C. Install, lifecycle, distribution

| # | Goal | Source | Status | Evidence |
|---|------|--------|--------|----------|
| C1 | One-liner installer | README | WORKING (Linux) / BROKEN (macOS v0.5.1) | raw-asset probing present; macOS trust check refuses ad-hoc binary (`scripts/install.sh:570-598`) |
| C2 | Install wizard, `--auto` | README | PARTIAL | wizard does not auto-launch without config; Custom preset unselectable (`wizard.rs:466-474`) |
| C3 | Bootstrap self-healing (15 reasons, 10 actions, runs on install) | README | NOT WIRED | no `Bootstrap` command; zero callers of `bootstrap::`; only 4 of 10 actions back up first |
| C4 | `sbh update` with rollback/cache/offline | README | BROKEN vs releases | asset contract `sbh-v<tag>-<triple>.tar.xz` (`cli/mod.rs:262-270`, `update.rs:1096`); v0.5.x has only raw binaries; no sigstore bundle has ever shipped |
| C5 | Uninstall with 5 cleanup modes, dry-run, backups | README | NOT WIRED | planner unreferenced; `--purge` deletes config/data/ballast with no backup (`install.rs:402-470`); `--dry-run`/`--keep-data` are clap errors |
| C6 | Hardened systemd unit | README | PARTIAL | directives present; `ReadWritePaths` hardcoded not derived (`systemd.rs:414-431`); `Type=notify` without `READY=1`; host runs a hand-written March unit |
| C7 | launchd plist | README | WORKING | docs say ThrottleInterval 10, code 60 |
| C8 | Kernel writeback tuning | README | WORKING | read-only `sbh tune` fails for non-root because it opens the stats DB |
| C9 | Supply-chain verification | README | WORKING in code / UNPROVEN in releases | no `.sha256` sidecars or sigstore in v0.5.x; macOS arm64 ad-hoc (CodeDirectory only, flags 0x20002), amd64 unsigned |
| C10 | CI + Release + cert monitoring | README, bd-ykwh | DEAD | all workflows `disabled_manually`; CI red since 08-14, silent since 08-20; Release last green v0.4.28 |
| C11 | Homebrew tap | README | STALE | tap formula at v0.4.28 |
| C12 | `sbh setup`, completions, `sbh service`, `sbh log`, `sbh truncate-logs`, `doctor --release` | (undocumented) | WORKING | not in README command reference |
| C13 | Active-target leases | README | WORKING | limits verified (`active_lease.rs:43-51`) |
| C14 | `sbh version --verbose` build metadata | README | MISMATCH | all "unknown" in shipped binaries (VERGEN env unset in manual builds) |

### D. macOS parity (epic bd-r7m7, still open)

| # | Goal | Status | Evidence |
|---|------|--------|----------|
| D1 | PAL with Linux/macOS impls | WORKING | names are `LinuxPal`/`MacOsPal`/`MockPlatform`; 3 writeback methods NotImplemented (tolerated) |
| D2 | Mount inventory via statfs/getmntinfo + APFS | PARTIAL | shells `/sbin/mount` every 5 s and `diskutil` every 5 min; purgeable and snapshot bytes are the same heuristic; Foundation API opt-in via undocumented env |
| D3 | libproc open-file evidence | WORKING | no time budget on `open_files_under`; `sbh_mach` (48 unsafe sites) never tested in CI |
| D4 | Memory pressure (Mach + sysctl + dispatch) | WORKING | |
| D5 | Cleanup catalog + sacred paths | WORKING | `~/Library/Caches` has no rule despite docs |
| D6 | Time Machine thinning | WORKING | bytes heuristic |
| D7 | `doctor --pal` | WORKING | FDA probe meaningless for system daemons |
| D8 | `sbh blame` on macOS | WORKING | |
| D9 | Signed, notarized, brew-distributed | REGRESSED | see C9-C11 |
| D10 | Epic acceptance 1/6/7 | NOT SATISFIED | macos-13 retired; workflows disabled; fresh-Mac install fails trust |
| D11 | Event source on macOS | NOT_STARTED | reconciliation only, no FSEvents/kqueue |

### E. Quality and proof

| # | Goal | Status | Evidence |
|---|------|--------|----------|
| E1 | Tests pass | WORKING | 0 failures; but ~955 TUI tests + `fallback_verification` never compile in CI or `quality-gate.sh` (10 of 21 stages pass vacuously) |
| E2 | Clippy clean (`-D warnings`, pedantic + nursery) | REGRESSED | 62 errors at HEAD (new nightly lints) |
| E3 | CI on every push, nightly gates | DEAD | see C10 |
| E4 | E2E coverage of the daemon | NONE | `e2e_test.sh` defers all daemon cases; "e2e"/"proof"/"stress" harnesses are in-process simulations; no test asserts a real daemon deletion |
| E5 | Documentation accuracy | SYSTEMIC DRIFT | test counts off 35-270 %; three different gate stage counts; config keys; unit name `sbh-daemon`; commands that do not exist |
| E6 | Tracker hygiene | POOR | DB was corrupt + schema v7; false closes; no beads for any gap here |

## 3. Ground truth in detail

### 3.1 Operator workstation

- `sbh.service` is enabled but `inactive (dead)` since 2026-08-30 14:59.
  Drop-ins: `SBH_SCANNER_ENGINE=v2`, `CPUQuota=10%`, `CPUWeight=20`,
  `IOWeight=10`, and `ConditionPathExists=!/etc/sbh/HOTLOOP_DISABLED`.
  The unit itself dates from 2026-03-05 (`Type=simple`, `/usr/local/bin/sbh`,
  no hardening, no `MemoryMax`), i.e. the generated hardened unit has never
  been used here.
- `/etc/sbh/HOTLOOP_DISABLED` text: "sbh logs 'ballast provision skipped: free
  space too low (<20%)' then sits in Red urgency and spins at 100% of a core.
  Threshold is 20% FREE, not 10%. Remove only once / is above ~20% free."
- `/` (btrfs, 977 GiB) at 12 % free = Orange for weeks; `/data` (btrfs,
  5.5 TiB) at 46 %. `root_paths = ["/tmp", "/data/tmp"]`; `/tmp` is tmpfs.
  Journal on every start: "pressure on / (Orange) but no scannable root_path
  resides on that device and cross_devices=false; cannot reclaim — backing
  off". Last run: `scans=0 candidates=0 deleted=0`, 33 s CPU in 5 min.
- Ballast: configured 5 × 2 GiB on `/var/lib/sbh/ballast`; directory empty;
  `sbh doctor --system` correctly FAILs "emergency reserve does not exist".
  The daemon provisioned 10 GiB on `/data/.sbh/ballast` instead (root-owned,
  invisible to `sbh ballast status`).
- Activity logs (JSONL, 2026-06-21 → 2026-08-30): artifact_delete ok/fail per
  rotated file 22/20, 3393/840, 707/1880, 2333/6092, 610/5911, 0/844.
  Failure reasons: NotWritable 10,362; Symlink 3,609; IdentityMismatch 999;
  FileOpen 570; "Directory not empty" IO failures. 35,692 `error/critical`
  events 08-09 → 08-11 all "special location UserTmp (/data/tmp) at N% free
  (buffer=15%)". 100 `emergency` events in one minute on 08-18 22:05 with
  `free_pct: 99.99999` (bogus) while `/data/tmp` did not exist (data volume
  rebuild).
- `sbh --json status` → `daemon_running: true`; human mode → "Daemon: not
  running (degraded mode)". `sbh stats`/`sbh tune` as user → SBH-2102
  readonly database; `sudo sbh stats` → `no_database` at
  `/root/.local/share/sbh/activity.sqlite3` (135 MB of data sits in
  `/var/lib/sbh/activity.sqlite3`).
- `sbh dashboard` → "TUI feature not enabled. Rebuild with --features tui".
  `sbh explain` → "unrecognized subcommand". `sbh update --version v0.5.0
  --dry-run` → would download
  `.../v0.5.0/sbh-v0.5.0-x86_64-unknown-linux-gnu.tar.xz` (does not exist).

### 3.2 Sandbox daemon runs (v0.5.1 binary, synthetic root on /data)

| Run | Config | Result |
|-----|--------|--------|
| 1 | defaults, `/` Orange, cross_devices=false | 45 s, **0 scans** ("no scannable root_path… backing off") |
| 2 | thresholds lowered so everything is Green, v2 then v1 | 60 s each, v2: one `scan_complete reason=green_idle paths_scanned=0`; v1: none |
| 3 | defaults + `cross_devices=true`, v2 then v1 | both scan in < 1 s, find the stale target and the `.git` sibling is refused correctly, **0 dispatched** (`cleanup=IdentifyOnly` at Orange); `sbh scan --explain` scores the stale target 0.6475 → `Review` |

The stale fixture was a 64 MiB cargo target with a valid `CACHEDIR.TAG`,
`deps/`, `incremental/`, `.fingerprint/`, no open files, 42 min old by
birth time, in a temp root. This is the canonical artifact the tool exists
to remove.

### 3.3 Shipped reality

- v0.5.1 (Latest, 2026-08-26) assets: `sbh_darwin_amd64`, `sbh_darwin_arm64`,
  `sbh_linux_amd64`, `sbh_linux_arm64`, `SHA256SUMS`. No workflow run for
  v0.5.0/v0.5.1 (hand-published). `sbh_darwin_arm64` Mach-O: one
  CodeDirectory slot, `flags=0x20002` (ad-hoc), no CMS blob, no team ID;
  `sbh_darwin_amd64`: no `LC_CODE_SIGNATURE` at all. v0.4.28 (2026-06-08)
  was the last Developer-ID-signed, notarized, workflow-built release.
- Workflows: CI, Release, Developer ID Certificate Expiration all
  `disabled_manually`. Last CI run 2026-08-16: Format + Lint failure, every
  Linux test job skipped, macOS lanes green.
- Homebrew tap `Dicklesworthstone/homebrew-sbh` formula → v0.4.28.
- Both installed binaries (`/usr/local/bin/sbh`, `~/.local/bin/sbh`) are
  0.5.1 with `git_sha: unknown`. HEAD is 4 commits past the v0.5.1 tag
  (rch classifier hardening, sudo config resolution, fixtures, fmt).

## 4. Gap analysis by category

| Category | Gaps |
|----------|------|
| Vision gap (documented, no bead, not built) | B1 explain; C3 bootstrap; C5 uninstall modes; A4 routine Green maintenance; B8 prediction surfaces; D11 macOS events |
| Design gap (built, cannot reach the goal this way) | A3 behavior matrix acts only at Red; A5 device-affinity starvation; A6 20 % provisioning floor; A12 VOI never scheduled; A10 policy engine nominal; A13 percent-only special-location thresholds; A17 idle spin |
| Implementation gap (built, incomplete or wrong) | A8 Review verdict for definite artifacts; A9 index replay bypass; A16 READY=1/watchdog/shutdown; B2 daemon_running; B3 non-root read paths; C4 updater contract; C6 ReadWritePaths; C1 macOS trust vs artifacts; B4 dashboard |
| Proof gap (built, not proven) | E4 no daemon e2e; E1 TUI tests never run; `sbh_mach` untested; macOS acceptance unmeasured (cold-start latency) |
| Integration gap | CLI vs daemon ballast pools; stats vs actual log contents; installer vs updater asset contracts; config example vs loader |
| Delivery gap | C9/C10/C11: signing, CI, tap, clippy gate |
| Documentation gap | E5 across README/AGENTS/docs |

## 5. Bead coverage and false closes

- Open/in-progress beads: `bd-r7m7` (macOS epic), `bd-r7m7.17` (hosted CI
  proof), `bd-xtpv` + `bd-xtpv.8` (scanner v2 validation), `bd-t951`
  (release-asset audit), `bd-ykwh` + `bd-ykwh.3` (release workflow).
  None of the 60+ rows above outside D and A18 is covered.
- Closed without the deliverable existing in the CLI: `bd-izu.2` (evidence
  ledger + explain command), `bd-2j5.21` (bootstrap migration +
  self-healing), `bd-2s9` (watchdog heartbeat: never enabled, no READY=1),
  `bd-xzt.5.3`/`bd-xzt.5.6` (rollout controls / legacy deprecation: Phase 1
  never started), `bd-2f8` from memory notes (SQLite-not-on-monitored-FS
  check: does not exist).
- `docs/internal/macos-parity-completion-audit.md` says "Complete as of
  v0.4.22" while the epic is open and reality regressed after it.

## 5b. Consolidation with the parallel bridge plan (2026-09-02)

A second agent ran an independent reality check in the same hours and
produced `docs/internal/reality-check-2026-09-01.md` plus the bead tree
`bd-rc-bridge-2026-09-btcx` (G0–G12, 62 beads). The two analyses agree on
every major finding they both cover (explain/bootstrap/uninstall/dashboard
absent, `READY=1` never sent, updater asset contract 404s, config example
silently ignored, CI/clippy red, host unprotected, `daemon_running` false
positive). Each found things the other did not:

- G-tree only: catalog roots for a pressured device with no configured root
  (G1.2), systemd unit-drift detection (G3.3), policy-engine fallback
  semantics and the guardrail near-alarm at e = 14.9 (G9), the LogSearch
  stub (G5.3), the `curl` calls without the required user agent (G4.1), no
  branch protection on `main` (G4.4), the 2026-05 source-tree deletion
  history behind the FAQ answer (G8.3), repository clutter decisions (G8.5).
- This tree only: the behavior matrix making Yellow/Orange identify-only
  (W1.2), Green never scanning (W1.4), the Review verdict for definite
  artifacts (W1.3), per-mount control ending affinity starvation (W1.1),
  the special-location horizon rule (W1.6), EROFS/ENOSPC recovery and the
  failure e-process (W1.7), state.json v2 (W1.8), the quantitative designs
  Q1–Q10, ballast integrity (W8), macOS technical closeout (W9), the
  daemon e2e suite (W10), regret-calibrated thresholds (W2.4), and the
  fleet rollout record (W13.2).

Resolution applied with `br`: every bead in this tree that duplicated a
G bead was closed with a pointer to the canonical G bead, its unique
details were appended to that G bead as notes, and cross-tree blocking or
related edges were added. Closed as duplicates: W0 (all children), W2.1–2.3,
W3.1, W3.2, W3.5–3.8, W4.1–4.4, W5.1, W5.3, W7.3, W9.4, W10.4, W11 (all),
W12 (all), W13.1. Remaining under `bd-rc-master-ajg1`: W1 (all eleven),
W2.4, W3.3, W3.4, W4.5, W5.2, W6, W7.1, W7.2, W7.4, W7.5, W8, W9.1–9.3,
W10.1–10.3, W13.2. The two master epics are linked as related. Implementers
should treat the union as one plan: G-tree for lifecycle, distribution,
explain, dashboard, docs, and policy; this tree for daemon behavior,
quantitative control, e2e proof, ballast integrity, macOS technical items,
and rollout.

## 6. Bridge plan (revision 4 — ambition rounds 1-3 applied)

### 6.0 Contracts that every workstream consumes

Each contract is a Rust module with a serde schema, a version field, and a
round-trip test. Docs are generated from the module (a doc-test renders the
table), never hand-typed.

**C-STATE — `state.json` v2** (`src/daemon/state_schema.rs`)

```
version, schema_version: 2, run_id, pid, started_at, last_updated,
stopped_at?, exit_reason?,
mounts[]: { path, fs_type, total, free, free_pct, level, urgency,
            controller: observe_only|maintain|reclaim|recovery|idle,
            idle_reason?, rates: { bytes_per_sec, accel, confidence,
            seconds_to_red?, seconds_to_full? },
            ballast: { dir, configured, available, health, releasable_bytes },
            last_scan: { at, engine, candidates, deleted, freed_bytes,
                         decision_ids_range },
            behavior_cell: { scan, cleanup, ballast, notify } }
memory: { level, available, swap_used_pct, thrash_risk },
policy: { mode, since, fallback_reason?, guard: {status, e_value, obs} },
threads: { monitor, scanner, executor, logger: running|stalled|dead, last_beat_secs },
counters: { scans, deletions, deletion_failures, bytes_freed, errors,
            dropped_log_events },
memory_rss_bytes, cpu_secs_total
```

`#[serde(default)]` is kept; readers tolerate v1 and set `state_stale` from
`last_updated`.

**C-EVENT — activity event schema** (`src/logger/schema.rs`): every event has
`ts, event, severity, run_id`; `artifact_delete` adds `decision_id, path,
size, ok, skip_reason?, errno?`; `decision` is the full `DecisionRecord`;
`ballast_provisioned|released|replenished` add `mount, files, bytes`;
`policy_transition` adds `from, to, reason`; `special_location` adds
`location, free_pct, free_bytes, floor_bytes`; `emergency` adds `mount,
free_pct, files_released`; `error` is reserved for failures and carries
`error_code`. Severity is one of `debug|info|warning|critical`; nothing
informational is ever `error`.

**C-ASSET — release asset contract** (`src/cli/mod.rs::ReleaseAssetContract`):
canonical `sbh-<tag>-<triple>.tar.xz` + `.sha256` + `.sigstore.json`; mirror
`sbh_<os>_<arch>` + `SHA256SUMS`; `release-provenance.json`. Installer and
updater probe in the same order; a test asserts `scripts/install.sh`'s
strategy block equals the contract's rendering.

**C-CONFIG — configuration schema**: `config_version = 2` at the top of the
file; `deny_unknown_fields` everywhere; v1 files (no version) are migrated by
`sbh bootstrap` (`deprecated-config-key` covers renamed keys, with backup);
the README example is a test fixture parsed in CI.

**C-EXIT — CLI exit codes**: 0 ok · 1 user error or pressure condition · 2
runtime/IO failure · 3 internal · 4 partial success. `check` uses 1 for
pressure; `clean`/`emergency` use 4 when any item failed. Human reports on
stdout, diagnostics on stderr, always.

### W0 — Restore the proof machinery

Design (unchanged from revision 2, with additions):
- Lint fixes by hand; nightly pinned by date; weekly "lint drift" job files a
  bead instead of breaking main.
- CI matrix: `{linux-x86_64, linux-aarch64, macos-arm64, macos-x86_64} ×
  {default, tui}`; release builds are `tui`.
- `quality-gate.sh` stages record executed-test counts and fail on zero;
  `--print-stages --markdown` is the source for both docs.
- `sbh_mach` in the workspace and tested on macOS lanes.
- `scripts/test-census.sh` generates the test table; CI diffs it.

Test matrix: gate self-test (vacuous stage detection), census diff test,
workflow lint (`actionlint`) in CI.

Acceptance: two consecutive green pushes on main across the full matrix;
TUI lane ≥ 950 tests; zero vacuous stages.

### W1 — Make the daemon reclaim before the cliff

**1.1 MountController state machine** (`src/daemon/mount_controller.rs`)

States: `ObserveOnly` (no root_path, no pool on this mount), `Maintain`
(Green, has work surface), `Reclaim` (Yellow+), `Recovery` (EROFS/ENOSPC
detected), `Idle` (has surface, nothing actionable, backoff armed).

Transitions, evaluated per tick from the mount's own PID/EWMA:
- `Maintain → Reclaim` when level ≥ Yellow, or predictive `seconds_to_red ≤
  action_horizon` with confidence ≥ min.
- `Reclaim → Maintain` after `recovery_clean_windows` consecutive Green ticks.
- `Reclaim|Maintain → Recovery` on `FilesystemReadOnly` or
  `NoSpaceForMetadata` from the executor; `Recovery → Reclaim` when a probe
  write of 4 KiB to `<mount>/.sbh/probe` succeeds and free ≥ red_min.
- `* → Idle` when a full pass yields zero dispatchable candidates and no
  ballast is releasable; `Idle → Maintain|Reclaim` on event-dirty roots,
  SIGUSR1, config reload, or after `min_rescan_interval × 2^n` (capped 1 h).
- `ObserveOnly` is entered at startup/reload and only leaves on config
  change.

Each state defines the tick cadence it contributes (`ObserveOnly`/`Idle`:
base poll; `Maintain`: base poll; `Reclaim`: PID interval with the existing
floors; `Recovery`: 30 s). The daemon's tick interval is the minimum over
mounts not in `ObserveOnly`/`Idle`. This removes R3 and R7 by construction.

**1.2 Behavior matrix** as `[behavior]` config with a `preset` selector
(`"v0.6"` default, `"v0.5"` for the old cells, `"custom"` with explicit
cells). Default v0.6 cells at normal memory: Green → maintenance pass
(`HighConfidenceCandidates`, ballast `None`), Yellow →
`HighConfidenceCandidates`/`None`, Orange → `DefiniteCandidates`/`Release`,
Red → `AnyDefiniteCandidate`/`ReleaseFirst`, Critical → same + Review
escalation. Memory rows may lower scan aggressiveness but never lower the
cleanup/ballast cell below the disk row (`memory_never_reduces_cleanup =
true`). The effective matrix is logged at startup and shown by `sbh config
show --effective`; `state.json` carries the active cell per mount.

**1.3 Definite-artifact certainty** (`src/scanner/certainty.rs`; calibration from Q4, idleness from Q5)

| Evidence (all structural, no name matching) | Certainty |
|---|---|
| Validated `CACHEDIR.TAG` at root, or Rust `.fingerprint/` + `incremental/`, or Go build-cache layout, or `node_modules/` under a temp root, or Xcode DerivedData child, or Electron cache dir, or rch marker dir with idle tree | Definite |
| Name pattern ≥ 0.85 confidence with one structural marker | Likely |
| Anything else | Unclear |

Decision layer: `Definite` uses prior `posterior_floor_definite` (0.85) after
all vetoes; `Likely` uses the existing posterior; `Unclear` can only reach
`Review`. The fast lane never runs before min-age, active-reference, sacred,
lease, or source-tree checks. Golden tests pin: sandbox stale target →
Delete at Yellow+ (with maintenance cell) and Orange+; fresh → Keep;
`.git` sibling → Keep; leased → Keep; open file → Keep.

**1.4 Green maintenance** (root selection from Q6): `maintenance_interval_secs` (1800) schedules a
`HighConfidenceCandidates` pass over roots picked by
`VoiScheduler::schedule()` (budget `[scheduler].scan_budget_per_interval`);
obeys duty cycle and empty-pass backoff; suppressed when memory is Critical.

**1.5 Ballast plan** (reserve target from Q1): per mount `n = clamp(floor((free_bytes -
reserve_floor_bytes) / file_size), 0, configured)` with `reserve_floor_bytes
= max(orange_min_free_pct × total, file_size)`; provision `n` now; re-plan
after each reclaim/replenish and every `maintenance_interval`; health
`full|partial|empty|unconfigured-for-space|unreadable`. CLI and daemon share
`BallastCoordinator::discover(config)`; `sbh ballast status` lists every pool
with its mount and health.

**1.6 Special locations** (horizon rule from Q2): `free_buffer = min(pct, absolute)`; defaults
RAM-backed 20 % (no absolute), disk-backed temp roots 15 % or 32 GiB,
custom 15 % or 32 GiB; alert severity `warning` (disk) / `critical` (RAM);
one event per location per 15 min; state changes log immediately.

**1.7 Failure classification** (alarm from Q8): `SkipReason::{ParentNotWritable(errno),
FilesystemReadOnly, NoSpaceForMetadata}`; the executor stops the batch on the
latter two and returns `BatchOutcome::RecoveryNeeded(mount)`; the daemon
switches that mount to `Recovery` (ballast release, Critical notification
with the exact commands, retries paused).

**1.8 Observability**: `rates`/`forecast` in `state.json`; `idle_reason` per
mount; `emergency` events truthful and deduplicated; `sbh status` prints the
controller state and idle reason per mount.

Test matrix:

| Level | Tests |
|---|---|
| Unit | state-machine transitions (table-driven); matrix resolution incl. presets and the never-reduce rule; certainty classifier per evidence row; ballast plan arithmetic incl. zero and negative headroom; special-location floor math; skip-reason errno mapping |
| Integration (MockPlatform, multi-mount stats) | two mounts, one pressured without root: other mount still maintained; tick cadence stays at base poll; Recovery entry/exit |
| Daemon e2e (W10) | host layout; Orange reclaim; Red with ballast; read-only bind mount; partial provisioning at 12 % free |

Rollout: ship with `preset = "v0.6"` default and `SBH_BEHAVIOR_PRESET=v0.5`
env override; canary on the operator workstation for 7 days with daily
review of `sbh stats --window 24h` (deletion success rate, bytes freed,
false-positive reports), `journalctl` CPU, and `sbh status` idle reasons;
fleet rollout via `sbh update` after W4; rollback is the env override.

### W2 — Explainability that exists

Design as revision 2, plus: `decision_log` indexed by `(run_id, seq)` and
`path`; `sbh explain --last N`, `--path`, `--since`; dashboard reads the
same table; retention 30 days shared with `activity_log`; JSONL `decision`
events are optional (`[telemetry] log_decisions_jsonl`, default true) to
bound log growth.

Test matrix: unit (id minting, record round-trip), integration (SQLite
insert/query, retention), e2e (delete → id → explain at four levels, CLI-only
run without daemon).

### W3 — Truthful CLI on real installs

Design as revision 2 with these precisions:
- `DaemonProbe` order: pidfile (default `<data_dir>/sbh.pid`, written by the
  daemon, checked with `kill(pid, 0)` and `/proc/<pid>/comm == "sbh"`),
  service manager (`systemctl is-active sbh.service` / `launchctl print`),
  state freshness. `daemon_running` is true only if pidfile or service
  manager says so; state freshness alone yields `daemon_running: false,
  state_stale: false` with a hint.
- Read-only SQLite opens; JSONL fallback; the sudo hint names the real
  system paths.
- `clean`/`emergency` partial → 4; `check` pressure → 1; `-q`/`-v`/
  `--no-color` implemented through one `Ui` helper.
- Uninstall planner wired with backups; `--purge` requires `--yes` in
  non-TTY and always backs up config + last 1 MiB of each log.
- Bootstrap wired; `sbh install` runs a dry-run and applies in `--auto`.
- TUI default feature; quick-release executes; `--start-screen`;
  `REDUCE_MOTION`; docs fixed; dead crossterm dashboard feature-gated pending
  deletion approval.
- `deny_unknown_fields` + `config_version` + tilde expansion + unknown-key
  diagnostics with did-you-mean; `auto_provision` honored.

Test matrix: CLI e2e in CI on user install and root-owned system install
fixtures (sudo job); config fixture round-trips; probe unit tests with fake
pidfiles.

### W4 — One release contract, working updater, live pipeline

Design as revision 2, plus the post-publish audit (`sbh doctor --release
--assets <dir|tag>`): downloads every asset, verifies checksums, Mach-O/ELF
arch per target, codesign identity and notarization ticket for macOS,
sigstore bundle verification, and tarball-vs-raw byte equality; the Release
workflow runs it and the manual script runs it before upload. Both installer
and updater share `probe_release_assets()` semantics; a fake-release-server
e2e covers tarball-only, raw-only, and mixed releases plus a checksum
mismatch and a missing sigstore with `Required` policy.

### W5 — systemd correctness

Design as revision 2. Test: `systemd-run --user` integration on Linux CI
(`Type=notify`, `WatchdogSec=5`) asserting `active` within 10 s, heartbeat
observed via `systemctl show -p WatchdogTimestamp`, clean stop writes
`stopped_at`.

### W6 — Logging and stats integrity

Design as revision 2, with the C-EVENT schema as the contract; `stats`
reads ballast/policy sections from real rows; degradation constants unified
and tested; VACUUM conditional.

### W7 — Scanner v2 hardening

Design as revision 2, plus: replayed candidates carry `index_generation` and
are dropped if the root's generation advanced; the A/B artifact format
(`scan-v1.json`/`scan-v2.json` + `scan_complete` events) is the closing
evidence for `bd-xtpv.8`.

### W8 — Ballast integrity

Design as revision 2 (flock coverage, read-only `ballast status`, per-mount
enumeration, APFS preallocation parity, cooldown reset every tick).

### W9 — macOS closeout

Design as revision 2, plus: `getfsstat` via `sbh_mach` with a unit test
against `/sbin/mount` output on the macOS lane; cold-start `sbh status`
budget 250 ms in the perf lane; `open_files_under` deadline 5 s / 50k pids
fail-closed; single `estimated_reclaimable_by_snapshot_thinning` field.

### W10 — Real daemon end-to-end suite

Scenario table (each asserts events, state, filesystem, CPU):

| Scenario | Setup | Must hold |
|---|---|---|
| host-layout | mount A pressured (injected stats), root on mount B healthy | B maintained within interval; A observe-only; CPU < 2 % |
| orange-reclaim | root mount Orange | stale Definite deleted; fresh/git/open/leased kept; ballast released; decision ids present |
| red-ballast | Red, pool of 2 | ReleaseFirst before scan; both released; events logged |
| read-only | root on `ro` bind mount | batch stops; Recovery; Critical notification; no retries 5 min |
| partial-provision | mount at 12 % free, orange 10 % | pool `partial` with n files |
| reload | SIGHUP with new root | new root scanned; matrix re-logged |
| forced-scan | SIGUSR1 at Green | scan_complete within 2 s |
| shutdown | SIGTERM | `stopped_at`, `exit_reason` written; exit 0 |
| engines | v1 and v2 | parity on the reclaim scenario |

Pressure injection: `SBH_TEST_FS_STATS` JSON consumed by `FsStatsCollector`
only under `SBH_TEST_MODE=1`; CI additionally uses a 512 MiB loop-mounted
ext4 for one real-pressure run. Placeholder tests become real; chmod tests
skip as root; suite runs on Linux and macOS.

### W11 — Documentation reconciliation

As revision 2, plus an explicit README change list:
- Delete: "1s polls", the non-monotonic age curve, "hundreds of patterns",
  `[monitor]`/`[logging]`/`[guardrails]`/`[scoring.weights]`/`[policy]
  mode` keys, `sbh explain` until W2 ships, the dashboard section until W3.7
  ships, `gh release download --pattern "sbh-*.tar.xz"` until W4 ships,
  `systemctl status sbh-daemon`, "runs automatically during install" until
  W3.6 ships, uninstall matrix until W3.5 ships.
- Rewrite: thresholds (20/14/10/6, Critical < 6), PID setpoint, EWMA alpha
  direction and confidence weights, guardrail constants, circuit breaker 5,
  degradation constants, JSONL daemon settings, ballast pools per mount,
  behavior matrix table, special-location floors, exit codes, release assets.
- Add: `service`, `log`, `setup`, `truncate-logs`, `doctor --release`,
  `lease`, `status --sacred`, env-var table completion.
- CI checks: README command existence; README config example validates;
  numbers in docs come from generated tables.

### W12 — Tracker hygiene

As revision 2.

### 6.14 Quantitative design (revision 4 — ambition round 3)

The daemon already contains the right skeletons: an adaptive EWMA with a
quadratic time-to-exhaustion solver, a PID with anti-windup, an e-process
guardrail, a Bayesian expected-loss decision, a VOI utility, a duty-cycle
limiter, and a process-level write-rate history. What follows makes each of
them load-bearing, with the math chosen so that every quantity is estimable
from data the daemon already collects and every guarantee is checkable by a
property test.

#### Q1. Reaction-window reserve sizing (ballast as a quantile, not a constant)

Definition. For mount `m`, the *reaction window* `W_m` is the time from a
pressure transition to the first byte actually freed: `W_m = poll + scan +
preflight + delete`, measured by the daemon (EWMA of observed cycle latencies,
default prior 300 s). The reserve the daemon must be able to release
instantly is the amount the host can write on `m` during `W_m`.

Estimator. `ProcessIoHistory` already samples per-process `write_bytes`
every 15 s. Aggregate per mount (attribute a process's writes to the mount of
its cwd / open files, fallback: the busiest mount) into window sums
`X_k = bytes written on m during window k of length W_m`. Keep a streaming
quantile sketch (t-digest, 100 centroids, persisted with `io_history.bin`).
`reserve_m = q_{0.99}(X)`; with fewer than 50 windows, use a
peaks-over-threshold fit (generalized Pareto on exceedances over `q_{0.90}`)
to extrapolate the 0.99 quantile, and floor the estimate at the configured
`file_size × 2`.

Use. `sbh tune` recommends `file_count_m = ceil(reserve_m / file_size)` per
mount; the daemon's provisioning plan (W1.5) targets that count subject to
the headroom rule; `doctor --system` reports reserve coverage as a ratio
(`releasable_bytes / reserve_m`) and FAILs below 1.0.

Property tests: monotonicity in the input stream; the GPD extrapolation never
returns less than the empirical `q_{0.90}`; a synthetic bursty writer (1 GiB
in 30 s every 10 min) yields a reserve ≥ 1 GiB.

#### Q2. Time-to-harm horizons for special locations and floors

Replace fixed percentage buffers by a hazard horizon. For location `L` with
free bytes `F_L` and estimated write rate `r_L` (EWMA of the location's own
`X_k / W`, with the mount's rate as a prior), define `h_L = F_L / max(r_L,
r_min)`. Alert when `h_L < H_alert` (default 30 min) or `F_L < absolute_floor`
(RAM-backed: 20 % of size; disk-backed: 4 GiB), whichever is stricter for
RAM-backed and whichever is *looser* for disk-backed roots on multi-TB
volumes. The 35,692-event storm of August becomes zero events: 760 GiB free at
any plausible rate is days of horizon.

Property tests: `h_L` is decreasing in `r_L`, increasing in `F_L`; the alert
predicate is invariant to volume size when expressed in horizon.

#### Q3. Per-mount control with feedforward and gain scheduling

Keep the PID but make it per mount (W1.1) and add:
- **Feedforward from the forecaster.** `raw = Kp·e + Ki·∫e + Kd·ė +
  Kf · clamp(1 − t_red / H_action, 0, 1)` where `t_red` is the quadratic
  TTE to the red line and `H_action` is the action horizon. The existing
  "boost to ≥ 0.70" becomes the `Kf` term (default 0.8) so urgency rises
  smoothly rather than jumping at 15 min.
- **Gain scheduling by capacity.** Errors are in percent; a 1 % error on a
  5.5 TiB volume is 55 GiB, on a 100 GiB root it is 1 GiB. Schedule
  `Kp_m = Kp · sqrt(total_m / 1 TiB)` clamped to [0.5, 2]·Kp so large volumes
  respond to the same *byte* rate of change.
- **Anti-windup on actionability.** Freeze the integral term while the mount
  is `ObserveOnly`, `Idle`, or `Recovery` (no actuator authority), which is
  the textbook cause of the "sits at urgency 0.99 forever" state in the
  kill-switch note.

Property tests: with the actuator frozen the integral does not grow; urgency
is monotone in `−t_red`; a step in free space converges without overshoot
beyond one level within N ticks (numeric stability test with the sandbox
trace).

#### Q4. Calibrated deletion with conformal risk control

Labels the daemon can observe. A deletion at time `t` of opaque root `p` is
a *regret event* if the same identity `(parent_dev, parent_ino, name)` is
recreated within `τ = 30 min` while a process with cwd or open files under
`p`'s parent is alive — i.e. somebody was still using it. Regret is a proxy
for false positive; it is exactly the "rebuild from cold" cost the v0.5.1
changelog describes for rch pools. Record it as `decision_outcome` rows
(`decision_id, outcome: regret|clean|unknown, observed_at`).

Estimator. Per category `c` (RustTarget, GoCache, NodeModules, Electron,
DerivedData, TempDir, …), maintain Beta posteriors `Beta(a_c, b_c)` for the
regret rate with an empirical-Bayes prior fit across categories (method of
moments on the per-category means), so rare categories borrow strength.

Control. Choose the delete threshold `θ_c` on the posterior-abandoned scale so
that the Clopper–Pearson upper bound of the regret rate at level `δ = 0.05`
stays ≤ `α_c` (default 0.02 for Definite, 0.005 for Likely). This is
learn-then-test risk control applied to one threshold per category: sort past
decisions by posterior, find the largest threshold whose empirical regret
upper bound ≤ α. The `posterior_floor_definite` of W1.3 is the *initial*
threshold; Q4 tightens or loosens it from evidence and the `calibration`
score already in the decision layer becomes `1 − UB(regret)`.

Guardrail. The existing e-process machinery gets a second stream: H0
"regret rate ≤ α"; observations are deletions; alarm demotes the policy to
Canary for that category (not globally), which is the missing category-level
fallback.

Property tests: with zero regrets the threshold never rises above the initial
floor; with regret rate 10 % in one category only that category's threshold
tightens; the Clopper–Pearson bound is monotone in the count.

#### Q5. Opaque-root idleness instead of birth time

Age of a directory should mean "time since anything inside it changed".
Compute `tree_idle_since(p)` cheaply: sample up to `k = 64` entries via a
bounded reservoir over the first 4,096 readdir results at depth ≤ 3, take the
max mtime, and combine with the root's own mtime and birth time:
`effective_age = now − max(sampled_max_mtime, root_mtime)`; birth time is
only a lower bound on age. This is the generalization of the rch idle probe
(`rch_tree_activity`) to every opaque candidate, with a hard cap on
syscalls. Property test: a tree with one fresh leaf never reports idle longer
than that leaf's age (sampling is deterministic under a seed so the test is
exact for k ≥ tree size).

#### Q6. Scan scheduling as a hazard-driven index policy

With v2's inotify dirty roots, the only question VOI must answer at Green is
"which non-dirty roots deserve a bounded look?". Model each root `i` as a
restless arm with change hazard `λ_i` (EWMA of dirty transitions per hour),
expected reclaim per visit `R_i` (already tracked), and visit cost `C_i`
(entries walked, already tracked). The index is
`I_i = R_i · (1 − e^{−λ_i · Δt_i}) − w_c · C_i`, where `Δt_i` is time since
the last visit: the probability that something changed times the payoff,
minus cost. Pick the top-`k` by index within the budget; roots with dirty
flags are always visited first. This is the Whittle-index heuristic for
restless bandits with Poisson change and it reduces to the existing
exploration bonus when `λ` is unknown (prior `λ_0 = 1/24 h`).

Property tests: a root with `λ = 0` and no dirty flag is visited at most
once per day; a root with high `λ` and high `R` dominates; the budget is
never exceeded.

#### Q7. CPU budget with a stated bound

Model scanner work as a token bucket with rate `ρ = max_scan_duty_cycle_pct /
100` cores and burst `B = 5 s`, fed by all scanner, prescan, and
maintenance work (not just walker passes), and charge the monitor thread's
own tick time to the same bucket. Long-run CPU fraction ≤ `ρ` plus the
bucket burst amortized over the window; with `ρ = 0.25` and `B = 5 s`, over
any 60 s window CPU ≤ 25 % + 8 %. The existing idle-debt formula gives the
same long-run bound for walker passes only; extending the charge to every
thread and adding per-mount `Idle`/`ObserveOnly` cadence is what turns the
bound into an invariant. Test: run the daemon 60 s in the host layout and
in Orange-with-work; assert `cpu_secs_total / wall ≤ 0.02` and `≤ 0.33`
respectively from `state.json.cpu_secs_total`.

#### Q8. Anytime-valid deletion-failure monitor

Failures are a stream; a 10,362-count `NotWritable` run should have tripped
something within minutes. Apply the guardrail e-process to the executor:
H0 "failure rate ≤ 10 %"; e-value factor 1.5 on failure, 2/3 on success,
clamp [−5, 3.5], alarm at 20 (same constants as the forecaster guard so the
math is shared). Alarm → mount enters `Recovery` (W1.7) and a Critical
notification names the dominant `SkipReason`. Property test: 20 consecutive
failures alarm; 9 failures per 100 do not.

#### Q9. Event-watch budget allocation

With `event_watch_budget = 8192` recursive watches and roots with far more
directories, allocate watches to directories in decreasing order of observed
event rate (EWMA per directory, Zipf-like in practice), keeping the root and
depth-1 always; everything unwatched is covered by the reconciliation pass
whose cadence is the maintenance interval. Overflow (`Q_OVERFLOW`) already
marks all roots dirty; add a counter and back off the reconciliation cadence
exponentially when overflows repeat. Property test: allocation never exceeds
the budget and always includes the root and depth-1 directories.

#### Q10. Snapshot-aware release accounting (macOS)

Ballast release under APFS with local snapshots frees blocks only when no
snapshot references them. Measure effectiveness `η_m = Δfree_observed /
bytes_released` after each release (statfs before/after, 5 s settle) and keep
an EWMA; the release controller targets `bytes_needed / η_m` files and the
status line reports `η_m` with the thin command when `η_m < 0.5`. Property
test: with `η = 0.25` the controller requests four times the files, capped
at the pool.

#### Proof obligations summary

Each Q-item ships with: (1) a pure function or small struct in the crate,
(2) proptest properties as listed, (3) a line in the daemon e2e that
exercises it end to end where feasible (Q1 via a synthetic writer, Q2 via
injected stats, Q3/Q7 via the sandbox trace, Q4 via a scripted regret, Q5
via fixtures, Q8 via a read-only mount), and (4) the numbers surfaced in
`state.json` and `sbh status --json` so operators and the dashboard can see
them.

## 7. Cross-cutting invariants

As revision 2, plus:
8. Every `SkipReason` is one of a closed enum with an errno where
   applicable; `stats` reports failures by reason.
9. `state.json` v2 is written at least every 30 s and on shutdown; readers
   compute staleness from `last_updated`.
10. The tick interval is never below the base poll interval unless at least
    one mount is in `Reclaim` with dispatchable work or releasable ballast.

## 8. Failure-mode analysis

As revision 2, plus:

| Failure | Detection | Response |
|---|---|---|
| Config from README v1 example | unknown-key diagnostics | `config validate` fails; daemon refuses to start in strict mode with did-you-mean |
| Fleet update to a release with only raw assets | asset probe | updater installs from raw + SHA256SUMS; audit flags missing sidecars |
| TUI build fails off-VPS | ftui git dep resolution | CI `tui` lane on a clean runner |
| Two daemons (user + system) on one host | pidfile + service probe | `sbh status` lists both; `sbh install` refuses a second scope without `--force` |

## 9. Security scope for a root daemon

- Deletion scope is the union of `scanner.root_paths` minus protected,
  sacred, source-tree, `.git`, lease, and open-file vetoes; the hardcoded
  source-tree refusal for `/data/projects`, `/home/*/projects`,
  `/Users/*/projects` stays and is documented.
- `ReadWritePaths` is derived from config so the systemd sandbox matches the
  deletion scope exactly; `ProtectSystem=strict` stays.
- Lease tokens remain 256-bit with digest-only storage; the sidecar lock path
  is canonicalized (fix `37111db` retained).
- `sbh uninstall --purge` never deletes outside the sbh config/data/ballast
  dirs and always backs up.
- The updater refuses unsigned macOS binaries unless `--no-verify`, and the
  Release workflow produces signed ones again.

## 10. Host remediation runbook (operator workstation)

As revision 2, with the addition that step 5 is preceded by a 60-minute
dry run: `SBH_SCANNER_DRY_RUN=1 sbh daemon --config /etc/sbh/config.toml`
in the foreground, reviewing `decision` events before enabling the service.

## 11. Fleet rollout plan

1. v0.5.2 (W0 + W4 + minimal W3 truthfulness): restores updater and CI;
   no behavior change; fleet self-updates; verify `sbh status` on every host.
2. v0.6.0 (W1 + W10 + W2 + W5 + W6): behavior change; canary on the
   operator workstation and one rch VPS for 7 days; rollout gated on
   deletion success rate ≥ 90 %, zero source-tree or protected deletions,
   CPU ≤ 2 % at Green, zero `Recovery` false entries; rollback via
   `SBH_BEHAVIOR_PRESET=v0.5`.
3. v0.6.x (W7, W8, W9, W11): incremental.

## 12. Sequencing and critical path

W0 + W12 → W1 (+W10) + W3 in parallel → W4 + W5 → W2, W6, W7, W8, W9 →
W11 throughout. Critical path: W0 → W4 (v0.5.2, fleet updater restored) →
W1/W10 → v0.6.0 canary → fleet.

## 13. Decisions needed from the operator

As revision 2.
