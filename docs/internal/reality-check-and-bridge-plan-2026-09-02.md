# Reality Check and Bridge Plan — 2026-09-02

Status: living document (revised in place). Source of truth for the follow-up
beads created from it; once those beads exist they carry all of this context.

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

## 6. Bridge plan

Principle for every workstream: change the code to match the promise where
the promise is the right product, and change the promise where the code's
behavior is the right product. Never leave a documented capability that a
user cannot exercise. Every workstream ends with a proof that runs in CI.

### W0 — Restore the proof machinery (prerequisite)

Problem: gates are red, disabled, or vacuous; nothing that follows can be
trusted without them.

Changes:
1. Fix the 62 clippy errors by hand (assert-empty idioms, `Duration`
   constructors, checked subtraction, constant assertion, redundant clone).
   Add a CI step that pins the nightly date in `rust-toolchain.toml` so lint
   drift is a deliberate bump, not a surprise.
2. Re-enable CI, Release, and cert-expiration workflows; confirm a green run
   on HEAD; make `paths-ignore` minimal.
3. Make `scripts/quality-gate.sh` honest: every TUI stage passes
   `--features tui` and fails if zero tests were selected; add a
   `--features tui` build+test lane in CI (ftui is a git dependency now, so
   the "strip local path deps" step is obsolete).
4. Run `crates/sbh_mach` tests in the macOS lanes.
5. Replace hardcoded numbers in `docs/testing-and-logging.md` and the gate
   runbook with a generated table (script that parses `cargo test` output).

Proof: green CI on main with Linux + macOS + TUI lanes; `quality-gate.sh`
exit 0 with non-zero test counts per stage.

### W1 — Make the daemon reclaim before the cliff

Problem: A3, A4, A5, A6, A8, A13, A17 combine so that the daemon watches a
disk fill and does nothing until Red, then cannot act.

Changes:
1. Behavior matrix: at normal memory, Yellow → `HighConfidenceCandidates`
   + ballast `None`; Orange → `DefiniteCandidates` + ballast `Release`; keep
   Red/Critical as is. Expose the matrix under `[behavior]` in config with
   validation and log the effective matrix at startup and on reload.
2. Definite-artifact fast lane in scoring: a candidate whose category is a
   validated regenerable build output (CACHEDIR.TAG signature, Rust
   fingerprint/incremental, Go cache, node_modules under temp) with age ≥
   floor and no active references gets a posterior floor that yields
   `Delete` under Orange+ pressure. Golden tests: the sandbox fixtures
   (stale → Delete at Orange, fresh → Keep, `.git` sibling → Keep).
3. Device affinity: the gate must only suppress the *aggressive* scan of the
   pressured device; routine/other-device work continues. Track pressure per
   mount that has a root_path or ballast pool and drive per-mount responses,
   so a foreign Orange mount cannot starve cleanup elsewhere.
4. Green maintenance: a configurable routine scan cadence (default 30 min)
   at Green that runs the normal safety pipeline in `HighConfidenceCandidates`
   mode; either wire `VoiScheduler::schedule()` to pick which roots to visit
   or delete the scheduler and its README section (decision: wire it).
5. Ballast provisioning floor: replace the flat 20 % refusal with "provision
   as many files as fit while keeping free ≥ orange threshold + one file";
   provision incrementally after each successful reclaim; `doctor --system`
   and `status` must show per-mount pools including `<mount>/.sbh/ballast`.
6. Idle spin: when no action is possible (no scannable root on the
   pressured device and no releasable ballast), back the tick off to ≥ 30 s
   and drop the Critical 100 ms cadence; add a test that measures daemon CPU
   time over a fixed window in that state.
7. Special locations: thresholds become `min(percent, absolute_bytes)` with a
   default absolute floor of 32 GiB for disk-backed user temp roots; alerts
   rate-limited to one per 15 min per location; severity `warning` unless
   RAM-backed.
8. Fix the bogus `free_pct` in `emergency` events; make "release all
   ballast" idempotent (one event when the pool is already empty).
9. Read-only filesystem awareness: classify `NotWritable` as root into
   EROFS / ENOSPC / permission with the real errno; on EROFS or btrfs
   metadata exhaustion, prefer ballast release and raise a Critical
   notification with the recovery command rather than retrying deletions.

Proof: a sandboxed daemon e2e (see W10) that reproduces the host layout
(pressured `/` without root_paths, healthy `/data` root) and asserts: routine
scan of `/data` root happens, stale target is deleted at Orange, ballast is
released at Orange, CPU time under a bound.

### W2 — Explainability that exists

Changes: persist `DecisionRecord`s to SQLite (`decision_log` table) and JSONL
with a stable id (`<daemon_run_id>-<seq>` or UUID); print the id on every
`artifact_delete`, `scan_complete` candidate line, and in `sbh scan --explain`
/ `sbh clean` output; implement `sbh explain --id <id> [--level 0..3]` over
the store with the four explain levels already in `decision_record.rs`; feed
the dashboard Explainability screen from the same store; retention alongside
`activity_log`.

Proof: e2e that deletes in the sandbox, captures the id from JSONL, and
`sbh explain --id` returns the full record in JSON and human modes.

### W3 — Truthful CLI on real installs

Changes:
1. `daemon_running`: state-file freshness + pidfile (`--pidfile` already
   exists; write it by default under the data dir) + `systemctl is-active`
   / `launchctl print`; remove the `/proc` cmdline substring scan; expose
   `state_age_secs` and `state_stale: bool` in JSON.
2. Read-only commands (`stats`, `tune`, `status` recent activity, `log`)
   open SQLite with `?mode=ro` and fall back to JSONL; non-root against a
   system install prints the `sudo` hint with the real system path; `config
   path` uses the same resolution as `Config::load`.
3. Export the EWMA rate and forecast into `state.json` (`rates` per mount)
   so `check --predict` and the status rate block work; delete the dead
   branches if the decision is not to export.
4. Exit codes: `clean`/`emergency` return `Partial` (4) when any deletion
   failed; `check` pressure failure is exit 1 not 2; human output stream
   consistent (stdout for reports, stderr for diagnostics); make
   `--no-color`, `-q`, `-v` real or remove them from clap.
5. Wire the uninstall planner: `--dry-run`, `--keep-data`, `--keep-config`,
   `--keep-assets`, `--purge`, backup-first, category-tagged JSON; `--purge`
   without backup is not allowed.
6. Wire bootstrap: `sbh bootstrap [--dry-run]` and an automatic dry-run
   report at the end of `sbh install` with a prompt to apply; all mutating
   actions back up first; drop AGENTS.md's "13 reasons".
7. Dashboard decision: make `tui` a default feature (ftui is already a git
   dependency; CI builds it), ship it in releases and Homebrew, keep
   `--legacy-dashboard` as the text loop, fix quick-release `x` (execute
   the confirmation through the ballast manager), add `--start-screen`,
   honor `REDUCE_MOTION`, correct the preferences filename in docs, delete
   the unreachable `src/cli/dashboard.rs` after confirming no behavior
   depends on it.
8. Config: `#[serde(deny_unknown_fields)]` on every config struct, with
   `sbh config validate` and daemon startup reporting unknown keys with the
   closest real key; tilde expansion for all path fields; add
   `[behavior]`; fix the README example to real keys (`[pressure]`,
   `[paths]`, `[policy] initial_mode`, `file_size_bytes`).

Proof: CLI e2e cases for each item running against a root-owned fixture
install (CI job with sudo) and a user install.

### W4 — One release contract, working updater, live pipeline

Changes:
1. Canonical asset contract, published in `docs/installer-dx-parity-matrix.md`
   and enforced by both `scripts/install.sh` and `src/cli/update.rs`:
   `sbh-<tag>-<triple>.tar.xz` + `.sha256` + `.sigstore.json`, plus raw
   `sbh_<os>_<arch>` mirrors and `SHA256SUMS`. The updater probes the release
   asset list via the GitHub API (with an offline manifest fallback) and
   accepts either form; checksum required for both.
2. Fix the Release workflow clippy gate (W0), re-enable it, and cut v0.5.2
   through the workflow: signed + notarized macOS tarballs (stapling the
   tarball is not possible; document `xattr` quarantine handling), sigstore
   bundles, tap update. Verify `sbh update` from 0.5.1 → 0.5.2 on one Linux
   host and one Mac before fleet rollout.
3. Manual release fallback (`docs/macos.md` "Manual Release Fallback") must
   produce the same asset set and run the tarball-arch guard locally; add a
   `sbh doctor --release --assets <dir>` check.
4. `sbh version --verbose` build metadata populated in every build path
   (build script reading git, or release env).
5. Keep `master` mirrored (documented in AGENTS.md) via a step in the
   Release workflow.

Proof: updater e2e against a local fake release server serving both asset
layouts; `install.sh` e2e on Linux and macOS lanes; the fleet self-updates
to 0.5.2.

### W5 — systemd correctness

Changes: send `READY=1` after init and `STOPPING=1` on shutdown; read
`WATCHDOG_USEC` and heartbeat at half the interval; derive `ReadWritePaths`
from `scanner.root_paths`, special locations, ballast dirs, data/config dirs
and re-render on `sbh install`/`config set`; write the final state file on
shutdown (and a `stopped_at`); join workers with the documented 30 s budget
or document 5 s; include thread health in `state.json`; remove
`ShutdownCoordinator` dead code. Add an integration test that runs the
daemon under `systemd-run --user --property=Type=notify` (or a container
with systemd) and asserts `active`.

### W6 — Logging and stats integrity

Changes: emit `BallastProvisioned/Released/Replenished` and
`PolicyTransition` events from the daemon and store them (`ballast_inventory`
upserts on every change); make degradation constants match docs (or docs
match code) and enable the RAM fallback in the daemon config; test the
SQLite trip/reopen path; only `VACUUM` when `auto_vacuum` changes; `stats`
`avg_age_hours` real or removed.

### W7 — Scanner v2 hardening and honesty

Changes: index replay under Orange+ re-scores each persisted candidate with
fresh min-age, active-reference, and sacred-overlap checks before dispatch
(or routes through the same `should_skip` closure plus a fresh
`ScoringInput`); move the stowaway sacred check into
`DeletionExecutor::preflight_check`; README and `engine.rs` state that v2 is
the default and what v1 is for; capture a live A/B artifact on one fleet
host and close `bd-xtpv.8` on evidence; either implement fanotify behind a
safe crate or remove the capability probe wording; macOS FSEvents via a safe
crate or explicit "reconciliation-only" in docs.

### W8 — Ballast integrity

Changes: `verify()` and `prune_orphans()` under the flock; `sbh ballast
status` is read-only (no pruning); CLI enumerates the daemon's per-mount pools;
APFS added to the preallocate-friendly set so daemon and CLI provision the
same way; release-controller cooldown reset runs on every tick, not only at
Green; document `<mount>/.sbh/ballast`.

### W9 — macOS closeout

Changes: rewrite epic acceptance criterion 6 (macos-13 → macos-15-intel);
measure and budget cold-start `sbh status` latency (replace `/sbin/mount`
with `getfsstat` via a safe crate or cache across processes); add a deadline
to `open_files_under`/`executables_under`; separate purgeable from
snapshot-retained bytes or label them as one estimate; add a
`~/Library/Caches` rule or drop the claim; fix `ThrottleInterval` in docs;
refresh the parity audit to reflect August reality and close `bd-r7m7.17`
with either CI proof or an explicit operator decision.

### W10 — Proof: a real daemon end-to-end suite

Changes: turn the sandbox scripts from this audit into
`tests/daemon_e2e.rs`: a temp root with stale/fresh/git/open-file/lease
fixtures, a pressure injection hook (`[telemetry] fs_stats_override_file`
read only when `SBH_TEST_MODE=1`, or a loop-mounted small filesystem in CI),
and assertions on deletions, ballast release, JSONL/SQLite rows, explain ids,
state.json fields, and CPU time. Convert the placeholder test files into real
tests instead of deleting them. Make chmod-based tests skip under root. Run
the suite in CI on Linux and macOS.

### W11 — Documentation reconciliation

Changes: README sections for thresholds, formulas, config example, command
reference (add `service`, `log`, `setup`, `truncate-logs`, `doctor
--release`, `lease`), dashboard availability, release assets, troubleshooting
unit names; AGENTS.md key-files table and config table; CHANGELOG release
markers; delete nothing, correct everything; add a CI check that every
`sbh <command>` mentioned in README exists in `sbh --help`.

### W12 — Tracker hygiene

Changes: reopen or annotate the false-closed beads; create beads for every
row above (done as the output of this document); add the missing
`.beads/.gitignore` patterns; decide whether `beads.db` stays tracked in git
(recommendation: untrack, keep `issues.jsonl` canonical — requires operator
approval since it removes a tracked file).

## 7. Sequencing

1. W0 (gates) and W12 (tracker) immediately; nothing else is trustworthy
   without W0.
2. W1 (reclaim before the cliff) and W3 (truthful CLI) in parallel; W10's
   daemon e2e is built alongside W1 as its acceptance test.
3. W4 (release contract + pipeline) and W5 (systemd) next; they unblock
   shipping W1/W3 to the fleet and the Mac.
4. W2, W6, W7, W8, W9 after the core is delivering; each has its own proof.
5. W11 continuously, finishing after everything else lands.

Critical path: W0 → W1 (+W10) → W4 → fleet rollout of v0.5.2.

## 8. Decisions needed from the operator

1. Should Orange delete definite artifacts and release ballast by default
   (this plan says yes; it is what the README promised)?
2. Ship the TUI in default builds (this plan says yes) or delete the README
   dashboard section?
3. Release asset contract: return to `.tar.xz` + sidecars as canonical with
   raw mirrors (this plan), or make raw binaries canonical and change the
   updater?
4. Untrack `.beads/beads.db` from git (needs explicit permission to remove a
   tracked file)?
5. On this workstation: once W1 ships, remove `/etc/sbh/HOTLOOP_DISABLED`,
   regenerate the unit with `sbh install --systemd`, add a `/`-resident root
   path (e.g. `/home/ubuntu/.cache`, `/var/tmp`) or enable `cross_devices`,
   and provision a partial ballast pool on `/`.
