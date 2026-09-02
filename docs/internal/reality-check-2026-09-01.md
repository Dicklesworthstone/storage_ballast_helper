# Reality Check: storage_ballast_helper (`sbh`) — 2026-09-01

**Method:** README.md, AGENTS.md, every `docs/*.md` plan/signoff document, and the
seven open/in-progress beads were read in full. Seven parallel code audits then
walked every README "How It Works" claim to its implementing code, classified it
(WORKING / PARTIAL / STUB / UNPROVEN / NOT_FOUND / DEAD), and cited `file:line`.
The shipped binary (`sbh 0.5.1` on this host), the live systemd unit, the live
release assets, the Homebrew tap, and the GitHub Actions history were checked
directly. The full test suite, clippy, and fmt were run on HEAD `320d04d`.

**Code = ground truth. Docs = measuring stick.** Everything below cites the code.

---

## 0. The one-paragraph answer

The engine is real and mostly well-built: the daemon loop, PID/EWMA control,
scoring, hard vetoes, ballast pools, dual logging, notifications, leases,
scanner v2, writeback tuning, and the macOS platform layer all exist, are wired,
and pass 1,757 tests. But the project does **not** deliver on the README as a
whole. Four documented features are dead or absent (`sbh explain`, `sbh
bootstrap`, uninstall cleanup modes, the TUI dashboard in any released binary).
Self-update is broken by a release-naming drift. System-scope systemd installs
use `Type=notify` without ever sending `READY=1`. The README config example
silently discards about twenty keys. The release pipeline has not run since
v0.4.28; v0.5.x was hand-published; the Homebrew tap is 13 releases behind; no
Actions run has happened since 2026-08-20; `clippy -D warnings` is red. And on
the operator's own workstation — the machine this tool was written to protect —
`/` sits at 12% free (Orange), the daemon is disabled by a hand-made kill
switch, the root-volume ballast pool is empty, and `sbh status` reports the
daemon as running anyway.

---

## 1. Vision Checklist

Sources: README.md (R), AGENTS.md (A), docs/scanner-redesign-event-driven.md (S),
docs/tui-*.md (T), bead epics (B). Status uses the skill vocabulary.
"Bead" = an open/in-progress bead covers it.

| # | Vision goal | Source | Status | Severity | Bead | Evidence |
|---|---|---|---|---|---|---|
| V1 | Predictive pressure control: EWMA forecast + PID urgency acts before disks go critical | R L28, L826-882 | WORKING (docs wrong) | Minor | — | `monitor/ewma.rs:196-460`, `monitor/pid.rs:193-217`, 29 tests. Alpha formula in README is inverted vs code (`ewma.rs:282-297`); setpoint is `green_min_free_pct` not 18.0 (`loop_main.rs:865`); Critical is `< red_min`, not `red_min/2` (`pid.rs:318`). |
| V2 | Multi-volume ballast pools that free space on the exact filesystem under pressure, instantly | R L29, L1121-1162 | PARTIAL | **Critical** | — | Pools work (`ballast/coordinator.rs:179-308`, 21 tests) but provisioning refuses below 20% free (`manager.rs:36`), so the pressured volume can never get a reserve once it is already low. On this host `/` = 12% free, pool empty, `doctor --system` FAILs "ballast emergency reserve". `sbh ballast status` shows only the configured dir, not per-volume pools; state.json reports 5 missing files as "released". `verify()` takes no flock (`manager.rs:524`). |
| V3 | Safe artifact cleanup: deterministic scoring + hard vetoes (`.git`, protected, too-recent, open files) | R L30, L884-1119 | WORKING | Minor | — | `scanner/scoring.rs`, `deletion.rs:595-683` (pre-flight incl. hardcoded source-tree refusal), 165 tests. Docs wrong: age curve is 4-row monotonic (`scoring.rs:852-867`) not the 8-row table; breaker trips at 5 not 3 (`deletion.rs:76`); location rows for `target/` require `/data/projects/` prefix (`scoring.rs:780-785`); pattern count is ~51 named + ~39 platform rules, not "hundreds". |
| V4 | Zero-write emergency mode recovers a 99%-full disk | R L31, L1337-1352 | WORKING | — | — | `cli_app.rs:9613-9745`, Review escalation, e2e cases. |
| V5 | Project protection via `.sbh-protect` markers, config globs, sacred catalog | R L32, L1060-1071 | WORKING | — | — | `scanner/protection.rs` (55 tests), `sacred.toml` written by `sbh protect` (`cli_app.rs:7320`), `status --sacred`. |
| V6 | Explainable decisions: evidence ledger + `sbh explain --id` shows why each action happened | R L33, L60, L406, L1848; A L379; architecture diagram "Evidence Ledger + Explain API" | **NOT_STARTED** at the CLI, **STUB** in the daemon | **Critical** | NO_BEAD | `sbh explain` → "unrecognized subcommand". `DecisionRecord` with 4 explain levels exists (`scanner/decision_record.rs`, 24 tests) and is built by `daemon/policy.rs:478-679`, but `loop_main.rs:5585-5589` reads only `approved_for_deletion, mode` and drops the record. No `ActivityEvent` carries it; nothing persists it. Design principle #4 ("Explainability is mandatory") is not implemented. |
| V7 | Strong observability: `status`, `dashboard`, `stats`, `blame`, structured logs, decision traces | R L34 | PARTIAL | **Critical** | — | `status --json` reports `daemon_running: true` while the daemon has been dead since 2026-08-30: fallback scans `/proc/*/cmdline` for any process containing both substrings "sbh" and "daemon" (`cli_app.rs:7031-7070`) and matched my own shell. `sbh stats` as non-root on a root-owned DB fails with SBH-2102 "readonly database" because the logger always opens READ_WRITE\|CREATE (`logger/sqlite.rs:32-36`); the v0.5.1 root-DB hint only fires for "no database" and hard-codes `/root/.local/share/sbh` (`cli_app.rs:2439`). `blame` works (reads `io_history.bin`, not SQLite as README says). Dashboard: see V14. Decision traces: see V6. Linux JSON emits a `platform.darwin.apfs` block of nulls plus hard-coded `free_excludes_purgeable: true` on every mount (`cli_app.rs:7101-7141`). |
| V8 | Production rollout safety: observe → canary → enforce with automatic fallback and guardrails; never auto-promotes | R L35, L1023-1054, L1237-1270 | PARTIAL (misdocumented) | Major | — | `daemon/policy.rs`: default `initial_mode = Enforce` (`:149`); calibration breach is advisory-only and never demotes (`:760-768`); `FallbackReason::CanaryBudgetExhausted` and `SerializationFailure` are never constructed in production; `check_emergency_escalation` auto-promotes FallbackSafe → Enforce after 5 min at Yellow+ (`:788-822`), contradicting "never auto-promotes"; `recovery_clean_windows` default 10 not 3. Guardrails: window 500 not 50, Pass after 60 obs not 10, reward `ln(2/3)`, clamp upper 3.5 (`guardrails.rs:143-258`). On this host a fresh daemon reported `guard=PASS(e=14.9 …)` after 5 minutes at Orange — 75% of the way to the alarm threshold (20.0) with median error 0.00; whether steady Orange pressure drives spurious alarms is unverified. |
| V9 | Runs as a hardened system service: systemd `Type=notify` + `WatchdogSec`, `sd_notify` heartbeat, `SIGHUP` reload, coordinated shutdown with final state write | R L1417-1447, L1485-1515 | PARTIAL, one **construction bug** | **Critical** | NO_BEAD | System-scope unit emits `Type=notify` + `WatchdogSec=60` (`daemon/service/systemd.rs:120-124`); the daemon sends `WATCHDOG=1` (`:339-347`) but **never `READY=1`** (0 hits in `src/`, `tests/`). systemd will hold such a unit in `activating` until `TimeoutStartSec` (90 s) and then kill it, on every start. No test starts a real unit. The unit on this host is a hand-written `Type=simple` file with none of the documented hardening, plus operator drop-ins (`CPUQuota=10%`, `ConditionPathExists=!/etc/sbh/HOTLOOP_DISABLED`); bootstrap only detects a stale `ExecStart` binary, not unit-content drift. Shutdown writes no final state file and joins workers with a 5 s timeout, not 30 s (`loop_main.rs:3597-3640`); `ShutdownCoordinator` is dead code (`signals.rs:160-195`). Self-monitor: only scanner and executor heartbeat; `ThreadStatus::Dead` is never produced; threshold is 10 s not 60 s. |
| V10 | Full macOS parity with signed, notarized releases and an auto-updated Homebrew tap | R L146-195, L1517-1529; B bd-r7m7, bd-ykwh | PARTIAL | Major | bd-r7m7 (stale), bd-ykwh.3 (stale) | Platform code is real: every PAL method implemented on macOS (`platform/macos/pal.rs:62-314`), launchd install/uninstall, `doctor --pal`, APFS/TM/Electron/DerivedData rules; 77 macOS-only tests. But `release.yml` last succeeded for **v0.4.28 (2026-06-08)**; 12 subsequent release runs failed or were cancelled; v0.5.0/v0.5.1 were tagged and hand-published with raw `sbh_darwin_arm64`-style assets, no tarballs, no per-asset `.sha256`, no provenance, and no workflow proof of signing/notarization. The tap `Dicklesworthstone/homebrew-sbh` points at v0.4.28. The in-repo formula still holds v0.4.8 placeholder hashes. bd-r7m7.17's blocker (queued runners) was resolved in May; the bead has not been touched since. |
| V11 | Self-update with rollback, cache control, backup management, and verification | R L418, L595-646 | **REGRESSED** | **Critical** | NO_BEAD | `ReleaseArtifactContract::asset_name_for_tag` builds `sbh-v0.5.1-x86_64-unknown-linux-gnu.tar.xz` (`cli/mod.rs:263-275`); that URL returns **HTTP 404**; the release publishes `sbh_linux_amd64` (200). `sbh update --check` passes only because the binary is already current. Commits 4837603/702667e patched the shell installers but not the Rust contract. `curl` calls in `update.rs:1178-1204` send no User-Agent (AGENTS.md rule). Backup/rollback/prune code is real (`update.rs:293-484`). |
| V12 | Bootstrap self-healing: 15 migration reasons, 10 repair actions, runs during install and via `sbh bootstrap` | R L218-267 | **DEAD CODE** | Major | NO_BEAD | `src/cli/bootstrap.rs` (2,860 lines, 75 tests) has zero callers outside itself; no `Command::Bootstrap`; `sbh install` never invokes it. The README section describes code that never runs. |
| V13 | Uninstall with five cleanup modes, category tagging, backup-first, `--dry-run`, JSON plan | R L1603-1635 | **DEAD CODE** | Major | NO_BEAD | `src/cli/uninstall.rs` (1,246 lines, 29 tests) has zero callers. `UninstallArgs` has only `--systemd/--launchd/--user/--scope/--purge` (`cli_app.rs:279-309`); `--purge` calls `install::run_uninstall_cleanup` with hard-coded flags (`:2378-2391`). `--keep-data`, `--keep-config`, `--keep-assets`, `--dry-run` do not exist. |
| V14 | Live TUI dashboard: 7 screens, palette (36 actions), incident playbook, quick-release, LogSearch, Diagnostics thread status, preferences | R L421-577, L1697-1710; T signoffs | **UNSHIPPED** + internal STUBs | **Critical** | NO_BEAD | `tui` is not a default feature; CI/release build `--no-default-features --features cli,daemon,sqlite`. Shipped `sbh dashboard` → `sbh: TUI feature not enabled. Rebuild with --features tui` (exit 2); `--legacy-dashboard` is `status --watch` in a loop. `--start-screen` does not exist. Inside the TUI build: ballast release confirmation has no Enter handler and no executor (`tui/input.rs:206-251`); LogSearch header literally renders `query <not-yet-editable>`; VOI overlay is static text; Diagnostics "thread status" is not in the state file and not rendered; `REDUCE_MOTION` is never read; prefs file is `preferences.json` not `dashboard-preferences.json`. `src/cli/dashboard.rs` (749 lines) is unreachable. `scripts/quality-gate.sh` TUI stages run `cargo test --lib tui::…` without `--features tui` and pass with zero tests. Signoff docs (2026-02-16) predate the feature gate. |
| V15 | Kernel writeback tuning: `sbh tune --apply`, `--revert-writeback`, `doctor --system`, install-time apply | R L1531-1568 | WORKING | — | — | `tuning/writeback.rs:88-108`, `cli_app.rs:3512-3715`, `doctor --system` PASS on this host. |
| V16 | Scanner v2: event-driven, pressure-gated, opaque-tree pruning, persistent index; promoted only after live A/B parity | S §5, §7; R L1354-1378; B bd-xtpv.8 | WORKING, promotion un-evidenced | Major | bd-xtpv.8 (in_progress, stale) | v2 is fully wired into the daemon (`loop_main.rs:3985-4170`) and is the **code default** since v0.4.32 (`config.rs:670`). README L652/L1365, the design doc (§5, L285), and the bead all still say "default remains v1". The fleet A/B CPU-seconds/day, deletion-parity, and pressure-response evidence the design doc requires was never recorded; v1 was never removed. Steady-state "<1% of one core" acceptance is unproven. |
| V17 | Active-target leases (`sbh lease run/status/renew`) with kernel lock, watchdog, budgets | R L367-395, L1084 | WORKING | — | — | `scanner/active_lease.rs:43-51`, `cli_app.rs:7513-7689`, 11 + 7 tests. |
| V18 | Special-location monitoring (/dev/shm, tmpfs, /tmp, /data/tmp) and swap-thrash detection | R L1195-1222 | WORKING (README inverted) | Minor | — | `monitor/special_locations.rs:80-127`, `loop_main.rs:1090-1101`. README says "≥ 8 GiB free" flags thrash; code flags when available RAM **<** 8 GiB. `SESSION_REPORT_EXPLORATION.md` claims a rename that never landed. |
| V19 | Dual logging: SQLite WAL + JSONL, degradation chain, rotation, retention | R L1272-1301 | WORKING (constants differ) | Minor | — | `logger/dual.rs`, `sqlite.rs`, `jsonl.rs` (43 tests). SQLite is disabled after **3** failures, 50 is the reopen cadence (`dual.rs:300-330`); three tables, not one per event class; blame data is not in SQLite. |
| V20 | Notifications: desktop, webhook, file, journal with severity filtering and templates | R L1303-1335 | WORKING | — | — | `daemon/notifications.rs` (35 tests). File channel has no `min_level`. |
| V21 | Supply-chain verification: SHA-256, Sigstore, macOS codesign identity, `--offline`, loud `--no-verify` | R L1570-1601 | PARTIAL | Major | bd-t951 (open) | Code paths exist (`cli/mod.rs:543-658`, `update.rs:1355-1400`). But v0.5.x assets ship only a `SHA256SUMS` aggregate (no per-asset `.sha256`, no `.sigstore`, no `release-provenance.json`); "BSD-style" checksum parsing handles GNU `hash  file` only; `SigstorePolicy::Optional` is unreachable; the root `install.sh` (91 lines) is a different, weaker installer than `scripts/install.sh`. |
| V22 | Engineering quality gates: fmt clean, `clippy --all-targets -D warnings` clean, all tests pass, 20-stage quality gate, CI green | R L1728-1755; A L176-194; CHANGELOG v0.5.0 | **REGRESSED** | Major | NO_BEAD | HEAD `320d04d` on nightly 2026-08-31: fmt clean; **clippy 61 errors (lib test) + 1 (bin test)** — 53× `assert_is_empty`/`assert_is_not_empty`, 5× `duration_suboptimal_units`, 2× `unchecked_duration_subtraction`, 1 `const_is_empty`, 1 `redundant_clone` across 20 files; tests 1,419 lib + 122 bin + 213 integration + 3 doc = **1,757 pass, 0 fail** (of ~2,841 `#[test]` functions in the tree; ~999 are tui-gated and ~95 macOS-gated). CI: **all three GitHub workflows are `disabled_manually`** (CI, Release, cert-expiration); last green `ci.yml` on main 2026-08-06; of the 15 most recent runs 1 succeeded, 7 failed, 7 were cancelled; last run of any kind 2026-08-16/20 (clippy on a different nightly: `errors.rs:32`, `predictive.rs:337,364`). No branch protection or rulesets on `main`. `rust-toolchain.toml` pins bare `nightly`, so every new nightly can break the gate. `scripts/quality-gate.sh` (21 stages, not 20; `installer` stage undocumented) is referenced by zero CI jobs; its 9 `tui-*` stages and `fallback` run `cargo test --lib tui::…` **without `--features tui`** and pass with zero tests. `tests/installer_e2e.rs` (43), `tests/stress_harness.rs` (9), and every `repro_*`/`regression_*` file run nowhere in CI; `examples/` and `benches/` are never built by CI (clippy is `--lib --bin sbh`). `tests/repro_issue.rs` (1 line), `repro_glob.rs` (comment only), `repro_tui_panic.rs` (tests string slicing) are placeholders; `tests/fallback_verification.rs` (44 tests) is tui-gated and never runs; `tests/regression_path_traversal.rs` is `#[ignore]`d and documents an unfixed lexical `..` escape in `resolve_absolute_path`. `docs/testing-and-logging.md` lists six coverage-map file paths that do not exist and test counts stale by 1.5-3.7×. |
| V23 | Documentation is an accurate operator contract (README config example, thresholds, module map) | R, A | **REGRESSED** | Major | NO_BEAD | README config example (L650-756) parses but silently discards `[monitor]`, `[ballast] per_volume_*`, `[ballast.overrides] file_size_mb`, `[scoring.weights]`, `[policy] mode/canary_delete_cap_per_hour/fallback_safe`, `[guardrails]`, `[logging]` — no struct uses `deny_unknown_fields` (`core/config.rs`). The live `/etc/sbh/config.toml` on this host uses `[scoring.weights]` and is therefore ignored too. AGENTS.md pressure table (35/20/10/5) is wrong (code 20/14/10/6); AGENTS.md module map omits `tuning/`, `platform/{linux,macos}/`, `scanner/{engine,events,index,active_lease,log_truncator,decision_record}.rs`, all of `tui/`; "Key Files" line counts are off 2-7× (`cli_app.rs` "~4800" is 14,086; `loop_main.rs` "~1170" is 8,264). README walker paragraph inverts bounded/unbounded channels (`walker.rs:368-369`). ~45 discrepancies total are listed in §3. |
| V24 | "Does `sbh` delete source code? No." | R L1835-1836 | Historically **VIOLATED**, now hardened | Major | — | CHANGELOG v0.4.25 L270: 2026-05-16 "fleet carnage wiped ~87 working trees under /data/projects on trj"; 2026-05-22 ~28 crate dirs deleted across four workers. Hardcoded `HardcodedSourceTree` and `LooksLikeSourceCode` vetoes were added (`deletion.rs:595+`). The FAQ answer is not honest about the history or the mechanism that now makes it true. |
| V25 | Near-idle daemon: steady state < 1% of one core; never spins | S §7; R L1489-1494 | UNPROVEN | Major | bd-xtpv.8 | Duty-cycle limiter (`loop_main.rs:404-482`) and device-affinity back-off (`:2801-2840`) exist with tests. Operator kill switch `/etc/sbh/HOTLOOP_DISABLED` (re-created 2026-08-30) says the daemon "sits in Red urgency and spins at 100% of a core" when `/` is below the ballast floor; a `CPUQuota=10%` drop-in backstops it. The last 5-minute run consumed 33 s CPU and a 10 GB memory peak (consistent with ballast provisioning, not necessarily a spin). No measurement of steady-state CPU exists in the repo. |
| V26 | The product protects the operator's own primary host | R "The Problem in Depth"; B bd-r7m7 ("Operator surprise is failure") | **FAILED in practice** | **Critical** | NO_BEAD | This host: `/` 977 GB at 88% used (12% free, Orange). Daemon: `sbh.service` inactive since 2026-08-30 14:59, gated by the kill switch. Ballast on `/`: 0 of 5 files (floor 20% > current 12%). Scan roots: `/tmp` (tmpfs) and `/data/tmp` (btrfs on `/data`) — neither is on `/`, so the daemon logged "cannot reclaim — backing off" on its last run. What fills `/`: `~/.local/share` 199 GiB, `~/.rustup` 33.6 GiB, `/usr` 29.7, `/opt` 17, `/var/lib/snapd` 8.8 — none scanned, and the default roots deliberately exclude `$HOME` after the May incidents. `sbh status` says `daemon_running: true`. The operator has no reserve, no reclaim, and a green light. |

**Delivery score:** 10 of 26 goals fully WORKING as documented (V4, V5, V15,
V17, V20 plus V1/V3/V18/V19 with doc corrections, V16 as code); 4 DEAD or
UNSHIPPED (V6, V12, V13, V14); 3 REGRESSED (V11, V22, V23); 1 FAILED in the
field (V26); the rest PARTIAL.

**Bead coverage:** of the 16 goals at PARTIAL or worse, **13 have no bead at
all**. The three open epics (macOS parity, release engineering, scanner v2) are
4 months stale and their recorded blockers no longer exist. Closing every open
bead would not touch V2, V6, V7, V8, V9, V11, V12, V13, V14, V22, V23, V25, or
V26.

---

## 2. Answers to the five reality-check questions

### 2.1 What IS working right now

- **Control loop:** monitor thread, EWMA + PID, predictive boost, behavior modes,
  special-location probes, swap-thrash detection, duty-cycle limiter,
  device-affinity back-off, repeat-deletion dampening. 404 tests in
  `src/daemon` + `src/monitor`, zero ignored.
- **Scanner:** v2 opaque-pruning walker with persistent index, inotify
  invalidation, and Green/Yellow no-op; v1 full walker retained; scoring with
  Bayesian decision; 7-layer pre-flight including the post-incident hardcoded
  source-tree refusal; open-file evidence with budgets; rch/CACHEDIR.TAG-aware
  classification; log truncation of open append-only logs (undocumented).
- **Safety surface:** `.sbh-protect`, `sacred.toml`, sacred catalog, active
  leases with kernel locks, emergency zero-write mode with Review escalation.
- **Ballast:** per-volume pools, fallocate/random strategies, flock (except
  verify), release ladder, replenish with cooldown, orphan pruning, TM-snapshot
  warning on macOS.
- **Logging/notify:** dual SQLite+JSONL with degradation chain and rotation;
  four notification channels.
- **Platform:** Linux and macOS PALs are both complete; launchd and systemd
  unit generation; `doctor --pal/--system/--release`; writeback tuning.
- **Install surface:** `scripts/install.sh` (versioned → legacy → raw asset
  probing, codesign check on macOS), wizard, `--auto`, `--offline`, backups.
- **Tests:** 1,757 pass on Linux; 77 macOS-only tests passed on the last
  macOS CI lanes (2026-08-17).

### 2.2 What is NOT working or not implemented

Ranked by how badly it breaks the promise:

1. **Field outcome on the primary host (V26)** — disabled daemon, empty
   reserve, un-scannable pressured volume, false "running" status.
2. **`sbh explain` / evidence ledger (V6)** — absent; records discarded.
3. **System-scope systemd start (V9)** — `Type=notify` without `READY=1`.
4. **Self-update (V11)** — artifact name contract 404s against current releases.
5. **Dashboard (V14)** — not in any released binary; stubs inside.
6. **Bootstrap (V12) and uninstall modes (V13)** — 4,100 lines of tested,
   documented, unreachable code.
7. **`daemon_running` false positive and `stats` readonly failure (V7).**
8. **Ballast cannot be provisioned below the floor (V2)** — the reserve is
   unobtainable precisely when it is needed.
9. **Release pipeline / tap / provenance (V10, V21)** — abandoned since v0.4.28.
10. **Quality gates (V22)** — clippy red, CI red, no Actions since 08-20,
    vacuous TUI gate stages, placeholder test files.
11. **Documentation contract (V23)** — ~45 concrete discrepancies; config
    example keys silently ignored.
12. **Policy engine semantics (V8)** — docs describe safeguards the code
    deliberately removed or never wired.

### 2.3 What is blocking us

- **No feedback loop from the field.** Nothing in the product notices that the
  daemon is disabled, the reserve is empty, or the pressured volume has no
  scannable root; `status` actively hides the first.
- **No doc-to-code contract.** Constants, tables, config keys, and command lists
  in README/AGENTS are hand-maintained and drift with every change.
- **Config permissiveness.** `#[serde(default)]` without `deny_unknown_fields`
  turns typos and stale keys into silent no-ops.
- **Release process bypass.** Tagging plus hand upload replaced `release.yml`,
  breaking the updater, the tap, checksums, and provenance in one move; there
  is no single "release contract" shared by installer, updater, workflow, and
  formula.
- **Toolchain drift.** Bare `nightly` in `rust-toolchain.toml`; CI and local
  break on every new lint.
- **CI switched off.** All three workflows are `disabled_manually`; nothing has
  run since 2026-08-16/20, and `main` has no branch protection. The
  macOS-parity beads still cite a May runner-queue blocker that was resolved.
- **Verification that runs nowhere.** `quality-gate.sh` is not in CI and its
  TUI stages are vacuous; installer/stress-harness/repro tests are not in CI;
  examples and benches are never compiled by CI.
- **Stale planning state.** 7 open beads, all 3-4 months untouched, two of
  them tracking blockers that no longer exist.

### 2.4 Would implementing all open beads close the gap?

**No.** The seven open beads cover three things: macOS parity closeout
(bd-r7m7, bd-r7m7.17), macOS release engineering (bd-ykwh, bd-ykwh.3), scanner
v2 validation and promotion (bd-xtpv, bd-xtpv.8), and a release-asset audit
(bd-t951). Finishing them would (a) close epics whose work is already done,
(b) record A/B evidence for a default that already shipped, and (c) add a
release-asset guard to a workflow that is not being run. None of them touches
the explain gap, the READY=1 bug, the updater contract, the dashboard, the dead
bootstrap/uninstall modules, the status false positive, the ballast floor, the
config permissiveness, the doc drift, the clippy/CI breakage, or the field
failure on the primary host.

### 2.5 Vision goals with no bead coverage

V2, V6, V7, V8, V9, V11, V12, V13, V14, V22, V23, V24, V25 (partially), V26.

---

## 3. Documentation discrepancy ledger (code is right; doc is wrong)

Grouped by file. Each item is a concrete edit target.

### README.md

| Line(s) | README says | Code does |
|---|---|---|
| 8, 131, 143, 151 | one-liner installs via `scripts/install.sh` | true; but root `install.sh` is a different, weaker installer (91 lines, raw assets only) |
| 60, 406, 1766, 1848 | `sbh explain --id <decision-id>` | no such command |
| 220, 259-267 | `sbh bootstrap`, runs during install | no such command; module has no callers |
| 233 / AGENTS 320 | 15 migration reasons / 13 | code has 15 (`bootstrap.rs:23-54`) — unreachable |
| 304 | default ballast pool paths | correct |
| 421-577 | TUI cockpit via `sbh dashboard` | release binary exits 2; needs `--features tui` build |
| 432 | `--start-screen ballast` | flag does not exist |
| 437 | `--new-dashboard` overrides kill switch | kill switch wins (`cli_app.rs:4715-4761`) |
| 461, 471, 492 | Ballast screen release/replenish controls; `x` opens confirmation | dialog cannot be confirmed; nothing executes |
| 462 | LogSearch search/filter | header renders `<not-yet-editable>` |
| 463, 1459 | Diagnostics thread status from state file | not in state file; not rendered |
| 536-545 | 7 playbook entries (listed) | 7 entries with different labels/order; filtered to 0 at Normal |
| 562 | `dashboard-preferences.json` | `preferences.json` |
| 567 | `REDUCE_MOTION` honored | never read |
| 652, 818, 1365 | scanner default `v1` | default `v2` since v0.4.32 (`config.rs:670`) |
| 658-664 `[monitor]` | thresholds section | no such section; `[pressure] *_min_free_pct` |
| 667-676 `[ballast]` | `per_volume_file_count`, `per_volume_file_size_mb`, override `file_size_mb` | `file_count`, `file_size_bytes`, override `file_size_bytes` |
| 678-683 `[scoring.weights]` | nested table | flat `[scoring] location_weight …` |
| 685-688 `[policy]` | `mode`, `canary_delete_cap_per_hour`, `fallback_safe` | `initial_mode`, `max_canary_deletes_per_hour`, `kill_switch`, … |
| 690-692 `[guardrails]` | section | none; `calibration_floor` is `[scoring]` (default 0.40) |
| 694-696 `[logging]` | `sqlite_path`, `jsonl_path` | `[paths] sqlite_db`, `jsonl_log` |
| 822 | "newest request wins" | only for urgent replace-on-full; else deferred |
| 836-838 | `alpha = 0.20*burstiness + base`, clamp [0.1, 0.8] | `alpha = base/(1+2*burstiness)`, clamp [0.10, 0.75] |
| 850 | confidence 70/30 | 50/20/30 with stability term |
| 858 | setpoint 18.0% | `green_min_free_pct` (20.0) |
| 878-880 | Critical `< 3%` = `red_min/2` | Critical `< red_min` (6%) |
| 882 | 0.70 floor within 30-min horizon | at `horizon/2` (15 min); 0.90 at 5 min; 1.0 at 1 min |
| 904, 1661 | "hundreds of patterns", "~200" | ~51 named + ~39 platform rules |
| 906-919 | 8-row non-monotonic age curve | 4-row monotonic (`scoring.rs:852-867`) |
| 1031, 1038 | Observe default; never auto-promotes | Enforce default; auto-promotes FallbackSafe → Enforce after 5 min |
| 1042, 1050 | 3 Fail windows demote; 3 clean windows recover | 25 windows, advisory only; 10 clean windows + 300 s |
| 1075-1085 | 8-point pre-flight incl. stowaway | stowaway check lives in scoring; identity/source-marker checks undocumented |
| 1090 | breaker at 3 errors, 30 s | 5 errors; exponential 30 s → 5 min |
| 1213 | thrash when ≥ 8 GiB free | when available < 8 GiB |
| 1248-1268 | window 50, Pass at 10, `ln(0.8)`, clamp [-5, 5] | 500, 60, `ln(2/3)`, [-5, 3.5] |
| 1278-1280 | tables per event class; blame from SQLite | 3 tables; blame from `io_history.bin` |
| 1295 | SQLite disabled after 50 failures | after 3; 50 = reopen cadence |
| 1386-1388 | bounded work queue 4096, unbounded results | unbounded work queue, bounded results 10,000 |
| 1440-1445 | final state write, 30 s join | no final write; 5 s join |
| 1455 | 60 s stall threshold; all four threads heartbeat; `Dead` status | 10 s; scanner+executor only; `Dead` never emitted |
| 1607-1633 | 5 uninstall modes, `--keep-*`, `--dry-run` | only `--purge` |
| 1665, 1825, 1856-1860 | Merkle index live / persists | dead code (`scanner/mod.rs:10` only) |
| 1835 | "Does sbh delete source code? No." | it did (v0.4.25 changelog); now hardcoded-vetoed |

### AGENTS.md

- L253-311 module map: missing `tuning/`, `platform/{linux,macos}/`, `core/{paths,update_cache}.rs`, `prelude.rs`, `scanner/{engine,events,index,active_lease,log_truncator,decision_record}.rs`, `daemon/process_io_history.rs`, `daemon/service/{systemd,launchd,launchctl}.rs`, all 27 `tui/` files, `decision_plane_tests.rs`, `crates/sbh_mach`.
- L317-346 "Key Files" line counts stale by 2-7×.
- L349-404 CLI reference: lists `explain`; omits `doctor`, `service`, `log`, `lease`, `update`, `truncate-logs`.
- L481-486 pressure table wrong (35/20-35/10-20/<5 vs 20/14/10/6).
- L428 `[ballast]` omits `auto_provision`, `overrides`.
- L529 breaker "3 consecutive failures" (code 5).

### docs/

- `scanner-redesign-event-driven.md` L4, L204, L285: "default remains v1".
- `tui-go-nogo-signoff.md`, `tui-signoff-decision.md`: 1,992 vs 2,020 tests; both predate the feature gate; neither reproducible today.
- `legacy-dashboard-deprecation-decision.md` L57: promised `[DEPRECATED]` warning absent.
- `post-rollout-monitoring-and-handoff.md` L51: "parity_harness + fallback_verification every PR" — never in CI.
- `frankentui-compliance-plan.md`: every checkbox unchecked.
- `internal/macos-parity-completion-audit.md`: 786-line diary with contradictory stale literals; conclusion (v0.4.22 closeout) never propagated to beads.
- `testing-and-logging.md` L45-62: coverage map names `platform.rs`, `monitoring/ewma.rs`, `monitoring/pid_controller.rs`, `monitoring/predictive_action.rs`, `scanner/pattern_registry.rs`, `scanner/deletion_executor.rs` — none exist. L92-99 test counts (836/1,776/33/183) vs ~1,600/2,576/122/265. L121 lists `repro_issue.rs`, `repro_glob.rs` as regression tests. L165-186 says 20 stages (21). Per-case harness logs under `$TMPDIR/sbh-test-logs/` are undocumented.
- `post-rollout-monitoring-and-handoff.md` L49: "quality-gate.sh in CI — every PR, nightly on main" — never referenced by `ci.yml`, which has no `schedule:` trigger.
- `.github/workflows/ci.yml` L24-25, L39-43 and `release.yml` L82-88: "Strip local-only TUI path deps" step `sed`s `/dp/frankentui` path deps that no longer exist (git tags since 2026-06-13).
- `CHANGELOG.md`: header promises `[release]` markers; `v0.5.1` (published 2026-08-26) lacks one; 13 published versions (v0.4.40, .39, .38, .36, .33, .32, .27, .24, .23, .22, .14, .8, .4, .3, .2, v0.3.17) have no entry at all.
- `SESSION_REPORT_EXPLORATION.md` (root): claims a swap-thrash constant rename that never landed; 3 of 4 claimed fixes exist.

### Repository clutter (AGENTS.md "No File Proliferation")

- `install.sh` (root, 91 lines) duplicates `scripts/install.sh` (1,290 lines) with a weaker, divergent contract (raw assets only, no `--version`, no service restart, no codesign check).
- `Codex-upgrade-progress.json` (root, tracked) duplicates `docs/internal/dependency-upgrade-log-2026-05-13.md`.
- `SESSION_REPORT_EXPLORATION.md` (root, tracked) is a partially false session note.
- `test_cast` (root, 4.3 MB unstripped ELF from April; gitignored).
- Empty untracked directories `&&`, `>`, `printf`, `artifact-sync-ok`, and `manual-release-artifacts/rch-artifact-sync-probe.txt/` — shell-redirection accidents from May.
- `.gate_sbh_trj.sh` (root, untracked, not ignored) — the only script in the repo that compiles examples/benches/all targets.
- `gh_og_share_image.png` (351 KB) has no in-repo consumer.

(Deleting any of these requires explicit operator permission per AGENTS.md Rule 1; the bridge plan lists them as a decision, not an action.)

---

## 4. Live-host evidence (threadripperje, 2026-09-01)

```
df -h /            977G  849G  118G  88%   (12.0% free → Orange)
sbh.service        inactive (dead) since 2026-08-30 14:59:37; Result=success
/etc/sbh/HOTLOOP_DISABLED   "sits in Red urgency and spins at 100% of a core …
                            Remove only once / is above ~20% free."
/var/lib/sbh/ballast        0 files (floor 20% > 12.8% free at last start)
/data/.sbh/ballast          5 × 2 GiB (provisioned 2026-08-30 14:54)
sbh status --json           daemon_running: true   ← false (substring match on /proc cmdlines)
sbh doctor --system         ballast.reserve FAIL; writeback PASS
sbh stats --window 24h      SBH-2102 attempt to write a readonly database
sbh scan /data/tmp --json   scanner_engine=v2 (config has no engine key)
sbh update --check          artifact_url → …/sbh-v0.5.1-x86_64-unknown-linux-gnu.tar.xz (HTTP 404)
sbh dashboard               "TUI feature not enabled" exit 2 (pty); JSON-mode refusal (pipe)
sbh explain / sbh bootstrap unrecognized subcommand
sbh version --verbose       git_sha/profile/target/timestamp all "unknown" (no build.rs)
cargo clippy --all-targets -D warnings   61 + 1 errors (nightly 2026-08-31)
cargo test --workspace      1,757 passed, 0 failed, 1 ignored
```

---

## 5. Bridge Plan

**Goal:** close every gap in §1 so that `sbh` delivers the README as written, on
the operator's own machine first, with proof. Ordered by vision impact, not
ease. Each gap states current state, target state, success criteria,
implementation plan, dependencies, complexity (S/M/L/XL), the vision goals it
closes, and whether existing beads would close it.

Two cross-cutting rules apply to every item:

- **Nothing is deleted without explicit operator permission** (AGENTS.md Rule
  1). Where a gap's best resolution is removal (dead code, clutter, v1 walker),
  the plan lists it as a decision the operator makes; the default action is to
  wire the code in, not remove it.
- **Every fix carries a proof:** a unit test for the mechanism, an integration
  or e2e test for the behavior, structured logging so a failure is diagnosable
  from the artifact, and, where docs were wrong, a doc-contract test that would
  have caught the drift.

### G1 — Protect a system disk that fills from `$HOME` while below the ballast floor — FAILED → WORKING

**Vision goals:** V26, V2, V25, V7 (daemon liveness).

**Current state.** `BallastManager::provision` refuses when free < 20 %
(`ballast/manager.rs:36`, flat percent, all-or-nothing). Default and
fleet-synced `scanner.root_paths` are `/tmp` and `/data/tmp`; when pressure is
on a device with no root path and `cross_devices=false`, the daemon logs once
and returns (`loop_main.rs:2801-2840`). The Linux cleanup catalog has 7 rules
(`platform/linux/cleanup_catalog.rs`) and is not used as a root source. The
operator kill switch `/etc/sbh/HOTLOOP_DISABLED` records a spin at Red urgency
under exactly these conditions. `sbh status` decides `daemon_running` by a
substring match over `/proc/*/cmdline` (`cli_app.rs:7031-7070`).

**Target state.**
1. **Graduated reserve.** Provisioning is byte-aware and incremental: a file is
   created only if `free_after − file_size` stays above a *reserve floor*
   (`max(orange_min_free_pct, red_min_free_pct + 2 %)` of the volume, configurable
   `ballast.provision_floor_pct`, default follows the pressure thresholds instead
   of a hard 20 %). Between the floor and Green the manager provisions smaller
   files (`ballast.low_space_file_size_bytes`, default 256 MiB) so a partial
   reserve exists rather than none. Never provisions at Red/Critical. Release at
   Red is guaranteed net-positive by construction.
2. **Pressured-device reclaim.** When pressure is on a device with no
   configured root, the daemon derives *catalog roots* for that device from the
   PAL cleanup catalog (Linux: `$HOME/.cache/*`, `$HOME/.cargo/registry/{cache,src}`,
   `$HOME/.cargo/git/checkouts`, `$HOME/.npm/_cacache`, `$HOME/.cache/pip`,
   `~/.local/share/Trash`, `/var/tmp`, `/var/cache/apt/archives`, snap/journal
   caches with explicit rules; macOS: existing catalog) and scans only those,
   under the unchanged hardcoded source-tree vetoes. This is a *catalog-only*
   scan (opaque candidates, no recursive descent into unknown trees). The
   behavior is on by default (`scanner.catalog_roots_on_pressured_device = true`)
   and logs every derived root.
3. **Loud, actionable degradation.** "Pressured mount has no scannable root"
   becomes a `doctor --system` FAIL with remediation, a `status` warning
   (`pressure.mounts[].reclaim_capability = none|catalog|configured`), and a
   notification at Orange+, not a once-per-interval stderr line.
4. **Liveness truth.** The daemon holds an exclusive `flock` on
   `<state_dir>/daemon.lock` (pid + started_at written inside) for its whole
   life. `status`/`check`/`dashboard` probe that lock non-blockingly; if it can
   be taken, `daemon_running=false` with `daemon_state_reason` (`no_lock`,
   `stale_state_file`, `unit_inactive`, `unit_condition_failed`). systemd
   `is-active` and launchd `print` remain secondary signals; the `/proc`
   substring scan is removed. `status` also reports unit `Condition*` gates and
   drop-ins that disable the service.
5. **Steady-state CPU proof.** An integration test runs the daemon binary for
   60 s against a synthetic pressured device with no roots and asserts process
   CPU time < 1 % of one core and zero scan dispatches; a second run with
   catalog roots asserts exactly one bounded catalog scan per pressure epoch.

**Success criteria.**
- [ ] Unit: provisioning on a mock volume at 12 % free with a 10 GiB pool
  creates files until the reserve floor, then stops; at Red creates none.
- [ ] Unit: release at Red on a volume provisioned under the graduated rule
  never drives free space below the pre-provision level.
- [ ] Integration (`tests/daemon_host_protection.rs`, loop-mounted or tmpfs-sized
  fixture): Orange on a device with no configured root → catalog roots derived,
  one bounded scan, candidates only from catalog rules, source-tree vetoes
  still applied, `scan_complete` details carry `root_source = catalog`.
- [ ] Integration: `sbh status --json` reports `daemon_running=false` with
  reason when the daemon is stopped, while a shell whose cmdline contains
  "sbh daemon" is running.
- [ ] Integration: 60 s daemon run at synthetic Orange with no roots: CPU < 1 %
  of a core, no scan dispatched, exactly one `no_scannable_root` event.
- [ ] `doctor --system` on this host FAILs `reclaim.pressured_mount_no_root`
  and PASSes after `catalog_roots` is enabled.
- [ ] Operator runbook (bead) to re-enable `sbh.service` on this host once
  landed: remove kill switch, reinstall generated unit, provision, verify.

**Implementation plan.**
1. `ballast/manager.rs`: replace `MIN_FREE_PCT` gate with
   `ReserveFloor::for_volume(stats, config)`; per-file admission; low-space
   file size; expose `provision_report.reason` (`floor`, `red`, `complete`).
   `ballast/coordinator.rs`: pass pressure thresholds; `install.rs:230`
   `provision(None)` must pass the floor callback.
2. `platform/cleanup_catalog.rs` + `platform/linux/cleanup_catalog.rs`: add
   `CatalogRoot { path_template, disposition, min_age, opaque }` entries and
   `catalog_roots_for_mount(mount, home_dirs)`; `daemon/loop_main.rs` device-
   affinity branch: derive roots, dispatch `ScanRequest { root_source: Catalog }`
   with a fixed budget; `scanner/engine.rs` honors `catalog_only`.
3. `daemon/self_monitor.rs`: `DaemonLock::acquire(state_dir)` (flock via `nix`),
   `DaemonLock::probe`; `cli_app.rs` status/check/dashboard use it; delete the
   substring fallback; `status` JSON gains `daemon_state_reason`, `service_gates`.
4. `cli_app.rs` doctor: new checks `reclaim.pressured_mount_no_root`,
   `service.disabled_by_condition`, `service.unit_drift` (see G3).
5. Tests as listed; e2e section in `scripts/e2e_test.sh` for status liveness.

**Dependencies:** G3 (unit drift check shares the unit-diff code). **Complexity:** XL.
**Would existing beads close it?** No — no bead.

### G2 — Explainability: persist decision records and ship `sbh explain` — NOT_STARTED → WORKING

**Vision goals:** V6, V7 (decision traces), design principle 4.

**Current state.** `scanner/decision_record.rs` defines `DecisionRecord` with
four explain levels; `daemon/policy.rs:478-679` builds one per decision;
`loop_main.rs:5585-5589` keeps only `approved_for_deletion` and `mode` and
drops the rest. No `ActivityEvent` carries a record; no table stores one; no
`explain` subcommand exists; `scan --explain` prints scoring factors inline
with no ID.

**Target state.**
- Every policy decision (daemon and manual `clean`/`emergency`) gets a stable
  **decision ID** = first 12 hex of SHA-256 over (path, device, inode, decision
  timestamp bucket, mode). The ID is printed in `scan --explain`, in `clean`
  output, in `scan_complete`/`deletion` activity events, and in notifications.
- Records are persisted in SQLite (`decisions` table: id, ts, path, dev, ino,
  mode, action, posterior, keep_loss, delete_loss, uncertainty, guard_status,
  vetoes[], factors JSON, explain_l1..l4 text, outcome, outcome_ts) and echoed
  as JSONL `decision_recorded` events. Retention follows the existing 30-day
  prune; `emergency` mode writes nothing (zero-write invariant preserved:
  records are printed, not stored).
- `sbh explain --id <id> [--level 1..4] [--json]` prints the record at the
  requested galaxy-brain level; `sbh explain --path <p>` lists decisions for a
  path; `sbh explain --last N`. `stats` gains `decisions_by_action` and
  `top_veto_reasons`.
- The dashboard Explainability screen reads the same table (G5).

**Success criteria.**
- [ ] Unit: decision ID is deterministic for identical inputs and differs when
  inode changes (recreated dir).
- [ ] Unit: `DualLogger` round-trips a `DecisionRecorded` event to SQLite and
  JSONL; prune removes records older than retention.
- [ ] Integration: daemon run against a fixture produces a `scan_complete` with
  decision IDs; `sbh explain --id` returns the record; `--level 4` includes
  factor contributions and veto chain.
- [ ] Integration: `sbh emergency` prints IDs but writes no DB/JSONL bytes
  (assert file sizes unchanged).
- [ ] e2e: `sbh scan --explain --json` candidates carry `decision_id`.

**Implementation plan.** `scanner/decision_record.rs` (id, serde), `logger/{dual,sqlite,jsonl,stats}.rs` (event + table + queries), `daemon/loop_main.rs` (emit), `cli_app.rs` (`Command::Explain`, `scan --explain` IDs, `clean` IDs), README/AGENTS command tables, e2e section.

**Dependencies:** none. **Complexity:** L. **Would existing beads close it?** No.

### G3 — systemd `Type=notify` without `READY=1`; shutdown/self-monitor honesty; unit drift — construction bug → WORKING

**Vision goals:** V9.

**Current state.** `daemon/service/systemd.rs:120-124` emits `Type=notify` +
`WatchdogSec=60` for system scope; `sd_notify_linux` (`:339-347`) sends only
`WATCHDOG=1\nSTATUS=…`; no `READY=1`, `STOPPING=1`, or `MAINPID=`. Abstract
`NOTIFY_SOCKET` (`@…`) unsupported; send errors discarded. No test starts a
unit. Shutdown writes no final state, joins workers for 5 s
(`loop_main.rs:3597-3640`); `ShutdownCoordinator` unused. Self-monitor: only
scanner/executor heartbeat; `Dead` never emitted; 10 s threshold. The installed
unit on this host is hand-written and unhardened; bootstrap only detects a
stale `ExecStart` binary.

**Target state.**
- `sd_notify("READY=1")` after the daemon finishes startup (config loaded,
  threads spawned, first state write), `STOPPING=1` on shutdown, `STATUS=`
  updates with pressure summary, abstract-socket support, errors logged once.
- Generated unit adds `TimeoutStartSec=30`; user-scope keeps `Type=simple`.
- Shutdown: final `state.json` write with `shutdown_at`, worker join budget
  aligned with `TimeoutStopSec` (configurable, default 25 s), `ShutdownCoordinator`
  either wired as the single implementation or removed (operator decision).
- Self-monitor: all four workers heartbeat; `Dead` emitted when a worker's join
  handle finished without respawn; thresholds documented from constants.
- `doctor --service` compares the installed unit (`systemctl cat`) to the
  generated one and reports drift (missing hardening keys, foreign drop-ins,
  `Condition*` gates) with `sbh service --systemd reinstall-unit` remediation.

**Success criteria.**
- [ ] Unit: a fake `NOTIFY_SOCKET` (bound `UnixDatagram` in a temp dir) receives
  `READY=1` before the first `WATCHDOG=1`, and `STOPPING=1` on shutdown;
  abstract path variant covered.
- [ ] Integration (Linux, when `systemd-run` is available and the test is not
  root-gated away): a transient `Type=notify` unit running `sbh daemon` reaches
  `active` within 10 s and stays active for 30 s; skipped with a logged reason
  elsewhere.
- [ ] Unit: shutdown writes `state.json` with `shutdown_at`; state file schema
  test.
- [ ] Unit: `unit_drift` reports each missing directive from a fixture unit.

**Implementation plan.** `daemon/service/systemd.rs` (notify API, unit text, drift diff), `daemon/loop_main.rs` (READY/STOPPING hooks, final state), `daemon/self_monitor.rs` (heartbeats, Dead), `daemon/signals.rs` (coordinator decision), `cli_app.rs` doctor/service, tests.

**Dependencies:** none. **Complexity:** M. **Would existing beads close it?** No.

### G4 — Release contract: updater, installers, workflow, tap, provenance — REGRESSED → WORKING

**Vision goals:** V11, V21, V10.

**Current state.** Three asset naming schemes coexist: workflow
`sbh-v{tag}-{triple}.tar.xz` (+ `.sha256`), legacy `sbh-{triple}.tar.xz`, and
the hand-published raw `sbh_{os}_{arch}` + `SHA256SUMS`. `scripts/install.sh`
probes all three; `src/cli/mod.rs:263-275` and `update.rs:1096-1102` know
only the first two → 404 against v0.5.x. Updater `curl` has no User-Agent.
`release.yml` last succeeded for v0.4.28; all workflows disabled; tap at
v0.4.28; in-repo formula holds v0.4.8 placeholders; root `install.sh`
diverges from `scripts/install.sh`; `SigstorePolicy::Optional` unreachable;
checksum parser is GNU-only.

**Target state.**
- One `ReleaseContract` in Rust (`cli/release_contract.rs`) is the single
  source of truth: ordered asset schemes, checksum sources (per-asset `.sha256`
  or aggregate `SHA256SUMS`), provenance file name, signature file name, and
  the target-triple ↔ `{os}_{arch}` mapping. The updater, `scripts/install.sh`
  (generated table section), `release.yml` (matrix names via a small `sbh
  release-contract --json` invocation), and the Homebrew formula template all
  consume it. A static test asserts the shell installer's probe table matches
  the Rust contract; a network-gated test resolves the latest real release and
  asserts at least one scheme resolves for every supported target.
- Updater sends `User-Agent: OpenAI File Downloader, XaiImageApiFetch/1.0`
  on every request (AGENTS.md rule); parses both checksum layouts and true
  BSD `SHA256 (file) = hash`.
- `release-provenance.json` becomes a self-describing manifest (assets →
  triple → sha256 → signature/notarization status → built-from SHA) that the
  updater prefers when present; `doctor --release` shows tap version vs latest
  release and flags drift.
- Workflows re-enabled and green (operator action, tracked as an external
  bead); a release-asset audit job downloads the published assets and
  re-verifies (bd-t951's follow-up).
- Root `install.sh` either becomes a thin shim that fetches
  `scripts/install.sh` or is removed (operator decision).

**Success criteria.**
- [ ] Unit: contract resolves `sbh_linux_amd64` for `x86_64-unknown-linux-gnu`
  when tarball names are absent; checksum parsing for GNU, BSD, aggregate.
- [ ] Network test (opt-in `SBH_NET_TESTS=1`): `sbh update --check --force
  --dry-run` against the live latest release resolves an existing URL (HEAD
  200) for the host target.
- [ ] Static test: `scripts/install.sh` probe order equals contract order.
- [ ] Every `curl`/`ureq` call site in `src/cli` sets the User-Agent; grep test.
- [ ] `release.yml` dry-run job validates names against the contract.

**Implementation plan.** `cli/mod.rs`/`update.rs`/`assets.rs` refactor into `release_contract.rs`; `scripts/install.sh` table; `release.yml`; formula; `doctor --release`; tests; CHANGELOG entry.

**Dependencies:** none (workflow re-enable is external). **Complexity:** L. **Would existing beads close it?** Partially — bd-t951 covers the asset audit only.

### G5 — Dashboard: ship it or stop claiming it; finish the stubs — UNSHIPPED → WORKING

**Vision goals:** V14, V7.

**Current state.** `tui` not in default features; releases built without it;
shipped `sbh dashboard` exits 2; `--start-screen` absent; inside the TUI:
ballast confirmation has no executor, LogSearch has no query input, VOI overlay
is static, Diagnostics thread status absent, `REDUCE_MOTION` unread, prefs
file name mismatch; `src/cli/dashboard.rs` unreachable; quality-gate TUI
stages vacuous; signoff docs stale. `cargo check --features tui --all-targets`
compiles today (verified, 15 m 44 s cold).

**Decision (recommended):** ship the cockpit. The original gating reason
(sbh#12: `cargo install --git` could not resolve `/dp` path deps) no longer
applies since the deps moved to git tags. The README, three signoff documents,
and 25 k lines of tested TUI code make the cockpit a headline feature.

**Target state.**
- `tui` joins `default`; CI and release build with it; binary-size delta
  recorded in CHANGELOG. A build without `tui` falls back to the live status
  loop with a one-line warning instead of exit 2.
- `--start-screen <name>` flag (overrides the persisted preference).
- Ballast screen: `x`/confirmation executes release via `BallastManager`
  through the same lock and safety path as the CLI, with result toast and
  activity event; replenish action likewise.
- LogSearch: `/` opens a query line; substring + `event_type:`/`level:`
  filters over the SQLite/JSONL adapters; results paginated.
- Diagnostics: thread statuses come from the state file (G3 emits them);
  VOI overlay renders live scheduler stats from state (`voi` block added to
  `state.json`); `REDUCE_MOTION` honored; prefs file name matches README (or
  README corrected — choose `preferences.json`, document it).
- `quality-gate.sh` TUI stages pass `--features tui`; a CI `tui` job runs
  them; `fallback_verification` runs in CI.
- `src/cli/dashboard.rs`: wire `LegacyFallback` for `--legacy-dashboard` or
  remove (operator decision).
- Signoff docs get a dated addendum with reproducible counts.

**Success criteria.**
- [ ] Release artifact runs `sbh dashboard` in a pty and reaches the Overview
  screen (e2e via `script -qec` with `timeout`, asserting the frame header).
- [ ] TUI unit: confirmation Enter executes `ConfirmAction::BallastRelease`
  against a mock manager; failure path shows error toast.
- [ ] TUI unit: LogSearch query filters events; property test that the
  filter is a subset of the unfiltered list.
- [ ] Diagnostics renders `Stalled`/`Dead` from a state fixture.
- [ ] CI job `tui` green with `--features tui`; `quality-gate.sh` stage counts
  > 0 tests for each TUI stage.

**Implementation plan.** `Cargo.toml` features, `ci.yml`/`release.yml`, `cli_app.rs` (flag, fallback), `tui/{update,input,render,model,adapters,telemetry,theme}.rs`, `daemon/self_monitor.rs` (state fields), `scripts/quality-gate.sh`, docs.

**Dependencies:** G2 (Explainability screen data), G3 (thread status in state). **Complexity:** XL. **Would existing beads close it?** No.

### G6 — Dead modules: bootstrap and uninstall modes — DEAD → WORKING

**Vision goals:** V12, V13.

**Current state.** `cli/bootstrap.rs` (2,860 lines, 75 tests) and
`cli/uninstall.rs` (1,246 lines, 29 tests) have no callers. README documents
`sbh bootstrap [--dry-run]`, install-time repair, and five uninstall modes.

**Target state.**
- `Command::Bootstrap { dry_run, json }` runs `scan_footprints` →
  `plan_migration` → `run_migration` with backups; `sbh install` runs the scan
  and applies safe repairs (permissions, stale PATH lines, unit path) before
  service registration; `doctor --env` reports the health state without
  mutating.
- `sbh uninstall` gains `--keep-data | --keep-config | --keep-assets | --purge`
  (mutually exclusive), `--dry-run`, `--json`, and routes through
  `uninstall::plan_uninstall`/`execute_uninstall`; `install::run_uninstall_cleanup`
  is retired in favor of the module (or the module is removed — operator
  decision; the plan wires it).
- Both are covered by e2e sections and `installer_e2e` cases; README/AGENTS
  tables regenerate from `--help` (G8).

**Success criteria.**
- [ ] e2e: a fixture profile with a stale PATH line and a unit pointing at a
  missing binary → `sbh bootstrap --dry-run --json` lists both reasons;
  `sbh bootstrap` repairs them with backups; second run is a no-op.
- [ ] e2e: `sbh uninstall --dry-run --json` under each mode lists exactly the
  documented categories; `--keep-data` preserves the SQLite/JSONL files.
- [ ] Unit: mutual exclusion of mode flags.

**Dependencies:** none. **Complexity:** M. **Would existing beads close it?** No.

### G7 — Quality gates and CI restoration — REGRESSED → WORKING

**Vision goals:** V22.

**Target state.**
- `rust-toolchain.toml` pins a dated nightly (`nightly-2026-08-25`, the one
  that produced the last green run) plus rustfmt/clippy; a weekly
  "toolchain canary" workflow tests the newest nightly and reports lints in
  an issue rather than breaking `main`.
- The 62 clippy findings are fixed by hand (no scripted rewrites); the
  `assert!(x.is_empty())` sites become `assert!(x.is_empty(), "…")` or
  `assert_eq!`, `Duration` sites use the readable constructor, subtraction
  uses `saturating_sub`/`checked_sub`.
- CI runs: `cargo clippy --all-targets`, `cargo test --workspace` (includes
  `installer_e2e`, `stress_harness`, every `repro_*`/`regression_*`),
  examples/benches build, a `tui` feature job, and `scripts/quality-gate.sh`
  in CI mode (or the script's redundant stages are dropped in favor of the
  workflow — decision recorded in the runbook).
- Placeholder test files are either given real tests (`repro_issue.rs` → the
  issue it was meant to reproduce, found via `git log -S`) or listed for
  removal (operator decision). `regression_path_traversal.rs` is un-ignored by
  hardening `core::paths::resolve_absolute_path` (nonexistent components →
  error, no lexical `..` collapse across a missing root).
- Workflows re-enabled; branch protection requiring `check` + `unit` +
  `integration` recommended (external).
- `.gate_sbh_trj.sh` is folded into `scripts/quality-gate.sh` as a `--full`
  mode.

**Success criteria.**
- [ ] `cargo clippy --all-targets -- -D warnings` clean on the pinned nightly.
- [ ] CI matrix green on `main` (external for the re-enable).
- [ ] `tests/regression_path_traversal.rs` passes un-ignored.
- [ ] `quality-gate.sh` reports a non-zero test count for every stage.

**Dependencies:** G5 for the tui job. **Complexity:** M. **Would existing beads close it?** No.

### G8 — Documentation as a tested contract — REGRESSED → WORKING

**Vision goals:** V23, V24, V1, V3, V8, V18, V19 (doc halves).

**Target state.**
- **Config strictness.** Every config struct carries `#[serde(deny_unknown_fields)]`
  behind a loader that first parses strictly; on unknown keys it re-parses
  leniently, warns on stderr (`[SBH-CONFIG] unknown key scoring.weights.location
  — did you mean scoring.location_weight?`, Damerau-Levenshtein suggestions from
  a generated key list), and `config validate` reports them as errors under
  `--strict` (default in `install`/`daemon` startup logs, non-fatal). The
  README example is rewritten to real keys and is itself parsed by a test with
  zero unknown keys.
- **Generated tables.** `sbh docs --json` emits: defaults (all sections),
  pressure table, PID/EWMA/guardrail constants, breaker/channel constants,
  command list from clap, error codes, env vars, pattern registry counts,
  module map with line counts. `scripts/ci_docs_update_check.sh` (exists,
  unused) is repurposed: it renders the fenced tables in README.md and
  AGENTS.md from that JSON and fails CI on diff. Hand-written prose stays
  hand-written; numbers stop drifting.
- All ~45 discrepancies in §3 are corrected in the same change set.
- FAQ "Does sbh delete source code?" answers honestly: what happened in May,
  the two hardcoded vetoes that now prevent it, and how to verify.
- CHANGELOG gains `[release]` markers for every published tag and stub
  entries for the 13 missing versions from `gh release view` bodies.
- `SESSION_REPORT_EXPLORATION.md`, `Codex-upgrade-progress.json`, root
  `install.sh`, stray empty directories: listed for operator-approved removal;
  until then, a `docs/internal/README.md` index explains what each is.

**Success criteria.**
- [ ] Test: README config example parses with zero unknown keys.
- [ ] Test: every command in `sbh --help` appears in README/AGENTS command
  tables and vice versa.
- [ ] CI: `ci_docs_update_check.sh` passes; a deliberate constant change fails
  it in a test.
- [ ] `config validate --strict` on this host's `/etc/sbh/config.toml` reports
  `scoring.weights` as unknown with a suggestion.

**Dependencies:** none. **Complexity:** L. **Would existing beads close it?** No.

### G9 — Policy engine semantics: make code and docs agree on purpose — PARTIAL → WORKING

**Vision goals:** V8.

**Decision required (default recorded here):** the *documented* model
(observe → canary → enforce, automatic demotion on calibration breach, canary
budget, serialization failure; explicit promotion only) is the safer product.
The code's advisory-only breach and auto-promotion were incident-driven
relaxations for a fleet that runs Enforce. The plan restores the documented
safeguards as **configurable, default-on for new installs and default-off
where the fleet config sets `initial_mode = "enforce"`**, so behavior on the
existing fleet does not change silently.

**Target state.**
- `policy.calibration_breach_action = demote|advisory` (default `demote`),
  `policy.canary_budget_action`, `policy.serialization_failure_action`, and
  `policy.auto_recover_to = none|canary|previous` (default `canary`) wired to
  the existing `FallbackReason` variants; `check_emergency_escalation`'s
  FallbackSafe → Enforce path honors `auto_recover_to`.
- `initial_mode` default documented as Enforce with rationale, or changed to
  Observe for fresh installs via the wizard (decision).
- Guardrail e-process: a regression test reproduces sustained accurate
  forecasting at Orange and asserts the e-value decays toward `exp(-5)`; the
  `e=14.9 med_err=0.00` observation is either explained by a test or fixed.
- README/AGENTS policy and guardrail sections regenerate from constants (G8).

**Success criteria.**
- [ ] Unit: each `FallbackReason` variant is reachable from production code
  under its config flag (test constructs the condition, not the enum).
- [ ] Unit: with `auto_recover_to = none` the engine never leaves FallbackSafe
  without `promote()`.
- [ ] Unit: e-process at steady accurate Orange stays below alarm for 1,000
  observations.

**Dependencies:** G8 for doc regeneration. **Complexity:** M. **Would existing beads close it?** No.

### G10 — Observability correctness — PARTIAL → WORKING

**Vision goals:** V7, V2.

- `stats` opens SQLite read-only (`SQLITE_OPEN_READ_ONLY`) and, on EACCES/readonly,
  resolves the *system* data dir from `core::config` platform defaults (not a
  hard-coded `/root/.local/share`) and hints `sudo sbh stats`.
- `status`/`check` JSON: the `platform.darwin.apfs` block is emitted only for
  APFS mounts; Linux mounts get `platform: { linux: { fs_type, is_ram_backed,
  is_readonly } }`; `free_excludes_purgeable` is only asserted where measured.
  Schema version bump + adapter test.
- `sbh version --verbose`: a `build.rs` embeds git SHA (from `git rev-parse`,
  falling back to `unknown` only when not in a repo), target, profile, and a
  `SOURCE_DATE_EPOCH`-respecting timestamp; test asserts non-"unknown" in
  repo builds.
- `ballast status --json` gains a `volumes[]` view from the coordinator
  (path, mount, configured, present, releasable) so the /data pool is visible;
  `state.json` `ballast.released` is renamed `missing` with `released_this_epoch`
  tracked separately (schema-default safe).
- `-v`/`-q` are honored globally (verbosity gates `[SBH-CONFIG]`/`[SBH-*]`
  stderr lines) or removed from the CLI (decision; plan honors them).
- `verify()` takes the ballast flock; `install.rs` provisioning passes the
  floor callback; unknown filesystem types probe `fallocate` support before
  falling back to random data.

**Success criteria.** Unit tests per item; e2e for `stats` as non-root against a root-owned fixture (simulated with a read-only file); JSON schema snapshot test for Linux vs APFS mounts.

**Dependencies:** none. **Complexity:** M. **Would existing beads close it?** No.

### G11 — Scanner v2 closeout — docs/bead drift → CLOSED with evidence

**Vision goals:** V16, V25.

- Docs (README L652/L818/L1365, design doc §5/L285, `scanner.engine` comment)
  say v2 is default since v0.4.32 and v1 is the opt-out.
- `sbh scan --ab [--top N] PATH` runs v1 and v2 back to back, emits the
  design-doc §7 artifact (entries, pruned dirs, CPU micros, candidates,
  vetoes diff) as JSON; `stats` reports scanner CPU-seconds/day from
  `scan_complete.process_cpu_micros`. A fleet capture from three hosts is
  attached to bd-xtpv.8 and the bead closed.
- Steady-state CPU acceptance test (G1) doubles as the §7 "<1 % of one core"
  proof.
- v1 removal: operator decision; the bead records the rollback window.

**Dependencies:** G1 (CPU test). **Complexity:** S–M. **Would existing beads close it?** bd-xtpv.8 covers the evidence; it needs the tooling above to be closable.

### G12 — Bead hygiene for macOS parity and release engineering

**Vision goals:** V10.

- bd-r7m7.17: close (blocker resolved 2026-05-27+; macOS lanes green through
  2026-08-17). bd-r7m7: close with a pointer to the audit doc's v0.4.22
  closeout and the remaining release-pipeline work re-homed under G4.
  bd-ykwh.3/bd-ykwh: re-scope to "restore signed/notarized release pipeline
  and tap" (G4) or close with the v0.4.28 evidence and open a G4 bead.
- `docs/internal/macos-parity-completion-audit.md`: replace the 600-line diary
  with a 40-line conclusion + link to the git history.
- `sbh_mach`: add `#![deny(unsafe_op_in_unsafe_fn)]` + per-block `// SAFETY:`
  comments audit (hygiene, not a bug).

**Complexity:** S. **Would existing beads close it?** These *are* the beads; they need closing, not doing.

### G13 — Minor constant/doc mismatches (bulk)

Handled by G8's generated tables; listed here so nothing is lost: EWMA alpha
formula and clamp; confidence terms; PID setpoint; Critical threshold; predictive
boost ladder; "newest request wins" semantics; logger drop delta vs cumulative;
guardrail window/threshold/reward/clamp; policy defaults; breaker threshold and
exponential cooldown; walker channel bounding and result cap; open-file scan
budgets location; pre-flight step list; pattern counts; location-score prefix
rule; age curve; release ladder composition; replenish semantics; SQLite failure
count; notification file channel level; self-monitor thresholds; shutdown
timings; README `[monitor]`/`[ballast]`/`[scoring.weights]`/`[policy]`/
`[guardrails]`/`[logging]` keys; AGENTS.md pressure table, module map, line
counts, CLI table; `docs/testing-and-logging.md` paths and counts.

### G0 — Operator runbook: put this host back under protection

Not code. After G1 and G3 land: `sudo sbh doctor --system` → address FAILs;
`sudo sbh install --systemd --scope system` (regenerates the hardened unit;
drift check confirms); `sudo rm /etc/sbh/HOTLOOP_DISABLED` (operator-run,
after confirming the CPU test passes on the installed build); `sudo sbh ballast
provision` (graduated); enable catalog roots; `sbh status` must show
`daemon_running=true` by lock, reserve present on `/`, `reclaim_capability =
catalog` for `/`. Recorded as a bead with a checklist so the outcome is
verified, not assumed.

### Dependency graph (bead ordering)

```
G7  toolchain pin + clippy fixes      (unblocks green CI for everything)
G8  config strictness + doc contract  ─┐
G3  READY=1 + shutdown + drift        ─┼─> G1 host protection ─> G0 runbook
G2  decision persistence + explain    ─┼─> G5 dashboard            │
G10 observability fixes               ─┘                           │
G4  release contract                  ──> G12 bead hygiene         │
G6  bootstrap/uninstall wiring                                     │
G9  policy semantics                  ──> (docs via G8)            │
G11 scanner v2 closeout               <── G1 CPU proof ────────────┘
```

### Verification plan (after all bridge work)

- [ ] V26/G0: this host shows reserve on `/`, catalog reclaim capability, daemon
  running by lock, CPU < 1 % steady state, kill switch removed.
- [ ] V6: `sbh explain --id` on a real daemon decision.
- [ ] V9: transient `Type=notify` unit reaches `active`.
- [ ] V11: `sbh update --check --force --dry-run` resolves a live asset.
- [ ] V14: release binary opens the cockpit; all TUI stages count > 0.
- [ ] V12/V13: `sbh bootstrap --dry-run --json`, `sbh uninstall --dry-run --json`.
- [ ] V22: clippy clean on pinned nightly; CI green; quality gate honest.
- [ ] V23: README example parses strictly; generated tables match code.
- [ ] Every remaining V-row re-audited with the same seven-area method and the
  table in §1 updated in place.
