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
| V22 | Engineering quality gates: fmt clean, `clippy --all-targets -D warnings` clean, all tests pass, 20-stage quality gate, CI green | R L1728-1755; A L176-194; CHANGELOG v0.5.0 | **REGRESSED** | Major | NO_BEAD | HEAD `320d04d` on nightly 2026-08-31: fmt clean; **clippy 61 errors (lib test) + 1 (bin test)** — 53× `assert_is_empty`/`assert_is_not_empty`, 5× `duration_suboptimal_units`, 2× `unchecked_duration_subtraction`, 1 `const_is_empty`, 1 `redundant_clone` across 20 files; tests 1,419 lib + 122 bin + 213 integration + 3 doc = **1,757 pass, 0 fail**. CI: last green `ci.yml` on main 2026-08-06; 12 later runs failed/cancelled (clippy on a different nightly: `errors.rs:32`, `predictive.rs:337,364`); **no Actions run of any kind since 2026-08-20** despite pushes on 08-25/26. `rust-toolchain.toml` pins bare `nightly`, so every new nightly can break the gate. `tests/repro_issue.rs` (1 line), `repro_glob.rs` (comment only), `repro_tui_panic.rs` (tests string slicing) are placeholders; `tests/fallback_verification.rs` (44 tests) is tui-gated and never runs; one regression test is `#[ignore]`d pending "path-resolution contract hardening". |
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
- **CI capacity.** No Actions run since 2026-08-20; likely quota/billing. The
  macOS-parity beads still cite a May runner-queue blocker that was resolved.
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
- `SESSION_REPORT_EXPLORATION.md` (root): claims a swap-thrash constant rename that never landed; 3 of 4 claimed fixes exist.

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

See §6 onward (revised in place through the ambition rounds).
