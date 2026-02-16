# Post-Rollout Monitoring, Incident Playbook Updates, and Maintainer Handoff (bd-xzt.5.5)

References:
- `docs/tui-signoff-decision.md` (go/no-go: GO)
- `docs/tui-rollout-acceptance-gates.md` (stage gates, rollback triggers)
- `docs/tui-acceptance-gates-and-budgets.md` (performance/error budgets)
- `docs/quality-gate-runbook.md` (gate sequence)
- `docs/testing-and-logging.md` (test conventions, log schema)
- `docs/dashboard-status-contract-baseline.md` (C-01..C-18)

## Part 1: Post-Rollout Monitoring Signals

### 1.1 Stage A Monitoring (Shadow / Opt-in)

During Stage A (`--new-dashboard` opt-in), monitor for early-adopter regressions.

| Signal | Source | Alert Threshold | Action |
| --- | --- | --- | --- |
| Dashboard panic | CI gate `G-ERR-PANIC-01` / user reports | Any occurrence | Immediate rollback; hotfix gate per rollout trigger matrix |
| Terminal cleanup failure | CI gate `G-ERR-TERM-02` / user reports | Any occurrence | Immediate rollback; verify `terminal_guard.rs` RAII |
| Stale-state false negative | CI gate `G-ERR-STALE-03` | Any occurrence | Immediate rollback; check `STALENESS_THRESHOLD_SECS` (90s) |
| Degraded-mode entry delay | CI gate `G-ERR-DEGRADE-04` | > 1 refresh interval | Investigate adapter fallback chain in `DashboardStateAdapter` |
| Recovery delay | CI gate `G-ERR-RECOVER-05` | > 2 refresh intervals | Investigate adapter reconnection in composite telemetry |
| Render errors | CI gate `G-ERR-RENDER-06` | > 0.05% frames in 24h | Profile render hot path; check for unbounded growth |
| Forced fallback to legacy | CI gate `G-ERR-FALLBACK-07` | > 0.1% sessions | Freeze promotion; investigate telemetry adapters |
| Frame render time (120x40) | `G-PERF-FRAME-01` | p95 > 14ms, p99 > 22ms | Profile render pipeline; check widget allocation |
| Input latency | `G-PERF-INPUT-03` | p95 > 75ms | Profile input dispatch; check scheduler jitter |
| RSS growth | `G-PERF-MEM-08` | > 24 MiB over 60 min | Profile model/adapter for unbounded collections |

### 1.2 Stage B Monitoring (Canary)

During Stage B (limited operator cohort), add real-terminal measurements:

| Signal | Source | Alert Threshold | Action |
| --- | --- | --- | --- |
| PTY render latency | Canary operator reports | p95 > 33ms actual | Compare headless vs PTY; isolate terminal I/O overhead |
| CPU at refresh=1000ms | Canary soak test | avg > 25% of one core | Profile scheduler and adapter polling frequency |
| CPU at refresh=100ms | Canary soak test | avg > 40% | Profile hot path; consider frame skipping |
| Refresh jitter | Canary soak test | > 25% drift at configured interval | Check scheduler timer implementation |
| Contract regression | Nightly contract suite | Any C-01..C-18 failure | Revert to legacy default; block release |
| Operator confusion | Canary feedback | Workflow > 6 keystrokes | Review navigation shortcuts; update help screen |

### 1.3 Stage C Monitoring (Enforce / Default)

After promotion to default, shift to steady-state monitoring:

| Signal | Source | Cadence | Action |
| --- | --- | --- | --- |
| Quality-gate suite | `scripts/quality-gate.sh` in CI | Every PR, nightly on main | HARD failure blocks merge |
| E2E suite | `scripts/e2e_test.sh` in CI | Every PR, nightly on main | Failure triggers regression bead |
| Contract parity | `parity_harness` + `fallback_verification` | Every PR | Regression = rollback trigger |
| Telemetry adapter health | `TelemetryHealth` in runtime | Continuous (per-refresh) | Degraded state shows DEGRADED label |
| Kill-switch test | Manual quarterly | Quarterly | Verify `SBH_DASHBOARD_KILL_SWITCH=true` forces legacy |

### 1.4 Monitoring Checklist for Operators

Before each stage transition, verify:

- [ ] All HARD gates in `scripts/quality-gate.sh` pass in 2 consecutive runs
- [ ] No open P0/P1 regressions in beads tracker
- [ ] Kill switch (`SBH_DASHBOARD_KILL_SWITCH=true`) tested and functional
- [ ] `--legacy-dashboard` flag produces correct legacy output
- [ ] Stage-appropriate error budget satisfied (see rollout-acceptance-gates.md)

## Part 2: Incident Playbook Updates

### 2.1 Dashboard-Aware Incident Triage

The new dashboard includes a built-in incident playbook system (`src/tui/incident.rs`)
with severity-adaptive guidance. When disk pressure escalates:

**Severity levels** (mapped from daemon `pressure.overall`):
- **Normal** (green): No action needed
- **Elevated** (yellow/warning): Awareness recommended
- **High** (orange): Active monitoring and preparation
- **Critical** (red/emergency): Immediate action required

**Built-in triage sequence** (7 prioritized entries):

| Priority | Action | Screen | Severity Gate | Shortcut |
| --- | --- | --- | --- | --- |
| 1 | Release ballast | S5 Ballast | High+ | `b` |
| 2 | Check pressure overview | S1 Overview | Elevated+ | `o` |
| 3 | Review critical events | S2 Timeline | Elevated+ | `t` |
| 4 | Inspect deletion decisions | S3 Explainability | High+ | `e` |
| 5 | Review pending candidates | S4 Candidates | High+ | `c` |
| 6 | Check daemon health | S7 Diagnostics | Elevated+ | `d` |
| 7 | Search logs for errors | S6 Logs | Elevated+ | `l` |

**Context-aware hints** (automatic, based on severity):
- `!` — Emergency ballast release
- `x` — Explain last decision
- `r` — Refresh/reconnect
- `f` — Filter timeline to critical events

### 2.2 New Dashboard Failure Modes and Recovery

| Failure Mode | Symptom | Recovery |
| --- | --- | --- |
| State file missing/corrupt | DEGRADED label, "no state" message | Check daemon status (`sbh status`); restart daemon if needed |
| Telemetry adapter unavailable | Timeline/explainability show partial data | Check SQLite WAL file; fall back to JSONL (`source: Jsonl`) |
| Terminal not responding | Dashboard hangs or garbles output | Press `q`/Esc/Ctrl-C (all three exit paths); terminal guard restores raw mode |
| Kill switch activated | Dashboard immediately shows legacy output | Check `SBH_DASHBOARD_KILL_SWITCH` env var or `dashboard.kill_switch` config |
| High CPU during dashboard | System slowdown while dashboard runs | Increase `--refresh-ms` (minimum 100ms); check adapter polling |

### 2.3 CLI Incident Commands (No Dashboard Required)

For headless or SSH environments where the TUI is unavailable:

```bash
# Snapshot status (one-shot, no terminal required)
sbh status --json

# Live status without TUI
sbh status --watch

# Emergency ballast release (works on 99% full disk)
sbh emergency

# Quick disk pressure check (exit code 0 = safe, 1 = pressure)
sbh check

# Pre-build safety check
sbh check && cargo build
```

### 2.4 Rollback Procedure

If the new dashboard causes issues during any stage:

1. **Immediate**: Set `SBH_DASHBOARD_KILL_SWITCH=true` in environment
2. **Config-level**: Set `dashboard.kill_switch = true` in sbh config
3. **CLI override**: Use `sbh dashboard --legacy-dashboard`
4. **Permanent**: Set `dashboard.mode = "legacy"` in config

Priority chain (highest wins): kill_env > kill_config > --legacy > --new > env > config > default

## Part 3: Maintainer Handoff Package

### 3.1 Architecture Map

```
src/
├── core/              # Foundation layer
│   ├── config.rs      # TOML config with validation (pressure thresholds, paths)
│   ├── errors.rs      # Error taxonomy (SbhError enum)
│   └── platform.rs    # PAL: detect_platform() → Linux/macOS abstraction
├── monitoring/         # Monitoring layer
│   ├── ewma.rs        # Disk usage rate estimation with EWMA + prediction
│   ├── pid_controller.rs  # 4-level PID pressure response
│   ├── guardrails.rs  # E-process drift detection, rolling calibration
│   └── predictive_action.rs  # Horizon warnings, danger detection
├── scanner/           # Scanner layer
│   ├── walker.rs      # Crossbeam work-stealing directory traversal
│   ├── pattern_registry.rs  # Build artifact pattern matching
│   ├── scoring.rs     # Multi-factor scoring (5 factors + hard vetoes)
│   ├── deletion_executor.rs  # Batch planning with circuit breaker
│   ├── merkle.rs      # Incremental change detection
│   └── protection.rs  # .sbh-protect marker files + config globs
├── ballast/           # Ballast layer
│   ├── manager.rs     # Provision/release/verify/replenish (fallocate on ext4/xfs)
│   └── coordinator.rs # Flow control, pressure-responsive release
├── logger/            # Logger layer
│   ├── sqlite.rs      # WAL-mode activity database
│   ├── jsonl.rs       # Append-only fallback log
│   ├── dual_write.rs  # Dual-write coordinator
│   └── stats.rs       # Time-windowed statistics engine
├── daemon/            # Daemon layer
│   ├── loop_main.rs   # Main event loop (crossbeam channels, no tokio)
│   ├── policy.rs      # Observe → canary → enforce lifecycle
│   ├── notifications.rs  # Multi-channel alerts (desktop/file/journal/webhook)
│   ├── self_monitor.rs   # Thread health, respawn, resource limits
│   └── install.rs     # systemd/launchd install orchestration
├── tui/               # TUI dashboard (behind `tui` feature flag)
│   ├── model.rs       # Elm-style Model with 7 screens
│   ├── update.rs      # Msg → Model reducer (pure state transitions)
│   ├── render.rs      # Model → Frame renderer (crossterm backend)
│   ├── runtime.rs     # Event loop, scheduler, terminal lifecycle
│   ├── adapters.rs    # DashboardStateAdapter (state.json → Model)
│   ├── telemetry.rs   # SQLite/JSONL/Composite telemetry adapters
│   ├── incident.rs    # Severity classification + playbook entries
│   ├── preferences.rs # User preferences (theme, hints, keybindings)
│   ├── widgets.rs     # Reusable gauge/table/chart widgets
│   ├── layout.rs      # Responsive layout engine
│   ├── terminal_guard.rs  # RAII raw-mode/alt-screen cleanup
│   └── test_*.rs      # 10 test modules (see testing-and-logging.md)
└── cli_app.rs         # Clap CLI with 15+ subcommands
```

### 3.2 Key Design Invariants

Maintainers must preserve these invariants when modifying the codebase:

1. **No tokio**: The daemon uses `std::Thread` + crossbeam channels. Do not introduce async runtime dependencies.
2. **No unsafe code**: `#![forbid(unsafe_code)]` at binary crate level. Use `nix` crate for syscalls.
3. **No production unwraps**: All `.unwrap()` calls are in test code only. Use `?` or explicit error handling.
4. **Bounded channels**: All crossbeam channels have explicit capacity (16/64/1024). Use `try_send()` for the logger channel.
5. **0o600 permissions**: All daemon-internal file writes use restricted permissions (state.json, JSONL, ballast, merkle checkpoint, notifications).
6. **Same-filesystem ballast**: Ballast files must be on the same filesystem as the pressure source.
7. **SQLite not on monitored FS**: The activity database must not be on a filesystem that the scanner monitors.
8. **Staleness threshold**: 90 seconds (`STALENESS_THRESHOLD_SECS`). State older than this triggers degraded mode.
9. **TUI feature gate**: All TUI code is behind `--features tui`. The binary compiles and runs without it.
10. **Contract parity**: C-01..C-18 contracts must pass. Changes to dashboard behavior require contract review.

### 3.3 Known Limitations

| Limitation | Severity | Context |
| --- | --- | --- |
| PTY latency unmeasured | LOW | Headless test harness validates logic; real PTY latency deferred to Stage B canary |
| CPU budgets measured headless | LOW | `G-PERF-CPU-06/07` are SOFT gates; actual CPU impact depends on terminal emulator |
| Snapshot goldens may drift | LOW | `test_snapshot_golden` is SOFT gate; update golden hashes on intentional render changes |
| CoW filesystem ballast | LOW | `fallocate()` not instant on CoW (btrfs/ZFS); random-data fallback used |
| No Windows support | EXPECTED | PAL only implements Linux and macOS; daemon requires systemd/launchd |

### 3.4 Common Maintenance Tasks

**Adding a new TUI screen:**
1. Add variant to `Screen` enum in `model.rs`
2. Add input handling in `update.rs` (pure reducer, no I/O)
3. Add rendering in `render.rs`
4. Add navigation shortcut in `model.rs` keybinding table
5. Add test coverage in `test_unit_coverage.rs` and `test_scenario_drills.rs`
6. Map to contract ID if it affects existing behavior

**Updating scoring factors:**
1. Modify factor computation in `scoring.rs`
2. Update `ScoringInput` struct if new data is needed
3. Verify `proof_harness` invariants still hold (monotonicity, ranking stability)
4. Check `decision_plane_e2e` for policy-level regression

**Changing daemon config schema:**
1. Update `config.rs` with validation
2. Update `DaemonState` if state.json is affected
3. Verify C-13 (state-file schema compatibility) via `parity_harness`
4. Update e2e tests for new config fields

**Updating dependencies:**
1. Run `cargo update` for patch versions
2. For minor/major bumps, check licensing (permissive only)
3. Run full quality-gate sequence: `./scripts/quality-gate.sh`
4. Verify `#![forbid(unsafe_code)]` still compiles (new deps may introduce unsafe)

### 3.5 Next Improvements (Candidate Backlog)

These items were identified during the overhaul but deferred as out-of-scope:

| Item | Priority | Notes |
| --- | --- | --- |
| Real PTY latency measurement | P1 | Requires Stage B canary infrastructure |
| CPU profiling in CI | P2 | Add `G-PERF-CPU-06/07` as measured CI gates |
| Accessibility audit | P2 | Screen reader compatibility, color-blind themes |
| Remote dashboard (SSH forwarding) | P3 | WebSocket or REST adapter for headless access |
| Plugin/extension system | P3 | Custom screens for site-specific monitoring |
| Automated golden snapshot updates | P3 | CI job to regenerate goldens on intentional changes |

### 3.6 Test Infrastructure Quick Reference

| What | Command |
| --- | --- |
| Full gate sequence | `./scripts/quality-gate.sh` |
| Quick local check | `cargo fmt --check && cargo test --lib --features tui` |
| Single TUI module | `rch exec "cargo test --lib --features tui tui::test_replay"` |
| Binary/CLI tests | `rch exec "cargo test --bin sbh"` |
| Integration tests | `rch exec "cargo test --test integration_tests --features tui"` |
| E2E suite | `./scripts/e2e_test.sh` |
| Stress tests | `rch exec "cargo test --test stress_tests"` |
| Decision proofs | `rch exec "cargo test --test proof_harness"` |

### 3.7 Contact and Ownership

| Area | Primary | Backup |
| --- | --- | --- |
| TUI dashboard | WindyWillow (signoff agent) | StormyIvy (quality-gate author) |
| Daemon core | LilacMouse (hardening) | MaroonMaple (permissions audit) |
| Scanner/scoring | BlueHollow (protection, walker) | SandyGate (decision plane) |
| Installer | SandyGate (orchestration) | DustyDove (backup/rollback) |
| CI/quality gates | StormyIvy (quality-gate.sh) | GreenIbis (render pipeline) |
