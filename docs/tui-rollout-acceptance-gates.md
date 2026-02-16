# TUI Rollout Acceptance Gates, Performance Budgets, and Error Budgets (bd-xzt.1.5)

This document defines objective release gates for the dashboard overhaul so
"looks good" cannot bypass safety-critical behavior checks.

References:
- `docs/dashboard-status-contract-baseline.md` (C-01..C-18 baseline contract)
- `docs/dashboard-information-architecture.md` (bd-xzt.1.4 IA + workflow paths)
- `docs/adr-tui-integration-strategy.md` (migration/rollback boundaries)
- `docs/testing-and-logging.md` (test and log registration conventions)

## 1. Gate Model

Release decision for the new dashboard is the conjunction of:

`PARITY_GATES && PERFORMANCE_GATES && ERROR_GATES`

If any gate fails, rollout promotion is blocked.

## 2. Non-Regression Parity Gates

### 2.1 Gate set

| Gate ID | Contract IDs | Requirement | Verification |
| --- | --- | --- | --- |
| `G-PAR-CLI-01` | C-01, C-02, C-03, C-04, C-05, C-06 | Status/dashboard command semantics remain identical unless explicitly versioned | Unit/integration tests for `run_status`, `run_dashboard`, `run_live_status_loop`, `validate_live_mode_output`, refresh normalization |
| `G-PAR-DATA-02` | C-08, C-09, C-10, C-11, C-12, C-13 | Dashboard/status data semantics and stale-state behavior are preserved | Integration fixtures for stale/fresh state, mount pressure mapping, optional rate display, ballast summary derivation, sqlite fallback |
| `G-PAR-TERM-03` | C-14, C-15, C-16, C-17, C-18 | Terminal lifecycle and degraded-mode rendering invariants are preserved | Unit + PTY integration tests for atomic state writes, raw mode/alt-screen restore, exit keys, degraded fallback, required section rendering |
| `G-PAR-IA-04` | bd-xzt.1.4 workflow map | New UI keeps all major workflows reachable from default entry in <= 3 interactions | Navigation integration tests: S1->S2/S3/S4/S5 and contextual drill-down routes |

### 2.2 Pass criteria

1. `cargo fmt --check` passes.
2. `rch exec "cargo check --all-targets"` passes.
3. `rch exec "cargo clippy --all-targets -- -D warnings"` passes.
4. `rch exec "cargo test --all-targets"` passes.
5. All tests tagged to `G-PAR-*` pass with no ignored failures in release gates.

## 3. Dashboard Performance Budgets

Budgets are measured with `--features tui` on representative fixture loads:

- 8 monitored mounts
- 2,000 timeline events (ring-buffered)
- 500 scan candidates
- terminal sizes: `120x40` (primary), `80x24` (narrow fallback)

### 3.1 Frame and latency budgets

| Budget ID | Metric | Target | Window |
| --- | --- | --- | --- |
| `G-PERF-FRAME-01` | Frame render time (`120x40`) | `p50 <= 6ms`, `p95 <= 14ms`, `p99 <= 22ms` | 10,000 frames |
| `G-PERF-FRAME-02` | Frame render time (`80x24`) | `p95 <= 10ms`, `p99 <= 18ms` | 10,000 frames |
| `G-PERF-INPUT-03` | Keypress-to-next-frame latency | `p95 <= 75ms`, `p99 <= 120ms` | 5,000 events |
| `G-PERF-CADENCE-04` | Refresh interval jitter at configured `R` | `p95(|dt-R|) <= max(10ms, 0.15R)`; `p99 <= max(20ms, 0.30R)` | 10,000 intervals |
| `G-PERF-START-05` | Startup to first fully rendered frame | `p95 <= 500ms` | 100 launches |

### 3.2 Resource budgets

| Budget ID | Metric | Target | Window |
| --- | --- | --- | --- |
| `G-PERF-CPU-06` | CPU at `refresh=1000ms` | `avg <= 3%` of one core | 30 min soak |
| `G-PERF-CPU-07` | CPU at `refresh=100ms` | `avg <= 12%` of one core | 30 min soak |
| `G-PERF-MEM-08` | RSS growth (post-warmup) | `delta <= 24 MiB` over 60 min | 60 min soak |
| `G-PERF-FD-09` | Open FD leakage from dashboard session | `delta == 0` after clean exit | 100 start/stop cycles |

### 3.3 Performance gate verdict

`G-PERF` passes only if all `G-PERF-*` targets pass in two consecutive runs.

## 4. Error Budget and Fallback Rules

### 4.1 Error budgets (numeric)

| Budget ID | Failure mode | Budget |
| --- | --- | --- |
| `G-ERR-PANIC-01` | Unhandled panic in dashboard path | `0` per release candidate |
| `G-ERR-TERM-02` | Raw-mode/alt-screen cleanup failure | `0` per release candidate |
| `G-ERR-STALE-03` | Stale-state false negative (state > 90s treated as live) | `0` tolerance |
| `G-ERR-DEGRADE-04` | Time to enter degraded mode after state-read failure | `<= 1 refresh interval` |
| `G-ERR-RECOVER-05` | Time to recover from degraded to live after valid state returns | `<= 2 refresh intervals` |
| `G-ERR-RENDER-06` | Recoverable render/update errors | `<= 0.05%` of frames in 24h soak |
| `G-ERR-FALLBACK-07` | Forced fallback from new dashboard to legacy path | `<= 0.1%` of canary sessions |

### 4.2 Mandatory fallback behavior

1. Any failure of `G-ERR-PANIC-01`, `G-ERR-TERM-02`, or `G-ERR-STALE-03`
   triggers immediate rollback to legacy default path.
2. If `G-ERR-RENDER-06` or `G-ERR-FALLBACK-07` is exceeded during canary,
   promotion freezes and canary exits until fixed.
3. Emergency mode remains outside the TUI path and is never blocked by TUI
   failures.

## 5. Rollout Stage Gates

### Stage A: Shadow (`--new-dashboard` opt-in only)

Entry:
1. `G-PAR-*` pass.
2. No unresolved critical defects in dashboard command path.

Exit to Stage B:
1. `G-PERF-*` pass in two consecutive runs.
2. `G-ERR-*` preflight tests pass.

### Stage B: Canary (limited operator cohort)

Entry:
1. Stage A exit criteria satisfied.

Exit to Stage C:
1. 72h canary window with all `G-ERR-*` budgets satisfied.
2. No parity regressions detected by nightly contract suite.

### Stage C: Enforce (new dashboard default)

Requirements:
1. All gates remain green on release branch.
2. `--legacy-dashboard` remains available for one release cycle.

## 6. Rollback Trigger Matrix

| Trigger | Action | Severity |
| --- | --- | --- |
| Any `G-PAR-*` failure on release branch | Revert to legacy default, block release | Critical |
| `G-ERR-PANIC-01` or `G-ERR-TERM-02` breach | Immediate rollback and hotfix gate | Critical |
| `G-ERR-STALE-03` breach | Immediate rollback; treat as safety defect | Critical |
| `G-PERF-FRAME-01` or `G-PERF-CADENCE-04` fail in 2 consecutive canary runs | Freeze promotion; keep canary off | High |
| `G-ERR-FALLBACK-07` breach | Freeze promotion; investigate telemetry and adapters | High |

## 7. Mapping to Downstream Beads

| Bead | Required outputs from this gate spec |
| --- | --- |
| `bd-xzt.2.1` | Runtime entrypoint must expose hooks needed for gate instrumentation |
| `bd-xzt.4.6` | Implement quality-gate runbook with pass/fail reporting per gate ID |
| `bd-xzt.5.3` | Rollout playbook must enforce Stage A/B/C entry and exit criteria |
| `bd-xzt.5.4` | Signoff report must include gate matrix with evidence artifacts |

## 8. Machine-Readable Reporting Requirement

The rollout runbook (`bd-xzt.4.6`) must emit a gate report artifact with one
record per gate ID:

```json
{
  "gate_id": "G-PERF-FRAME-01",
  "status": "pass|fail",
  "measured": {
    "p50_ms": 0.0,
    "p95_ms": 0.0,
    "p99_ms": 0.0
  },
  "target": {
    "p50_ms_lte": 6.0,
    "p95_ms_lte": 14.0,
    "p99_ms_lte": 22.0
  },
  "evidence": "path/to/artifact"
}
```

Release signoff requires all gate records to be `status=pass`.

