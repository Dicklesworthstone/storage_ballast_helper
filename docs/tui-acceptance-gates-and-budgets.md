# TUI Acceptance Gates and Budgets (bd-xzt.1.5)

This document defines the acceptance gates, performance budgets, and error
budgets required before the FrankentUI-inspired dashboard overhaul can become
default behavior.

This is the source of truth for:
- `bd-xzt.2.1` (runtime entrypoint cutover readiness)
- `bd-xzt.4.6` (quality-gate runbook implementation)
- `bd-xzt.5.3` (phased rollout controls)
- `bd-xzt.5.4` (go/no-go signoff artifact)

References:
- `docs/dashboard-status-contract-baseline.md` (C-01..C-18 non-regression contract)
- `docs/adr-tui-integration-strategy.md` (selected architecture and invariants)
- `docs/dashboard-information-architecture.md` (operator workflow and navigation model)
- `docs/testing-and-logging.md` (test/log conventions)

## 1. Gate Policy

Gate levels:
- `HARD`: must pass for merge to `main` on dashboard-overhaul work and for default-cutover.
- `SOFT`: may temporarily fail only with explicit waiver and mitigation note.

Waiver rules:
1. Waivers are allowed only for `SOFT` gates.
2. Every waiver must include:
   - failing metric/gate id,
   - mitigation and owner,
   - expected fix bead and date.
3. No waivers are allowed for terminal cleanup safety, panic freedom, or contract parity.

## 2. Contract Non-Regression Gates (HARD)

All baseline contracts must be mapped to at least one automated assertion before cutover.

| Contract | Required Assertions | Gate Level |
| --- | --- | --- |
| C-01 | `status` snapshot vs `status --watch` live-mode behavior | HARD |
| C-02 | 1000ms watch refresh invariant for `status --watch` | HARD |
| C-03 | `dashboard --refresh-ms` minimum floor (`>= 100ms`) | HARD |
| C-04 | dashboard live-json rejection with explicit error text | HARD |
| C-05 | live refresh footer text + clear-screen cadence behavior | HARD |
| C-06 | dashboard command routing contract validation | HARD |
| C-07 | `tui` feature-gate build-matrix compatibility | HARD |
| C-08 | daemon staleness/liveness interpretation | HARD |
| C-09 | pressure threshold mapping correctness | HARD |
| C-10 | optional rates display behavior (present vs absent) | HARD |
| C-11 | ballast summary derivation contract | HARD |
| C-12 | activity source fallback behavior | HARD |
| C-13 | state-file schema compatibility for dashboard/status | HARD |
| C-14 | atomic state write + unix permission guarantees | HARD |
| C-15 | raw mode / alternate-screen restoration on all exits | HARD |
| C-16 | dashboard exit key semantics (`q`, `Esc`, `Ctrl-C`) | HARD |
| C-17 | degraded-mode fallback visibility when state unavailable | HARD |
| C-18 | required section visibility in crossterm dashboard mode | HARD |

Minimum evidence:
- Contract-to-test mapping table in test output artifact.
- No unmapped contract IDs at signoff time.

## 3. Performance Budgets

Performance budgets use two thresholds:
- `target`: normal expected bound.
- `hard_limit`: release-blocking bound.

| Metric | Target | Hard Limit | Scope | Gate |
| --- | --- | --- | --- | --- |
| Initial dashboard render (fresh startup) | p95 <= 500ms | p95 <= 800ms | Local + CI perf run | HARD |
| Steady-state frame render time | p95 <= 16ms | p99 <= 33ms | perf HUD + stress suite | HARD |
| Input-to-visible-feedback latency | p95 <= 80ms | p99 <= 150ms | PTY interaction suite | HARD |
| Refresh scheduler jitter (`--refresh-ms 250`) | <= 15% drift | <= 25% drift | long-run interaction test | SOFT |
| Dashboard process CPU (steady 5-minute run) | p95 <= 25% of one core | p95 <= 40% | stress/perf suite | SOFT |
| Dashboard RSS growth (30-minute run) | <= 5 MiB | <= 10 MiB | stress/perf suite | HARD |

Notes:
- Budget measurements must be captured with trace IDs and environment metadata
  (terminal size, refresh interval, workload profile).
- If machine variance affects CPU timing, CPU gates are `SOFT`, but frame-time
  and latency gates remain `HARD`.

## 4. Reliability and Error Budgets

| Metric | Budget | Gate |
| --- | --- | --- |
| Panics in dashboard runtime under test matrix | 0 | HARD |
| Raw mode / terminal restoration failures | 0 | HARD |
| Unhandled adapter failures (state/telemetry/preferences) | 0 | HARD |
| Silent degraded-mode transitions (without operator indicator) | 0 | HARD |
| Flaky PTY/e2e retries required | <= 1 retry per full suite run | SOFT |
| Unknown/unclassified error codes in logs | 0 | HARD |

Required behavior for failure modes:
1. Failures must degrade to safe/read-only behavior where possible.
2. Failures must emit structured logs and clear UI state indicators.
3. Recovery transitions (fault clears) must be validated, not assumed.

## 5. Operator Workflow Acceptance Gates

Based on `docs/dashboard-information-architecture.md`, the following workflows
must pass scripted acceptance before cutover:

| Workflow | Required Path | Required Evidence | Gate |
| --- | --- | --- | --- |
| Pressure triage | S1 -> contextual route (S2/S4/S5) | trace artifact + expected route log | HARD |
| Explainability drill-down | S1/S2 -> S3 | decision/evidence linkage assertion | HARD |
| Cleanup candidate review | S1/S2 -> S4 | factor + veto visibility assertion | HARD |
| Ballast response | S1/S2 -> S5 + confirm | action guard + post-action visibility check | HARD |

Workflow criteria:
- Each workflow must be reachable in <= 3 interactions from default overview.
- All workflows must preserve always-on critical signals (pressure severity,
  daemon mode/staleness, safety state, active operation state).

## 6. Required Verification Command Sequence

CPU-intensive checks must use `rch` per project policy.

```bash
# Formatting (allowed local)
cargo fmt --check

# Build/lint/test gates
rch exec "cargo check --all-targets"
rch exec "cargo clippy --all-targets -- -D warnings"
rch exec "cargo test --lib"
rch exec "cargo test --bin sbh"
rch exec "cargo test --test integration_tests"

# E2E + stress/perf
./scripts/e2e_test.sh
rch exec "cargo test --test stress_tests -- --nocapture"
```

Additional dashboard-overhaul suites (once added in `bd-xzt.4*`) become mandatory:
- PTY keyflow suite (`bd-xzt.4.9`)
- deterministic replay suite (`bd-xzt.4.10`)
- property-based invariants (`bd-xzt.4.11`)
- failure-injection suite (`bd-xzt.4.14`)

## 7. Gate Artifacts and Logging Requirements

Each gate run must emit:
- `trace_id` (stable run identifier),
- gate stage name,
- command executed,
- pass/fail status,
- elapsed duration,
- links/paths to stdout/stderr/frame artifacts.

Mandatory artifact bundle fields:
- `trace_id`
- `gate_id`
- `suite_name`
- `environment` (OS, terminal size, refresh interval)
- `result`
- `started_at` / `finished_at`
- `failure_summary` (if failed)

If any `HARD` gate fails:
1. Cutover is blocked.
2. A regression bead must be created/linked.
3. A rerun with the same trace context is required after fix.

## 8. Release Decision Criteria (for bd-xzt.5.4)

Cutover to default dashboard is allowed only when:
1. All `HARD` gates in this document pass.
2. No open P0/P1 regressions related to dashboard safety/runtime parity exist.
3. Rollback controls from `bd-xzt.5.3` are validated and documented.
4. Signoff artifact includes:
   - contract parity table (C-01..C-18),
   - performance/error budget results,
   - workflow acceptance results,
   - explicit go/no-go statement with owners.

## 9. Change Control

Any threshold or gate policy change requires:
1. Update to this document.
2. Reference in bead comments for the impacted work.
3. Re-validation of affected gate outputs.
