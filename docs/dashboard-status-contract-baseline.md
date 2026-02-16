# Dashboard and Status Baseline Contract (bd-xzt.1.1)

This document freezes the current behavior contract for `sbh status` and
`sbh dashboard` before the TUI overhaul work (`bd-xzt.*`).

Goal: prevent silent regressions by giving implementation and testing tasks a
shared, explicit checklist with verification expectations.

## Scope

- Primary command path in `src/cli_app.rs`:
  - `run_status`
  - `run_dashboard`
  - `run_live_status_loop`
  - `render_status`
- Optional crossterm dashboard module in `src/cli/dashboard.rs`
  (`feature = "tui"` only).
- Daemon state-file schema and staleness assumptions from
  `src/daemon/self_monitor.rs`.

## Contract Checklist

| ID | Baseline Contract | Source of Truth | Verification Method |
| --- | --- | --- | --- |
| C-01 | `sbh status` is snapshot-by-default. `sbh status --watch` is live mode. | `src/cli_app.rs` (`run_status`) | Integration: assert `status` returns once and `status --watch` keeps running until timeout/user interrupt. |
| C-02 | `sbh status --watch` refresh interval is fixed at 1000ms. | `src/cli_app.rs` (`STATUS_WATCH_REFRESH_MS`) | Unit: constant-level assertion + live-loop regression test around `run_status`. |
| C-03 | `sbh dashboard --refresh-ms` uses the requested interval but clamps to a hard minimum of 100ms. | `src/cli_app.rs` (`normalize_refresh_ms`, `LIVE_REFRESH_MIN_MS`) | Unit: `normalize_refresh_ms_enforces_minimum_floor`. |
| C-04 | Live JSON is allowed for `status --watch` and rejected for `dashboard` with a user-facing error mentioning `dashboard` and `does not support --json`. | `src/cli_app.rs` (`validate_live_mode_output`) | Unit: `validate_live_mode_output_allows_status_watch_json_streaming`, `validate_live_mode_output_rejects_dashboard_json_live_mode`. |
| C-05 | Human live mode clears screen each tick and prints `Refreshing every <N>ms (Ctrl-C to exit)`. | `src/cli_app.rs` (`run_live_status_loop`) | Integration/e2e: capture output stream and assert refresh footer text. |
| C-06 | Mainline `dashboard` command currently routes through `run_live_status_loop` + `render_status` (same renderer family as `status`). | `src/cli_app.rs` (`run_dashboard`) | Integration: command wiring assertion via CLI dispatch tests. |
| C-07 | The crossterm dashboard module is optional (`feature = "tui"`) and not the current default dashboard entrypoint. | `Cargo.toml` features + `src/cli/mod.rs` + `src/cli_app.rs` dispatch | Build-matrix check: default-feature build and `--features tui` build both compile with expected routing. |
| C-08 | Daemon liveness in status output is inferred from state-file existence + parse success + staleness threshold (`<= 90s`). | `src/cli_app.rs` (`render_status`, `DAEMON_STATE_STALE_THRESHOLD_SECS`) | Integration: stale vs fresh state-file fixtures asserting `daemon_running` and human banner mode. |
| C-09 | Pressure table is derived from current platform mount stats; level boundaries come from config thresholds. | `src/cli_app.rs` (`render_status`, `pressure_level_str`) | Unit: threshold mapping tests; integration: fixture config threshold smoke test. |
| C-10 | `status` rate estimates are shown only if raw daemon state JSON contains `rates.<mount>.bytes_per_sec`. | `src/cli_app.rs` (`render_status`) | Integration: fixture state JSON with and without `rates` object. |
| C-11 | `status` ballast summary is config-derived (`file_count`, `file_size_bytes`, computed total pool), not live inventory. | `src/cli_app.rs` (`render_status`, `ballast_total_pool_bytes`) | Unit: `ballast_total_pool_bytes_*` tests + integration assertion against synthetic config. |
| C-12 | `status` recent activity is read from SQLite if available; otherwise falls back to `no database available`. | `src/cli_app.rs` (`render_status`) | Integration/e2e: run with and without sqlite path fixture. |
| C-13 | `state.json` schema consumed by dashboard/status includes `DaemonState`, `PressureState`, `BallastState`, `LastScanState`, and `Counters` fields from self-monitor. | `src/daemon/self_monitor.rs` structs | Unit: serde round-trip/parse tests for state schema; integration: status/dashboard fixture parse tests. |
| C-14 | Self-monitor writes `state.json` atomically via `.tmp` + rename and enforces owner-only permissions on Unix (0600). | `src/daemon/self_monitor.rs` (`write_state_atomic`) | Unit: existing atomic-write + permissions tests in self-monitor module. |
| C-15 | In crossterm dashboard mode, terminal lifecycle guarantees are: enter raw mode + alternate screen on start, always restore on exit. | `src/cli/dashboard.rs` (`run`) | Integration/manual: PTY-based test to verify alt-screen/raw-mode cleanup on normal and error exits. |
| C-16 | In crossterm dashboard mode, exit keys are `q`, `Esc`, and `Ctrl-C`. | `src/cli/dashboard.rs` (`run_inner`) | PTY integration/manual keystroke tests. |
| C-17 | In crossterm dashboard mode, when daemon state is unavailable it falls back to live fs stats and labels mode as `DEGRADED`. | `src/cli/dashboard.rs` (`run_inner`, `render_frame`) | Integration: missing-state fixture + fs collector fallback assertions. |
| C-18 | In crossterm dashboard mode, visible sections include pressure gauges, EWMA trends, last scan, ballast summary, counters/PID, and exit footer. | `src/cli/dashboard.rs` (`render_frame`) | Snapshot tests for frame content under deterministic fixture state. |

## Required Usage by Downstream Tasks

- Every implementation task in `bd-xzt.2*` and `bd-xzt.3*` must list affected
  contract IDs from this checklist in its design/PR notes.
- Every verification task in `bd-xzt.4*` must map tests directly to contract IDs.
- Rollout/signoff tasks in `bd-xzt.5*` must include an explicit pass/fail report
  against all contract IDs marked in scope.

## Out of Scope (Not Contracted Here)

- New UX ideas from FrankentUI that do not exist in current `status/dashboard`.
- Additional operator actions beyond current read-only status/dashboard behavior.
- Visual polish choices that do not alter semantics, safety boundaries, or data
  dependencies.
