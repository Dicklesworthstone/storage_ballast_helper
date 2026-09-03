# Testing and Logging Guide

This document is the single source of truth for how to validate and debug
`storage_ballast_helper` behavior, including the new TUI dashboard.

## Quick Start

```bash
# Full quality gate (uses rch for remote compilation)
./scripts/quality-gate.sh

# Quick local check (no rch required)
cargo fmt --check
cargo test --lib --features tui
cargo test --bin sbh
```

## Status and Check JSON (schema_version 2)

`sbh status --json` and `sbh check --json` carry a top-level
`"schema_version": 2`. Version 2 keys each mount's `platform` block by
filesystem family and drops the APFS-only mount keys on every other family
instead of emitting them as null. Assert on the family you expect:

```json
{"path": "/data", "fs_type": "ext4", "free": 250, "free_pct": 25.0,
 "platform": {"linux": {"fs_type": "ext4", "is_ram_backed": false,
                        "is_readonly": false, "device_id": 66306}}}
```

```json
{"path": "/System/Volumes/Data", "fs_type": "apfs", "free": 250,
 "free_excludes_purgeable": true, "purgeable_bytes": 32,
 "platform": {"darwin": {"apfs": {"container_id": "/dev/disk3",
                                  "free_excludes_purgeable": true}}}}
```

Nothing in the repository parses these payloads except the tests and
`scripts/e2e_test.sh`; the dashboard reads `state.json`, whose own
`schema_version` is checked by `tui/adapters.rs`. Unit coverage:
`status_mount_json_keys_the_platform_block_by_filesystem_family` and
`status_mount_json_exposes_apfs_container_metadata` in `src/cli_app.rs`; the
macOS integration tests compare the APFS block against `diskutil`.

## Dashboard and Status Contract Baseline (bd-xzt.1.1)

Source of truth: `docs/dashboard-status-contract-baseline.md`

For TUI/dashboard overhaul work (`bd-xzt.*`):

- Implementation tasks must name the contract IDs they change.
- Test tasks must map each new assertion to at least one contract ID.
- Release/signoff tasks must report contract pass/fail status, not just aggregate test counts.

## TUI Acceptance Gates and Budgets (bd-xzt.1.5)

Source of truth: `docs/tui-acceptance-gates-and-budgets.md`

For TUI/dashboard rollout work:

- Treat `HARD` gates as release blockers.
- Keep performance and error budget reporting trace-linked to test artifacts.
- Use `scripts/quality-gate.sh` as the canonical gate sequence.

## Test Coverage Map

### Unit Tests (library)

**Command**: `rch exec "cargo test --lib --features tui"`

| Module | File(s) | Tests | Coverage |
| --- | --- | --- | --- |
| Config | `src/core/config.rs` | validation, TOML roundtrip, defaults, README example | Config schema, pressure thresholds |
| Errors | `src/core/errors.rs` | error types, display formatting, `ERROR_CODES` catalog | Error taxonomy |
| Platform | `src/platform/pal.rs`, `src/platform/types.rs` | detect_platform, PAL dispatch | Linux/macOS abstraction |
| Protection | `src/scanner/protection.rs` | marker files, config globs, dual-mode | .sbh-protect markers, glob exclusions |
| EWMA | `src/monitor/ewma.rs` | rate estimation, confidence, prediction | Disk rate trending |
| PID | `src/monitor/pid.rs` | level classification, response table, config reload, README formulas | Pressure response |
| Guardrails | `src/monitor/guardrails.rs` | e-process drift, calibration, alarms | Statistical safety bounds |
| Predictive | `src/monitor/predictive.rs` | horizon warnings, danger detection | Proactive action triggers |
| Scoring | `src/scanner/scoring.rs` | multi-factor, veto logic, evidence | Artifact classification |
| Walker | `src/scanner/walker.rs` | traversal, exclusion, parallelism | Directory scanning |
| Patterns | `src/scanner/patterns.rs` | artifact type classification | Build artifact detection |
| Deletion | `src/scanner/deletion.rs` | batch planning, circuit breaker | Safe cleanup execution |
| Merkle | `src/scanner/merkle.rs` | incremental index, checkpointing | Change detection |
| Ballast | `src/ballast/manager.rs`, `src/ballast/coordinator.rs` | provision, release, verify, replenish | Ballast file lifecycle |
| Policy | `src/daemon/policy.rs` | observe/canary/enforce/fallback, behavior matrix | Decision mode transitions |
| Notifications | `src/daemon/notifications.rs` | event dispatch, channel handling | Alert delivery |
| Self-monitor | `src/daemon/self_monitor.rs` | respawn, staleness, resource limits | Daemon health |
| Logger | `src/logger/dual.rs`, `src/logger/sqlite.rs`, `src/logger/jsonl.rs`, `src/logger/stats.rs` | SQLite, JSONL, stats, dual-write | Activity recording |
| Docs generator | `src/cli/docs.rs` | env-var registry, command/flag parity, file references, generated regions | README/AGENTS.md truth |
| CLI | `src/cli_app.rs` | argument parsing, routing, output, doc contract | Command interface |

### Dashboard / TUI Tests

**Command**: `rch exec "cargo test --lib --features tui tui::"`

All TUI tests require `--features tui`. Without it, these modules are excluded from compilation.

| Test Module | File | Tests | What It Validates |
| --- | --- | --- | --- |
| `test_unit_coverage` | `src/tui/test_unit_coverage.rs` | model/adapter/keymap/render helpers | C-08..C-18 contract compliance |
| `test_properties` | `src/tui/test_properties.rs` | reducer invariants, navigation, scheduler | No panics on random input, quit monotonicity |
| `test_replay` | `src/tui/test_replay.rs` | deterministic state replay regression | Same inputs produce same state (trace digest) |
| `test_scenario_drills` | `src/tui/test_scenario_drills.rs` | multi-phase operator workflows | Pressure escalation, ballast ops, explainability, incidents |
| `test_fault_injection` | `src/tui/test_fault_injection.rs` | adapter/state degradation and recovery | Safe degraded mode, recovery transitions |
| `test_snapshot_golden` | `src/tui/test_snapshot_golden.rs` | per-screen golden frame hashes | Visual output stability across changes |
| `test_operator_benchmark` | `src/tui/test_operator_benchmark.rs` | task-time, error-rate, keystroke count | Workflow efficiency vs legacy baseline |
| `test_stress` | `src/tui/test_stress.rs` | long-run stability, burst telemetry | Memory stability, frame-time consistency |
| `parity_harness` | `src/tui/parity_harness.rs` | legacy-vs-new frozen contract matrix | Zero behavior regression from old dashboard |
| `test_artifact` | `src/tui/test_artifact.rs` | e2e artifact schema validation | ArtifactCollector/CaseBuilder correctness |
| `replay` | `src/tui/replay.rs` | log timeline load/reconstruction, scrubber driver, replay adapter | `sbh dashboard --replay` |

**Running a single TUI test module:**
```bash
rch exec "cargo test --lib --features tui tui::test_replay -- --test-threads=4"
```

### Test Count Summary

Generated by `./scripts/test-census.sh` (`cargo test <target> -- --list` per
target on Linux; `--check` fails on drift, `--write` rewrites the table).
Counts are what libtest enumerates on this platform and feature set;
macOS-only tests are compiled out here, `#[ignore]` tests are listed.

<!-- sbh-census:begin -->
| Target | Tests |
| --- | --- |
| `cargo test --lib` (default features, with the TUI) | 2593 |
| `cargo test --lib --no-default-features --features cli,daemon,sqlite` (lean) | 1613 |
| `cargo test --bin sbh` | 140 |
| `cargo test --test cli_exit_codes` | 5 |
| `cargo test --test daemon_e2e` | 21 |
| `cargo test --test dashboard_integration_tests` | 31 |
| `cargo test --test dashboard_pty` | 3 |
| `cargo test --test decision_plane_e2e` | 7 |
| `cargo test --test explain_ledger` | 4 |
| `cargo test --test fallback_verification` | 42 |
| `cargo test --test fuzz_smoke` | 2 |
| `cargo test --test installer_e2e` | 50 |
| `cargo test --test integration_tests` | 71 |
| `cargo test --test proof_harness` | 26 |
| `cargo test --test regression_issue_pid_slow_attack` | 1 |
| `cargo test --test regression_path_traversal` | 4 |
| `cargo test --test regression_risky_patterns` | 16 |
| `cargo test --test repro_ballast_restart_stability` | 1 |
| `cargo test --test repro_dangerous_patterns` | 1 |
| `cargo test --test repro_glob` | 2 |
| `cargo test --test repro_issue` | 2 |
| `cargo test --test repro_merkle_index_integration` | 1 |
| `cargo test --test repro_pid_skew` | 1 |
| `cargo test --test repro_risky_patterns` | 2 |
| `cargo test --test repro_symlink_loop` | 1 |
| `cargo test --test repro_tui_panic` | 2 |
| `cargo test --test stress_harness` | 9 |
| `cargo test --test stress_tests` | 12 |
| Integration test files (sum of the `--test` rows) | 317 |
| E2E shell cases defined in `scripts/e2e_test.sh` | 129 |
| **Cargo tests on Linux, default features (lib + bin + integration)** | **3050** |
<!-- sbh-census:end -->

### Binary Tests (CLI)

**Command**: `rch exec "cargo test --bin sbh"`

Tests CLI argument parsing, subcommand routing, dashboard mode resolution,
and output formatting (33 tests).

### Integration Tests

**Command**: `rch exec "cargo test --test <name>"`

| File | Tests | Coverage |
| --- | --- | --- |
| `integration_tests.rs` | CLI smoke, full pipeline, walker, scoring, ballast lifecycle | C-01..C-06, C-13 |
| `dashboard_integration_tests.rs` | Command semantics, state-file contract, mode selection | C-08..C-13, feature gating |
| `fallback_verification.rs` | Config rollback, env overrides, degradation chains, schema drift | C-14..C-18 |
| `decision_plane_e2e.rs` | Shadow/canary/enforce/fallback mode transitions | Policy safety invariants |
| `proof_harness.rs` | Scoring determinism, veto hard constraints, state machine | Mathematical correctness proofs |
| `installer_e2e.rs` | Install/update/rollback/uninstall orchestration | Installer safety contracts |
| `stress_tests.rs` | Long-run daemon loops, SQLite throughput, channel deadlocks | Daemon stability |
| `stress_harness.rs` | Walker concurrency, multi-volume coordination, EWMA bursts | Agent swarm load behavior |
| `repro_issue.rs`, `repro_glob.rs` | Specific bug regression tests | Previously-fixed issues |

### E2E Tests (Shell)

**Command**: `./scripts/e2e_test.sh [--verbose]`

33 sections covering: CLI smoke, exit codes, config, status, scan, clean,
ballast lifecycle, protection markers, check, blame, tune, stats, emergency,
scoring determinism, daemon stubs, dashboard modes, output formatting,
installer, offline update, performance, concurrent CLI, JSON coverage.

**Environment variables:**

| Variable | Default | Purpose |
| --- | --- | --- |
| `SBH_E2E_LOG_DIR` | `/tmp/sbh-e2e-TIMESTAMP/` | Artifact output directory |
| `SBH_E2E_CASE_TIMEOUT` | `60` | Per-case timeout (seconds) |
| `SBH_E2E_SUITE_BUDGET` | `600` | Total suite time budget (seconds) |
| `SBH_E2E_FLAKY_RETRIES` | `1` | Retry count for flaky tests |
| `SBH_E2E_BIN` | auto-detected | Override binary path |

**Artifacts produced:**
- `cases/<name>.log` — per-case stdout/stderr with timing
- `summary.json` — machine-readable pass/fail counts with case names
- `e2e.log` — timestamped suite-level log

## Verification Commands

**Authoritative runbook:** `scripts/quality-gate.sh` (bd-xzt.4.6)

```bash
./scripts/quality-gate.sh                 # Remote compilation via rch (default)
./scripts/quality-gate.sh --local         # Local compilation
./scripts/quality-gate.sh --ci            # CI mode (abort on first HARD failure)
./scripts/quality-gate.sh --stage NAME    # Run single named stage
./scripts/quality-gate.sh --verbose       # Full command output
./scripts/quality-gate.sh --print-stages  # The stage table, without running (--markdown for docs)
./scripts/quality-gate.sh --self-test     # The executed-test accounting and the vacuous path, without cargo
```

The runbook's stages are listed below in six groups (the count is the
table's last line). HARD failures block merge/release. SOFT failures
require waivers. A `test` stage must
execute at least one test: the script sums the `test result:` lines of the
stage log (passed + failed), and a command that exits 0 having selected no
test is recorded as **vacuous**, a failure of that gate. The `e2e` stage
counts the suite's `summary pass=N fail=M` line; `check` stages (fmt,
clippy) have no tests.

**Stage summary** (generated by `./scripts/quality-gate.sh --print-stages --markdown`; `--write-stages` rewrites it after editing the script, `--check-stages` fails on drift):

<!-- sbh-qg:stages:begin -->
| # | Stage | Gate | Kind | Group | Dimension | Command |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `fmt` | HARD | check | Code Quality | code-style | `cargo fmt --check` |
| 2 | `clippy` | HARD | check | Code Quality | correctness-warnings | `cargo clippy --all-targets -- -D warnings` |
| 3 | `docs-drift` | SOFT | check | Code Quality | generated-docs | `cargo run --quiet --bin sbh -- docs --check README.md AGENTS.md` |
| 4 | `test-census` | SOFT | check | Code Quality | generated-test-counts | `./scripts/test-census.sh --check` |
| 5 | `stage-docs` | SOFT | check | Code Quality | generated-stage-table | `./scripts/quality-gate.sh --check-stages` |
| 6 | `unit-lib` | HARD | test | Unit Tests | core-logic | `cargo test --lib -- --test-threads=4` |
| 7 | `unit-bin` | HARD | test | Unit Tests | cli-routing | `cargo test --bin sbh -- --test-threads=4` |
| 8 | `cli-exit-codes` | HARD | test | Unit Tests | exit-code-contract | `cargo test --test cli_exit_codes -- --test-threads=4` |
| 9 | `integration` | HARD | test | Integration Tests | pipeline-correctness | `cargo test --test integration_tests -- --test-threads=4` |
| 10 | `decision-plane` | HARD | test | Integration Tests | policy-correctness | `cargo test --test proof_harness -- --test-threads=4` |
| 11 | `decision-e2e` | HARD | test | Integration Tests | policy-lifecycle | `cargo test --test decision_plane_e2e -- --test-threads=4` |
| 12 | `explain-ledger` | HARD | test | Integration Tests | explainability | `cargo test --test explain_ledger -- --test-threads=4` |
| 13 | `fallback` | HARD | test | Integration Tests | fallback-safety | `cargo test --test fallback_verification --features tui -- --test-threads=4` |
| 14 | `tui-unit` | HARD | test | Dashboard / TUI Tests | dashboard-correctness | `cargo test --lib --features tui tui:: -- --test-threads=4` |
| 15 | `tui-replay` | HARD | test | Dashboard / TUI Tests | deterministic-replay | `cargo test --lib --features tui tui::test_replay -- --test-threads=4` |
| 16 | `tui-scenarios` | HARD | test | Dashboard / TUI Tests | operator-workflows | `cargo test --lib --features tui tui::test_scenario_drills -- --test-threads=4` |
| 17 | `tui-properties` | HARD | test | Dashboard / TUI Tests | invariant-safety | `cargo test --lib --features tui tui::test_properties -- --test-threads=4` |
| 18 | `tui-fault-injection` | HARD | test | Dashboard / TUI Tests | degraded-recovery | `cargo test --lib --features tui tui::test_fault_injection -- --test-threads=4` |
| 19 | `tui-snapshots` | SOFT | test | Dashboard / TUI Tests | visual-contract | `cargo test --lib --features tui tui::test_snapshot_golden -- --test-threads=4` |
| 20 | `tui-parity` | HARD | test | Dashboard / TUI Tests | legacy-parity | `cargo test --lib --features tui tui::parity_harness -- --test-threads=4` |
| 21 | `tui-benchmarks` | SOFT | test | Dashboard / TUI Tests | operator-efficiency | `cargo test --lib --features tui tui::test_operator_benchmark -- --test-threads=4` |
| 22 | `dashboard-integration` | HARD | test | Dashboard / TUI Tests | dashboard-e2e | `cargo test --test dashboard_integration_tests --features tui -- --test-threads=4` |
| 23 | `dashboard-pty` | HARD | test | Dashboard / TUI Tests | dashboard-pty-session | `cargo test --test dashboard_pty --features tui -- --test-threads=1` |
| 24 | `stress` | HARD | test | Stress & Performance | daemon-stability | `cargo test --test stress_tests -- --test-threads=2` |
| 25 | `fuzz` | SOFT | test | Stress & Performance | parser-robustness | `cargo test --test fuzz_smoke` |
| 26 | `stress-harness` | SOFT | test | Stress & Performance | concurrency-safety | `cargo test --test stress_harness -- --test-threads=2` |
| 27 | `tui-stress` | SOFT | test | Stress & Performance | dashboard-endurance | `cargo test --lib --features tui tui::test_stress -- --test-threads=4` |
| 28 | `daemon-e2e` | SOFT | test | E2E & Installer | daemon-lifecycle | `cargo test --test daemon_e2e -- --test-threads=2` |
| 29 | `installer` | HARD | test | E2E & Installer | install-safety | `cargo test --test installer_e2e -- --test-threads=4` |
| 30 | `e2e` | HARD | e2e | E2E & Installer | user-experience | `./scripts/e2e_test.sh` |

30 stages: 21 HARD, 9 SOFT.
<!-- sbh-qg:stages:end -->

**Output artifacts:**
- `stages/<name>.log` — per-stage stdout/stderr
- `summary.json` — machine-readable results with trace_id, timing, status (`pass`/`fail`/`vacuous`) and `executed_tests` per stage, plus the totals
- `e2e/` — nested e2e suite artifacts (when stage `e2e` runs)

**Remote compilation:** CPU-intensive stages use `rch exec` by default.
Use `--local` to skip rch. CI workflows run locally (no rch available).

**Docs update lint:** PR CI runs `scripts/ci_docs_update_check.sh` in the
Format + Lint job before Cargo setup. The guard compares the pull request
against the base branch and fails when user-facing source, installer,
packaging, cleanup-policy, or config-schema files change without a companion
update to README, `docs/`, CHANGELOG, CLI help text in `src/cli_app.rs`, or the
Homebrew formula. It also checks two high-risk cases directly:

- New `#[arg]` or `#[command]` annotations in `src/cli_app.rs` must add clap
  help/about text or a Rust doc comment in the same diff.
- New public config fields in `src/core/config.rs` must update config docs or
  sample configs.

Local dry run:
```bash
DOCS_UPDATE_BASE=origin/main DOCS_UPDATE_HEAD=HEAD bash scripts/ci_docs_update_check.sh
```

**Superseded CI cancellation:** Branch and pull-request CI runs use workflow
concurrency group `github.workflow` plus the PR number or ref, with
`cancel-in-progress` enabled only for `pull_request` events;
a main run that is in progress is never cancelled. Several
agents push to main every few minutes, and cancelling in progress meant no
main run ever finished (four in a row were cancelled on 2026-09-02).
GitHub still keeps at most one main run waiting behind the active one, and
a newer push replaces the waiting run, so the group holder has to start: on
2026-09-02 a run stuck in `queued` for 78 minutes held the group and every
later push was cancelled while pending until that run was cancelled by hand
(`gh run cancel <id>`). Check `gh run list --status queued` before blaming
the concurrency policy.
Tag-triggered release workflow calls are not cancelable through this CI
policy either, which preserves `workflow_call` behavior for the
release quality gates.

**macOS validation independence:** The `macos-platform`, `macos-coverage`, and
`macos-benchmarks` jobs intentionally do not declare `needs: check`. They still
run their own checkout, toolchain setup, build, tests, and artifact upload, but
a queued Ubuntu runner cannot hide missing macOS proof. The final provenance job
continues to require all Linux and macOS validation lanes before a CI run is
trusted.

**CI artifact retention** (`.github/workflows/ci.yml`):

| CI Job | Artifacts | Retention |
| --- | --- | --- |
| homebrew-formula | `homebrew-formula-style-output.txt`, `homebrew-generated-formula-style-output.txt`, generated `Formula/sbh.rb` | 14 days |
| unit | `unit-test-output.txt`, `bin-test-output.txt` | 14 days |
| integration | `integration-output.txt` | 14 days |
| decision-plane | `proof-harness-output.txt`, `decision-plane-e2e-output.txt` | 30 days |
| e2e | `e2e-output.txt`, per-case logs | 14 days |
| macos-platform | `macos-*-output.txt`, `macos-runner-info.txt`, `macos-toolchain-output.txt`, `macos-codesign-output.txt`, `macos-codesign-entitlements.plist`, `sbh-completions.zsh` | 14 days |
| macos-coverage | `current-coverage.json`, `current-lcov.info`, `coverage-summary.json`, optional PR `base-coverage.json` | 30 days |
| macos-benchmarks | `current-summary.json`, `current-output.txt`, `benchmark-summary.json`, optional PR `base-summary.json` | 30 days |
| stress | `stress-output.txt` | 14 days |
| dashboard | TUI test stage outputs | 14 days |
| provenance | `ci-metadata.json`, `dependency-tree.txt` | 90 days |

**macOS CI runners:** As of May 2026, GitHub's standard hosted runner labels
for this project are `macos-latest` for Apple Silicon (`arm64`) and
`macos-15-intel` for Intel (`x86_64`). The retired `macos-13` label is not used
in active workflows. The `macos-platform` job asserts `uname -m` so runner-label
drift is caught before release artifacts are trusted.

**Homebrew formula validation:** The `homebrew-formula` job runs on
`macos-latest` before release credentials are needed. It runs `brew style` on
the checked-in `packaging/homebrew/Formula/sbh.rb`, then copies the formula,
substitutes a synthetic tag and both macOS SHA-256 checksums with the same Perl
expression used by `.github/workflows/release.yml`, fails if any
`REPLACE_WITH_` marker remains, and runs `brew style` on the generated formula.
The tagged release workflow repeats the checksum substitution against the real
release artifacts and runs `ruby -c homebrew-sbh/Formula/sbh.rb` before pushing
the tap update with the repository-scoped deploy key. This keeps the tap formula
generation path covered on normal PR/push CI and still catches malformed
generated Ruby during a signed release.

**macOS coverage tracking:** The `macos-coverage` job runs on `macos-latest`
and installs `cargo-llvm-cov` with `taiki-e/install-action@cargo-llvm-cov`, the
upstream GitHub Actions install path for prebuilt cargo-llvm-cov binaries. It
generates JSON and LCOV coverage for the CI-supported non-TUI library, binary,
and `integration_tests` targets. On pull requests it also checks out the base
SHA, computes the same macOS line-coverage summary, and fails if current
coverage is more than 2.0 percentage points below the base branch. The rendered
step summary and `coverage-summary.json` show current, base, and delta values.

**macOS performance budgets:** The `macos-benchmarks` job runs on
`macos-latest` and executes the Criterion bench target
`macos_performance`. The bench records two hard budget summaries:

- `daemon_poll_tick_avg_ms` must stay at or below 200 ms for a representative
  synthetic monitoring tick.
- `pal_surface_avg_ms` must stay at or below 5 ms for the PAL filesystem and
  memory calls exercised by a tick.

On pull requests, CI also runs the same bench target at the base SHA when that
target exists there. `benchmark-summary.json` reports current, base, and delta
values, and the job fails if either metric regresses by more than 20 percent.
The harness uses the native PAL when platform detection is available and falls
back to a deterministic synthetic PAL while a platform implementation is still
being wired in.

## Log Artifact Naming Conventions

### Test Artifacts

All test artifacts use this naming pattern:
```
<suite>-<timestamp>/<stage-or-case>.<ext>
```

Examples:
- `/tmp/sbh-qg-20260216-120000/stages/tui-replay.log`
- `/tmp/sbh-e2e-20260216-120000/cases/17a_dashboard_tui_feature_gate.log`
- `/tmp/sbh-qg-20260216-120000/summary.json`

### Dashboard E2E Artifact Schema

The `ArtifactCollector` (`tui/e2e_artifact.rs`) produces structured test bundles:

```
TestRunBundle {
  trace_id: String,          // Unique run identifier
  started_at: String,        // ISO-8601 timestamp
  finished_at: String,
  cases: Vec<TestCaseArtifact>,
  summary: { total, passed, failed },
  diagnostics: Vec<DiagnosticEntry>,
}
```

Each `TestCaseArtifact` contains:
- `name`, `section`, `tags` — identification and classification
- `frames: Vec<FrameCapture>` — dashboard state snapshots (tick, screen, overlay, degraded)
- `assertions: Vec<AssertionRecord>` — expected vs actual with pass/fail
- `diagnostics: Vec<DiagnosticEntry>` — debug context for failures
- `status` — Pass, Fail, or Skip

### Daemon Runtime Logs

Daemon structured logs follow this schema:
```json
{
  "ts": "2026-02-16T08:00:00Z",
  "level": "INFO",
  "component": "scanner",
  "event": "scan.start",
  "trace_id": "abc123",
  "message": "Starting artifact scan"
}
```

Stable component IDs: `scanner`, `ballast`, `monitor.pid`, `monitor.ewma`,
`daemon`, `logger`, `walker`, `protection`, `policy`, `notification`.

Stable event IDs follow `<component>.<action>` pattern:
- `scan.start`, `scan.complete`, `scan.error`
- `decision.selected`, `decision.vetoed`, `decision.explain`
- `ballast.release`, `ballast.provision`, `ballast.verify`
- `pressure.escalate`, `pressure.recover`
- `policy.transition`, `policy.fallback`

## Failure Triage Guide

### Common Failure Classes

| Symptom | Likely Cause | Action |
| --- | --- | --- |
| Single TUI test fails | Model field added/renamed | Update test fixture to match new struct |
| All replay tests fail | Update loop logic changed | Regenerate replay fixtures or verify new behavior is correct |
| Snapshot golden mismatch | Render output changed | Compare old/new frames; update golden if intentional |
| Property test fails | Random input found invariant violation | Check seed in output, reproduce with `-- --seed N` |
| Fault injection fails | Adapter degradation path changed | Verify DashboardStateAdapter still degrades safely |
| Parity harness fails | New dashboard lost legacy behavior | Map failure to C-xx contract, restore behavior |
| Scenario drill fails | Cross-screen workflow broke | Check which phase failed; isolate to specific screen/transition |
| Benchmark threshold exceeded | Workflow takes too many keystrokes | Review command palette or shortcut changes |
| E2E timeout | Hung process or slow binary | Check `SBH_E2E_CASE_TIMEOUT`, look for blocking I/O |
| Stress test OOM | Unbounded growth in model/adapter | Profile with sustained load, check Vec/HashMap bounds |
| macOS benchmark regression | Daemon tick or PAL surface cost exceeded budget/delta | Inspect `macos-benchmarks/benchmark-summary.json`, then profile the touched monitor or PAL path |
| Decision plane proof fails | Scoring/ranking invariant violated | Check scoring weights, RRF fusion, or veto logic |
| Clippy lint | New lint in toolchain update | Add targeted `#[allow]` with justification, or fix |
| Feature gate error | Missing `--features tui` | TUI tests require explicit feature flag |
| A `chmod`-based test fails only as root | Root bypasses permission bits, so the provoked `EACCES` never happens | Guard the test with `crate::platform::running_as_root()` and print `SKIP: running as root (<test>)`; the CI job `unit-as-root` counts those lines |
| `from_source` cargo/rustc probes fail under `sudo` | `sudo` reset `PATH`/`HOME`, so rustup cannot find a toolchain | Run as `sudo -E env "PATH=$PATH" cargo test --lib` (what CI does); this is an environment problem, not a permission one |

### Isolating TUI Failures

When a TUI test fails, run the specific module in isolation:

```bash
# Run just the failing module with full output
rch exec "cargo test --lib --features tui tui::test_replay -- --nocapture --test-threads=1"

# Run a single test by name
rch exec "cargo test --lib --features tui tui::test_replay::scenario_name -- --nocapture"
```

For determinism failures, the test output includes a **trace digest** (SHA-256
of state transitions). Compare the digest from the failing run against the
expected value to identify where the state diverged.

For scenario drill failures, the **ArtifactCollector** output includes per-phase
assertions with expected vs actual values, making it straightforward to identify
which phase and which assertion failed.

### Failure Escalation

1. **HARD gate failure**: Merge/release blocked. Create a regression bead, link
   to the failing gate ID, fix, and re-run the full gate sequence.
2. **SOFT gate failure**: Record a waiver with mitigation, owner, and fix bead.
   Promotion proceeds but the waiver is visible in the signoff artifact.
3. **Intermittent failure**: Run the failing stage in isolation 3 times. If it
   passes consistently, flag as flaky. If it fails 2/3 times, treat as HARD.

## Structured Logging Registration

### Event Shape

Every new module should emit logs with these baseline fields:

- `ts`: RFC3339 timestamp
- `level`: `INFO|WARN|ERROR`
- `component`: stable component id (see list above)
- `event`: stable event id (`component.action` pattern)
- `trace_id`: correlation id when available
- `message`: concise human-readable summary

### Where to Wire

- Human-readable logs: stderr / console output for operators
- Machine-readable logs: JSONL and/or SQLite activity records
- Integration tests should assert on both behavioral outcomes and log artifacts when practical

### Installer/Updater Diagnostics (Required)

Installer/update flows should emit phase-level records that include:

- `command`: `install|update|bootstrap|uninstall`
- `phase`: deterministic step label (`resolve_contract`, `verify_integrity`, `backup_create`, `rollback_apply`, etc.)
- `decision`: `allow|deny|bypass|retry|rollback`
- `reason_codes`: stable reason list for failures/overrides
- `target_version` and `current_version` when applicable

## Test Registration

### 1. Unit and Property Tests

- Add module-level unit tests in the same file behind `#[cfg(test)]`.
- Keep tests deterministic: fixed inputs, explicit timestamps, no random nondeterminism unless seeded.
- For property tests, use `proptest` with explicit strategies and clear shrinking expectations.

### 2. Integration Tests

- Add cross-module tests in `tests/`.
- Reuse `tests/common/mod.rs` for:
  - command execution helpers
  - verbose test logging
  - per-case trace artifacts
- Name files by scope, e.g. `tests/integration_tests.rs`, `tests/dashboard_pty.rs`.

### 3. End-to-End Tests

- Add scenario-driven shell tests under `scripts/`.
- Use `scripts/e2e_test.sh` as the entrypoint pattern.
- Each scenario must:
  - emit a scenario id/name
  - capture stdout/stderr
  - append structured metadata to the shared log
  - fail with a non-zero exit code on assertion failure

### 4. Dashboard Tests

- Add TUI test modules in `src/tui/` behind `#[cfg(test)]`.
- Use `DashboardHarness` from `test_harness.rs` for headless testing.
- Use `ArtifactCollector` from `e2e_artifact.rs` for structured output.
- Every scenario drill should have a corresponding determinism test.
- Map assertions to contract IDs (C-01..C-18) where applicable.

**DashboardHarness example:**
```rust
use super::test_harness::*;

#[test]
fn my_dashboard_test() {
    let mut h = DashboardHarness::new();
    h.startup_with_state(sample_healthy_state());
    h.tick(); // must tick before first capture_frame

    // Navigate to a screen
    h.inject_char('e'); // switch to explainability
    h.tick();

    // Assert on model state
    assert_eq!(h.screen(), Screen::Explainability);
    assert!(!h.is_degraded());

    // Capture a frame for artifact collection
    let fc = capture_frame(&h);
    assert!(fc.text.contains("Explainability"));

    // Inject keycode (not char) for Enter
    h.inject_keycode(ftui_core::event::KeyCode::Enter);
    h.tick();

    // Feed degraded state
    h.feed_unavailable();
    h.tick();
    assert!(h.is_degraded());
}
```

**ArtifactCollector example:**
```rust
let mut collector = ArtifactCollector::new("my_drill");
let fc = capture_frame(&h);
collector.start_case("phase_1")
    .frame(fc)
    .assertion("screen is overview", h.screen() == Screen::Overview,
               "Overview", &format!("{:?}", h.screen()))
    .finish(CaseStatus::Pass);
let bundle = collector.finalize();
bundle.validate_minimum_payload(); // ensures failing cases have diagnostics
```

**Key patterns:**
- Always call `h.tick()` before the first `capture_frame(&h)`.
- Use `inject_keycode(KeyCode::Enter)` for Enter, not `inject_char('\n')`.
- Extract owned values from `capture_frame` before calling `h.model_mut()`
  to avoid borrow checker conflicts (`capture_frame` borrows `&h`
  immutably while `model_mut` needs `&mut`).

## FrankentUI Code Reuse Compliance (bd-xzt.1.6)

Source of truth: `docs/frankentui-compliance-plan.md`

For any PR importing FrankentUI-derived code:

- Follow the import review checklist in the compliance plan.
- Verify nightly toolchain compilation before merging.
- Add attribution comments to files with substantial copied code.
- Audit new transitive dependencies for permissive licensing.

## Contribution Checklist for New Modules

1. Add/update module tests (`#[cfg(test)]` and/or `tests/`).
2. Register at least one integration assertion for cross-module behavior.
3. Add/extend an e2e scenario if the change is user-facing.
4. Emit structured logs with stable `component` + `event` naming.
5. For dashboard changes: add TUI test assertions mapped to contract IDs.
6. Run `./scripts/quality-gate.sh --stage <relevant>` before pushing.
7. Update this document if you introduce a new test/logging pattern.
