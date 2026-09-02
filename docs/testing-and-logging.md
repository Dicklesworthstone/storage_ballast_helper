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
| Config | `config.rs` | validation, TOML roundtrip, defaults | Config schema, pressure thresholds |
| Errors | `errors.rs` | error types, display formatting | Error taxonomy |
| Platform | `platform.rs` | detect_platform, PAL dispatch | Linux/macOS abstraction |
| Protection | `scanner/protection.rs` | marker files, config globs, dual-mode | .sbh-protect markers, glob exclusions |
| EWMA | `monitoring/ewma.rs` | rate estimation, confidence, prediction | Disk rate trending |
| PID | `monitoring/pid_controller.rs` | 4-level escalation, config reload | Pressure response |
| Guardrails | `monitoring/guardrails.rs` | e-process drift, calibration, alarms | Statistical safety bounds |
| Predictive | `monitoring/predictive_action.rs` | horizon warnings, danger detection | Proactive action triggers |
| Scoring | `scanner/scoring.rs` | multi-factor, veto logic, evidence | Artifact classification |
| Walker | `scanner/walker.rs` | traversal, exclusion, parallelism | Directory scanning |
| Patterns | `scanner/pattern_registry.rs` | artifact type classification | Build artifact detection |
| Deletion | `scanner/deletion_executor.rs` | batch planning, circuit breaker | Safe cleanup execution |
| Merkle | `scanner/merkle.rs` | incremental index, checkpointing | Change detection |
| Ballast | `ballast/manager.rs`, `ballast/coordinator.rs` | provision, release, verify, replenish | Ballast file lifecycle |
| Policy | `daemon/policy.rs` | observe/canary/enforce/fallback | Decision mode transitions |
| Notifications | `daemon/notifications.rs` | event dispatch, channel handling | Alert delivery |
| Self-monitor | `daemon/self_monitor.rs` | respawn, staleness, resource limits | Daemon health |
| Logger | `logger/*.rs` | SQLite, JSONL, stats, dual-write | Activity recording |
| CLI | `cli_app.rs` | argument parsing, routing, output | Command interface |

### Dashboard / TUI Tests

**Command**: `rch exec "cargo test --lib --features tui tui::"`

All TUI tests require `--features tui`. Without it, these modules are excluded from compilation.

| Test Module | File | Tests | What It Validates |
| --- | --- | --- | --- |
| `test_unit_coverage` | `tui/test_unit_coverage.rs` | model/adapter/keymap/render helpers | C-08..C-18 contract compliance |
| `test_properties` | `tui/test_properties.rs` | reducer invariants, navigation, scheduler | No panics on random input, quit monotonicity |
| `test_replay` | `tui/test_replay.rs` | deterministic state replay regression | Same inputs produce same state (trace digest) |
| `test_scenario_drills` | `tui/test_scenario_drills.rs` | multi-phase operator workflows | Pressure escalation, ballast ops, explainability, incidents |
| `test_fault_injection` | `tui/test_fault_injection.rs` | adapter/state degradation and recovery | Safe degraded mode, recovery transitions |
| `test_snapshot_golden` | `tui/test_snapshot_golden.rs` | per-screen golden frame hashes | Visual output stability across changes |
| `test_operator_benchmark` | `tui/test_operator_benchmark.rs` | task-time, error-rate, keystroke count | Workflow efficiency vs legacy baseline |
| `test_stress` | `tui/test_stress.rs` | long-run stability, burst telemetry | Memory stability, frame-time consistency |
| `parity_harness` | `tui/parity_harness.rs` | legacy-vs-new frozen contract matrix | Zero behavior regression from old dashboard |
| `test_artifact` | `tui/test_artifact.rs` | e2e artifact schema validation | ArtifactCollector/CaseBuilder correctness |

**Running a single TUI test module:**
```bash
rch exec "cargo test --lib --features tui tui::test_replay -- --test-threads=4"
```

### Test Count Summary

| Category | Count |
| --- | --- |
| Library unit (no TUI) | 836 |
| Library unit (with TUI) | 1,776 |
| Binary (CLI) | 33 |
| Integration (all files) | 183 |
| E2E shell cases | 115+ |
| **Total automated** | **2,100+** |

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
./scripts/quality-gate.sh              # Remote compilation via rch (default)
./scripts/quality-gate.sh --local      # Local compilation
./scripts/quality-gate.sh --ci         # CI mode (abort on first HARD failure)
./scripts/quality-gate.sh --stage NAME # Run single named stage
./scripts/quality-gate.sh --verbose    # Full command output
```

The runbook runs 20 stages across 6 categories. Each stage has a HARD or SOFT
gate level. HARD failures block merge/release. SOFT failures require waivers.

**Stage summary:**

| # | Stage | Gate | Dimension |
| --- | --- | --- | --- |
| 1 | `fmt` | HARD | Code style |
| 2 | `clippy` | HARD | Correctness warnings |
| 3 | `unit-lib` | HARD | Core logic |
| 4 | `unit-bin` | HARD | CLI routing |
| 5 | `integration` | HARD | Pipeline correctness |
| 6 | `decision-plane` | HARD | Policy correctness |
| 7 | `fallback` | HARD | Fallback safety |
| 8 | `tui-unit` | HARD | Dashboard correctness |
| 9 | `tui-replay` | HARD | Deterministic replay |
| 10 | `tui-scenarios` | HARD | Operator workflows |
| 11 | `tui-properties` | HARD | Invariant safety |
| 12 | `tui-fault-injection` | HARD | Degraded recovery |
| 13 | `tui-snapshots` | SOFT | Visual contract |
| 14 | `tui-parity` | HARD | Legacy parity |
| 15 | `tui-benchmarks` | SOFT | Operator efficiency |
| 16 | `dashboard-integration` | HARD | Dashboard E2E |
| 17 | `stress` | HARD | Daemon stability |
| 18 | `stress-harness` | SOFT | Concurrency safety |
| 19 | `tui-stress` | SOFT | Dashboard endurance |
| 20 | `e2e` | HARD | User experience |

**Output artifacts:**
- `stages/<name>.log` — per-stage stdout/stderr
- `summary.json` — machine-readable results with trace_id, timing, pass/fail per stage
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
pushes to `refs/heads/main` queue behind each other and every one completes. Several
agents push to main every few minutes, and cancelling in progress meant no
main run ever finished (four in a row were cancelled on 2026-09-02).
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
- Name files by scope, e.g. `tests/integration_tests.rs`, `tests/scanner_integration.rs`.

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
