# Testing and Logging Registration Guide

This document defines the baseline conventions for adding tests and structured logs in `storage_ballast_helper`.

## Dashboard and Status Contract Baseline (bd-xzt.1.1)

Source of truth: `docs/dashboard-status-contract-baseline.md`

For TUI/dashboard overhaul work (`bd-xzt.*`):

- Implementation tasks must name the contract IDs they change.
- Test tasks must map each new assertion to at least one contract ID.
- Release/signoff tasks must report contract pass/fail status, not just aggregate test counts.

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

## Structured Logging Registration

### Event Shape

Every new module should emit logs with these baseline fields:

- `ts`: RFC3339 timestamp
- `level`: `INFO|WARN|ERROR`
- `component`: stable component id (`scanner`, `monitor.pid`, `ballast`, etc.)
- `event`: stable event id (`scan.start`, `decision.selected`, `ballast.release`)
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

## Verification Commands

```bash
cargo fmt --check
rch exec "cargo check --all-targets"
rch exec "cargo clippy --all-targets -- -D warnings"
rch exec "cargo test --lib"
rch exec "cargo test --test integration_tests"
./scripts/e2e_test.sh
```

## FrankentUI Code Reuse Compliance (bd-xzt.1.6)

Source of truth: `docs/frankentui-compliance-plan.md`

For any PR importing FrankentUI-derived code:

- Follow the import review checklist in the compliance plan.
- Verify stable toolchain compilation before merging.
- Add attribution comments to files with substantial copied code.
- Audit new transitive dependencies for permissive licensing.

## Contribution Checklist for New Modules

1. Add/update module tests (`#[cfg(test)]` and/or `tests/`).
2. Register at least one integration assertion for cross-module behavior.
3. Add/extend an e2e scenario if the change is user-facing.
4. Emit structured logs with stable `component` + `event` naming.
5. Update this document if you introduce a new test/logging pattern.
