# AGENTS.md — storage_ballast_helper (`sbh`)

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main main:master
  ```

**Why this matters:** Install URLs and update checks may reference `master`. If `master` falls behind `main`, users get stale code.

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main main:master`

---

## Multi-Agent Environment

Multiple agents work on this codebase simultaneously. This is normal and expected.

**How to handle other agents' changes:**
- You will regularly see modified files you didn't touch in `git status`. This is expected.
- **NEVER** stash, revert, overwrite, or otherwise disturb other agents' changes.
- Treat those changes identically to changes you yourself made. Commit them alongside your own work.
- If another agent's code causes compilation errors, fix them as part of your normal workflow.
- Never stop to ask about "unexpected changes" — they are always from concurrent agents.

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (see `Cargo.toml`)
- **Toolchain:** Stable (see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml only
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]` in both `lib.rs` and `main.rs`)

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` + `clap_complete` | CLI parsing with derive macros and shell completion generation |
| `serde` + `serde_json` + `toml` | Serialization for config (TOML), structured output (JSON) |
| `rusqlite` (bundled) | SQLite for activity logging and stats queries |
| `chrono` | Timestamps for events and log entries |
| `colored` | Terminal colors with TTY detection |
| `thiserror` | Structured error types with stable error codes |
| `parking_lot` + `crossbeam-channel` | Concurrency primitives (no tokio) |
| `memchr` | Fast byte scanning for pattern matching |
| `regex` | Artifact classification patterns |
| `sha2` | SHA-256 checksums for supply-chain verification |
| `signal-hook` | Signal handling for graceful daemon shutdown |
| `rand` | Ballast file generation and randomized test fixtures |
| `nix` + `libc` | Unix-specific filesystem and signal operations |
| `tempfile` | Test fixtures (dev-dependency) |
| `proptest` | Property-based testing (dev-dependency) |

### Release Profile

```toml
[profile.release]
opt-level = "z"     # Optimize for size (lean binary for distribution)
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

### Clippy Configuration

Pedantic + nursery lints are enabled project-wide with select exceptions:

```toml
[lints.clippy]
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_panics_doc = "allow"
missing_errors_doc = "allow"
missing_const_for_fn = "allow"
doc_markdown = "allow"
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Remote Compilation (CRITICAL)

**All CPU-intensive operations MUST use `rch` (Remote Compilation Helper)** to offload work to remote workers. This includes `cargo check`, `cargo test`, `cargo clippy`, and `cargo build`.

```bash
# CORRECT: use rch for all compilation
rch exec "cargo check --all-targets"
rch exec "cargo test --lib"
rch exec "cargo test --bin sbh -- test_name"
rch exec "cargo clippy --all-targets -- -D warnings"
rch exec "cargo fmt --check"

# WRONG: never run cargo directly
cargo check   # DO NOT DO THIS
cargo test    # DO NOT DO THIS
```

**Exceptions:** `cargo fmt` (formatting only, no compilation) can run locally.

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings
rch exec "cargo check --all-targets"

# Check for clippy lints (pedantic + nursery are enabled)
rch exec "cargo clippy --all-targets -- -D warnings"

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

**Note:** Clippy errors in other agents' code are expected in a multi-agent environment. Only fix errors in files you are actively working on, unless they block compilation.

---

## sbh — This Project

**This is the project you're working on.** `sbh` (Storage Ballast Helper) is a cross-platform disk-pressure defense system for AI coding workloads. It continuously monitors storage pressure, predicts exhaustion, and safely reclaims space using layered controls.

### Three-Pronged Defense

1. **Ballast files** — pre-allocated sacrificial space released under pressure
2. **Artifact scanner** — multi-factor scoring to find and delete stale build artifacts
3. **Special location monitor** — surveillance of /tmp, /data/tmp, and other volatile paths

### Design Principles

1. **Safety before aggressiveness:** hard vetoes always win over reclaim pressure
2. **Predict, then act:** pressure trends and controller outputs drive timing and scope
3. **Deterministic decisions:** identical inputs produce identical ranking and policy outcomes
4. **Explainability is mandatory:** every action has traceable evidence and rationale
5. **Fail conservative:** policy/guard failures force fallback-safe behavior

---

## Architecture

```text
Pressure Inputs
  fs stats + special location probes
        |
        v
EWMA Forecaster --> PID Controller --> Action Planner
        |                                 |
        |                                 v
        |                         Scan Scheduler (VOI-aware)
        |                                 |
        v                                 v
                    Parallel Walker -> Pattern Registry
                                   -> Deterministic Scoring
                                   -> Policy Engine (shadow/canary/enforce)
                                   -> Guardrails (conformal/e-process)
                                   -> Ranked Deletion + Ballast Release
                                                    |
                                                    v
                                  Dual Logging (SQLite + JSONL)
                                  Evidence Ledger + Explain API
```

### Data Flow

1. **Monitor**: `fs_stats` samples disk usage; `ewma` computes rate trends; `predictive` forecasts exhaustion
2. **Controller**: `pid` computes pressure response; `voi_scheduler` allocates scan budget
3. **Scanner**: `walker` traverses directories; `patterns` classifies artifacts; `scoring` ranks candidates
4. **Safety**: `protection` enforces `.sbh-protect` markers and config globs; `deletion` runs pre-flight checks (path exists, not open, writable, no `.git/`)
5. **Execute**: `deletion` applies circuit-breaker-guarded removal; `ballast/release` frees pre-allocated space
6. **Log**: `dual` writes to both SQLite (queryable) and JSONL (append-only, sync-safe)

---

## Module Structure

```
src/
  lib.rs              # Crate root: re-exports all modules
  main.rs             # Binary entry point: CLI parse + dispatch
  cli_app.rs          # Full CLI definition (clap derive) + command handlers

  core/
    config.rs         # TOML config model + env var overrides + defaults
    errors.rs         # SbhError enum with SBH-XXXX error codes

  monitor/
    fs_stats.rs       # Filesystem stats collection (statvfs/platform)
    ewma.rs           # Exponentially weighted moving average rate estimator
    pid.rs            # PID pressure controller
    predictive.rs     # Predictive action pipeline with early warning
    special_locations.rs  # /tmp, /data/tmp, swap monitoring
    voi_scheduler.rs  # Value-of-Information scan budget allocator

  scanner/
    walker.rs         # Parallel directory walker with open-file detection
    patterns.rs       # Artifact pattern registry (build dirs, caches, etc.)
    scoring.rs        # Multi-factor candidacy scoring engine
    deletion.rs       # Circuit-breaker-guarded deletion executor
    protection.rs     # .sbh-protect markers + config glob patterns
    merkle.rs         # Incremental Merkle scan index

  ballast/
    manager.rs        # Ballast pool lifecycle (provision, verify, inventory)
    release.rs        # Pressure-responsive ballast release
    coordinator.rs    # Multi-volume ballast coordination

  daemon/
    loop_main.rs      # Main monitoring loop (poll → decide → act → log)
    signals.rs        # Signal handling (SIGTERM, SIGHUP, SIGUSR1)
    self_monitor.rs   # Daemon health self-checks (RSS, state writes)
    service.rs        # systemd + launchd service management
    notifications.rs  # Multi-channel notification system

  logger/
    dual.rs           # Dual-write logger (SQLite + JSONL)
    sqlite.rs         # SQLite WAL-mode activity logger
    jsonl.rs          # JSONL append-only log writer
    stats.rs          # Stats engine for time-window queries

  cli/
    mod.rs            # Shared installer/update contracts, supply chain verification
    bootstrap.rs      # Bootstrap migration and self-healing
    assets.rs         # Asset manifest download/verify/cache pipeline
    dashboard.rs      # Dashboard launcher and mode selection
    install.rs        # Install orchestration with wizard and service setup
    from_source.rs    # From-source build fallback mode
    uninstall.rs      # Uninstall with safe cleanup modes
    update.rs         # Self-update with rollback, cache, and backup management
    wizard.rs         # Guided first-run install wizard

  platform/
    pal.rs            # Platform Abstraction Layer trait
```

---

## Key Files Reference

| File | Lines | Purpose |
|------|-------|---------|
| `src/cli_app.rs` | ~4800 | CLI definition (clap derive) and all command handlers |
| `src/cli/bootstrap.rs` | ~1660 | Bootstrap migration with 13 migration reason types |
| `src/cli/assets.rs` | ~1240 | Asset manifest pipeline with SHA-256 verification |
| `src/daemon/loop_main.rs` | ~1170 | Main daemon monitoring loop |
| `src/scanner/merkle.rs` | ~1080 | Incremental Merkle scan index with full-scan fallback |
| `src/cli/uninstall.rs` | ~1020 | Uninstall parity with 5 cleanup modes |
| `src/daemon/notifications.rs` | ~1020 | Multi-channel notification system |
| `src/cli/mod.rs` | ~910 | Shared installer/update contracts |
| `src/logger/stats.rs` | ~900 | Stats engine with time-window aggregation |
| `src/daemon/service.rs` | ~890 | systemd + launchd service management |
| `src/monitor/voi_scheduler.rs` | ~880 | VOI scan budget allocator |
| `src/ballast/coordinator.rs` | ~870 | Multi-volume ballast coordination |
| `src/monitor/predictive.rs` | ~780 | Predictive action pipeline |
| `src/cli/wizard.rs` | ~750 | Guided first-run wizard + --auto mode |
| `src/cli/from_source.rs` | ~740 | From-source fallback build mode |
| `src/logger/dual.rs` | ~720 | Dual-write activity logger |
| `src/scanner/protection.rs` | ~710 | Protection registry (markers + globs) |
| `src/scanner/walker.rs` | ~700 | Parallel directory walker |
| `src/scanner/deletion.rs` | ~680 | Deletion executor with circuit breaker |
| `src/ballast/manager.rs` | ~650 | Ballast pool lifecycle management |
| `src/core/config.rs` | ~640 | Config model with nested sections |
| `src/daemon/self_monitor.rs` | ~630 | Daemon health self-monitoring |
| `src/scanner/scoring.rs` | ~600 | Multi-factor scoring engine |
| `src/logger/jsonl.rs` | ~590 | JSONL append-only logger |
| `src/logger/sqlite.rs` | ~540 | SQLite WAL-mode logger |
| `src/scanner/patterns.rs` | ~420 | Artifact pattern registry |
| `src/platform/pal.rs` | ~390 | Platform abstraction trait |

---

## CLI Command Reference

### Core Commands

| Command | Purpose |
|---------|---------|
| `sbh daemon` | Run the monitoring loop and policy engine |
| `sbh status [--watch]` | Real-time health, pressure, and controller state |
| `sbh check [--target-free N] [--need N] [--predict N]` | Pre-flight space check and recommendations |
| `sbh scan [PATHS...] [--top N] [--min-score N]` | Manual candidate discovery and scoring |
| `sbh clean [PATHS...] [--target-free N] [--dry-run] [--yes]` | Manual cleanup with confirmation |
| `sbh emergency [PATHS...] [--target-free N] [--yes]` | Zero-write recovery mode for critically full disks |

### Ballast Commands

| Command | Purpose |
|---------|---------|
| `sbh ballast status` | Show per-volume ballast inventory |
| `sbh ballast provision` | Create/rebuild ballast files idempotently |
| `sbh ballast release <COUNT>` | Release N ballast files on demand |
| `sbh ballast replenish` | Rebuild previously released ballast |
| `sbh ballast verify` | Verify ballast file integrity |

### Observability Commands

| Command | Purpose |
|---------|---------|
| `sbh stats [--window WINDOW] [--top-patterns N] [--top-deletions N]` | Time-window activity statistics |
| `sbh blame [--top N]` | Attribute disk pressure by process/agent |
| `sbh dashboard` | Live TUI dashboard with pressure visualization |
| `sbh explain --id <decision-id>` | Explain policy decision evidence |

### Configuration and Lifecycle

| Command | Purpose |
|---------|---------|
| `sbh config path\|show\|validate\|diff\|reset\|set` | Manage configuration |
| `sbh install [--systemd\|--launchd] [--user] [--from-source] [--wizard\|--auto]` | Install as system service |
| `sbh uninstall [--systemd\|--launchd] [--purge]` | Remove service integration |
| `sbh setup [--all] [--path] [--verify] [--completions SHELLS]` | Post-install PATH/completions setup |
| `sbh tune [--apply] [--yes]` | Show/apply tuning recommendations |
| `sbh protect <PATH>\|--list` | Protect path subtree from cleanup |
| `sbh unprotect <PATH>` | Remove protection marker |
| `sbh version [--verbose]` | Show version and build metadata |
| `sbh completions <SHELL>` | Generate shell completions |

### Global Flags

| Flag | Purpose |
|------|---------|
| `--config <PATH>` | Override config file path |
| `--json` | Force JSON output mode |
| `--no-color` | Disable colored output |
| `-v, --verbose` | Increase verbosity |
| `-q, --quiet` | Quiet mode (errors only) |

---

## Configuration

### Default Paths

| Path | Purpose |
|------|---------|
| `~/.config/sbh/config.toml` | User configuration file |
| `~/.local/share/sbh/state.json` | Runtime state |
| `~/.local/share/sbh/activity.sqlite3` | SQLite activity log |
| `~/.local/share/sbh/activity.jsonl` | JSONL activity log |
| `~/.local/share/sbh/ballast/` | Ballast file pool |

### Config Sections

| Section | Key Settings |
|---------|-------------|
| `[pressure]` | `green_min_free_pct`, `yellow_min_free_pct`, `orange_min_free_pct`, `red_min_free_pct`, `poll_interval_ms` |
| `[pressure.prediction]` | `enabled`, `action_horizon_minutes`, `warning_horizon_minutes`, `min_confidence`, `min_samples` |
| `[scanner]` | `root_paths`, `excluded_paths`, `protected_paths`, `min_file_age_minutes`, `max_depth`, `parallelism`, `dry_run` |
| `[scoring]` | `min_score`, `location_weight`, `name_weight`, `age_weight`, `size_weight`, `structure_weight` |
| `[scoring]` (decision-theoretic) | `false_positive_loss`, `false_negative_loss`, `calibration_floor` |
| `[ballast]` | `file_count`, `file_size_bytes`, `replenish_cooldown_minutes` |
| `[telemetry]` | Structured logging and observability settings |
| `[paths]` | Override default config/data/log paths |
| `[notifications]` | Multi-channel notification settings |

---

## Error Codes

SBH uses structured error codes in the format `SBH-XXXX`:

| Range | Category | Description |
|-------|----------|-------------|
| SBH-1xxx | Configuration | Config loading, parsing, and validation errors |
| SBH-2xxx | Runtime/IO | Filesystem, serialization, SQL, and safety errors |
| SBH-3xxx | System | Permission, IO, channel, and runtime errors |

### Common Error Codes

| Code | Error | Typical Cause |
|------|-------|---------------|
| `SBH-1001` | Invalid config | Bad config values or structure |
| `SBH-1002` | Missing config | Config file not found at expected path |
| `SBH-1003` | Config parse failure | Invalid TOML syntax |
| `SBH-1101` | Unsupported platform | Feature unavailable on current OS |
| `SBH-2001` | Filesystem stats failure | Cannot stat a watched path |
| `SBH-2003` | Safety veto | Hard veto prevented deletion |
| `SBH-2102` | SQL failure | SQLite query or schema error |
| `SBH-3001` | Permission denied | Insufficient filesystem permissions |
| `SBH-3002` | IO failure | File read/write error |

All errors implement `code()` for stable machine-parseable codes and `is_retryable()` to indicate whether retry might help.

---

## Scoring Engine

The artifact scoring system uses five weighted factors to rank deletion candidates:

| Factor | Default Weight | What It Measures |
|--------|---------------|-----------------|
| `location` | 0.25 | How "safe" the directory is (temp > build > source) |
| `name` | 0.25 | Pattern match against known artifact names (`.o`, `node_modules`, `target/`) |
| `age` | 0.20 | Time since last access/modification |
| `size` | 0.15 | Bytes reclaimable (larger = higher score) |
| `structure` | 0.15 | Directory structure signals (depth, sibling count) |

**Decision-theoretic tuning:** `false_positive_loss` and `false_negative_loss` control the cost asymmetry between wrongly deleting (expensive) vs. missing a candidate (less costly). `calibration_floor` sets the minimum acceptable calibration level for adaptive actions.

---

## Pressure Levels

| Level | Default Threshold | Daemon Response |
|-------|------------------|-----------------|
| Green | > 35% free | Normal monitoring, no action |
| Yellow | 20-35% free | Increase scan frequency |
| Orange | 10-20% free | Begin ballast release + cleanup |
| Red | < 5% free | Emergency mode: aggressive cleanup |

The PID controller smooths transitions between levels. EWMA rate estimation predicts when the next level will be reached.

---

## Ballast System

Ballast files are pre-allocated sacrificial space that can be instantly released when disk pressure spikes:

- **Provision:** Creates random-data files in `<data_dir>/ballast/` per configured volume
- **Release:** Removes ballast files to free space immediately (no scanning needed)
- **Replenish:** Rebuilds released ballast files when pressure returns to green
- **Verify:** Checks integrity of existing ballast files
- **Per-volume overrides:** Different file count/size per mount point

---

## Dual Logging System

Every significant event is logged to both backends:

| Backend | Format | Purpose |
|---------|--------|---------|
| **SQLite** (WAL mode) | Structured rows | Queryable stats, time-window aggregation, blame attribution |
| **JSONL** (append-only) | One JSON object per line | Portable, grep-friendly, safe during crashes |

The `DualLogger` writes to both backends and degrades gracefully if one fails. The `StatsEngine` queries SQLite for `sbh stats` reports.

---

## Protection System

Two protection modes prevent accidental cleanup of important files:

1. **Marker files:** Place `.sbh-protect` in any directory to protect it and all children
2. **Config patterns:** Shell-style globs in `scanner.protected_paths` (e.g., `/data/projects/production-*`)

Additional hard safety vetoes in the deletion executor:
- Path must still exist at deletion time
- Path must not be currently open by any process (Linux: `/proc/*/fd` check)
- Parent directory must be writable
- Directory must not contain `.git/` (final safety net)
- Circuit breaker: 3 consecutive failures trigger 30s cooldown

---

## Testing

### Unit Tests

Each module contains inline `#[cfg(test)]` tests. Tests for binary-crate code (in `cli_app.rs`) require the `--bin sbh` flag:

```bash
# Run all library tests
rch exec "cargo test --lib"

# Run specific module tests
rch exec "cargo test --lib scoring"
rch exec "cargo test --lib bootstrap"
rch exec "cargo test --lib assets"

# Run binary crate tests (cli_app.rs)
rch exec "cargo test --bin sbh"

# Run a specific binary test
rch exec "cargo test --bin sbh -- setup_command_parses_with_flags"
```

### Integration Tests

Located in `tests/integration_tests.rs` with shared helpers in `tests/common/mod.rs`:

```bash
rch exec "cargo test --test integration_tests"
```

The test harness:
- Resolves the `sbh` binary path via `CARGO_BIN_EXE_sbh` or fallback search
- Logs each test case output to timestamped files for debugging
- Verifies CLI scaffolding and subcommand handlers

### End-to-End Testing

```bash
./scripts/e2e_test.sh
```

The E2E script runs real CLI invocations with per-case logging.

### Test Conventions

- **Table-driven tests:** Use arrays of test cases with descriptive names
- **Temporary directories:** Use `tempfile::TempDir` for filesystem tests — paths auto-clean on drop
- **Backup-first:** Tests that mutate files should verify backup creation
- **Idempotency:** Tests should verify that re-running an operation produces the same result

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## Output Style

sbh supports two output modes:

- **Human-readable to stderr/stdout:** Colorful terminal output with tables and status indicators
- **JSON to stdout:** Machine-parseable output when `--json` is passed

Colors are automatically disabled when stdout is not a TTY.

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
  Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | fix suggestion | Exit 0/1 -> pass/fail

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

<!-- bv-agent-instructions-v1 -->

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push origin main main:master  # Push to both branches
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds via `rch`
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   br sync --flush-only    # Export beads to JSONL (no git ops)
   git add .beads/         # Stage beads changes
   git add <other files>   # Stage code changes
   git commit -m "..."     # Commit everything
   git push origin main main:master  # Push to BOTH branches
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds


---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/cli/commands/upgrade.rs, src/storage/sqlite.rs, tests/conformance.rs, tests/storage_deps.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
2. Triage beads_rust-orko (clippy/cargo warnings) and beads_rust-ydqr (rustfmt failures).
3. If you want a full suite run later, fix conformance/clippy blockers and re-run cargo test --all.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.
