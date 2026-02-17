# Architecture

## System Overview

```
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
                                   -> Policy Engine (observe/canary/enforce)
                                   -> Guardrails (conformal/e-process)
                                   -> Ranked Deletion + Ballast Release
                                                    |
                                                    v
                                  Dual Logging (SQLite + JSONL)
                                  Evidence Ledger + Explain API
```

## Daemon Thread Architecture

Four concurrent threads with bounded crossbeam channels:

| Thread | Channel Cap | Purpose |
|--------|-------------|---------|
| Monitor | — | Polls fs stats, EWMA, PID controller. Issues ScanRequest |
| Scanner | 2 | Parallel directory walk, scoring, produces DeletionBatch |
| Executor | 64 | Pre-flight checks, circuit breaker, executes deletions |
| Logger | 1024 | SQLite + JSONL dual writes, degradation chain |

**Thread panic recovery:** Up to 3 respawns within 5-minute window per thread.

## Module Map

```
src/
  lib.rs              # Crate root
  main.rs             # Binary entry point
  cli_app.rs          # CLI definition + handlers (~4800 lines)

  core/
    config.rs         # TOML config + env overrides + validation
    errors.rs         # SBH-XXXX error codes

  monitor/
    fs_stats.rs       # statvfs filesystem sampling
    ewma.rs           # Adaptive EWMA with quadratic prediction
    pid.rs            # PID controller with predictive urgency boost
    predictive.rs     # Early warning pipeline
    guardrails.rs     # e-process drift detection + calibration
    special_locations.rs  # /tmp, /dev/shm, swap monitoring
    voi_scheduler.rs  # Value-of-Information scan budget

  scanner/
    walker.rs         # Parallel directory walker + open-file detection
    patterns.rs       # ~200 artifact patterns
    scoring.rs        # 5-factor scoring + Bayesian framework
    deletion.rs       # Circuit-breaker executor
    protection.rs     # .sbh-protect + glob patterns
    merkle.rs         # Incremental Merkle scan index

  ballast/
    manager.rs        # Provision/verify/inventory
    release.rs        # Pressure-responsive release
    coordinator.rs    # Multi-volume coordination

  daemon/
    loop_main.rs      # Main loop (4 threads)
    policy.rs         # Progressive delivery: observe/canary/enforce
    signals.rs        # SIGTERM, SIGHUP reload, SIGUSR1 scan
    self_monitor.rs   # Health self-checks (RSS, state writes)
    service.rs        # systemd + launchd integration
    notifications.rs  # Multi-channel notifications

  logger/
    dual.rs           # Dual-write with degradation chain
    sqlite.rs         # WAL-mode SQLite logger
    jsonl.rs          # Append-only JSONL with rotation
    stats.rs          # Time-window aggregation + blame

  tui/                # 7-screen dashboard
    model.rs, update.rs, render.rs, input.rs, ...

  cli/                # Installation + lifecycle
    bootstrap.rs, wizard.rs, integrations.rs, ...

  platform/
    pal.rs            # Platform abstraction (Linux procfs/statvfs)
```

## Safety Layers (6 Deep)

1. **Protection Registry** — `.sbh-protect` markers + config globs
2. **Pre-Flight Checks** — Exists, not open, parent writable, no `.git/`
3. **Circuit Breaker** — 3 consecutive failures -> 30s halt
4. **Policy Engine** — observe/canary/enforce with automatic fallback
5. **Guardrails** — Continuous calibration + e-process drift detection
6. **Repeat-Deletion Dampening** — Exponential backoff prevents loops

## Scoring Engine

Five factors, all weights must sum to 1.0:

| Factor | Weight | Signal |
|--------|--------|--------|
| Location | 0.25 | Directory type (temp=high, source=low) |
| Name | 0.25 | Match against ~200 artifact patterns |
| Age | 0.20 | Non-monotonic curve (peaks 4-10 hours) |
| Size | 0.15 | Bytes with diminishing returns |
| Structure | 0.15 | Marker files, build dir indicators |

**Decision layer:** Bayesian expected-loss balances false positive cost (50x) vs false negative cost (30x).

## Ballast Release Controller

| Urgency | Files Released |
|---------|---------------|
| 0.0-0.3 | 0 (none) |
| 0.3-0.6 | 1 file |
| 0.6-0.9 | 3 files |
| 0.9-1.0 | ALL files (emergency) |

Replenishment: Wait for Green pressure + cooldown (30 min), then rebuild 1 file every 5 min.

## Dual Logging

| Backend | Format | Use Case |
|---------|--------|----------|
| SQLite (WAL) | Structured rows | `sbh stats`, `sbh blame`, time-window queries |
| JSONL | One JSON per line | Crash-safe, grep-friendly, portable |

**Degradation chain:** SQLite fails (50x) -> JSONL only -> /dev/shm fallback -> stderr -> silent discard.

## Prediction System

- **EWMA Forecaster:** Adaptive alpha with quadratic acceleration detection
- **Action Horizon:** 30 min default (triggers pre-emptive scan)
- **Warning Horizon:** 60 min default (early notification)
- **Imminent Danger:** 5 min (maximum urgency)
- **Critical Danger:** 2 min (emergency escalation)

## Signal Handling

| Signal | Action |
|--------|--------|
| SIGTERM | Graceful shutdown (flush logs, release locks) |
| SIGHUP | Reload configuration without restart |
| SIGUSR1 | Force immediate scan cycle |

## Special Location Monitoring

| Location | Free Buffer | Poll Interval | Priority |
|----------|-------------|---------------|----------|
| `/dev/shm` | 20% | 3s | 255 |
| ramfs mounts | 18% | 4s | 220 |
| tmpfs mounts | 15% | 5s | 200 |
| `/tmp`, `/data/tmp` | 15% | 5s | — |

## Swap Thrash Detection

When swap > 70% AND available RAM > 8 GiB: flag as swap-thrash risk with 15-minute warning cooldown.
