# storage_ballast_helper (`sbh`)

<div align="center">
  <img src="sbh_illustration.webp" alt="sbh - Storage Ballast Helper illustration">
</div>

Cross-platform disk-pressure defense for AI coding workloads: predictive monitoring, safe cleanup, ballast release, and explainable policy decisions.

## TL;DR

**The problem:** agent swarms and build systems can fill disks faster than humans can react, causing failed builds, stuck daemons, and crashed workflows.

**The solution:** `sbh` continuously monitors storage pressure, predicts exhaustion, and safely reclaims space using layered controls: ballast pools, deterministic artifact scoring, hard safety vetoes, and conservative fallback modes.

### Why Use `sbh`?

| Capability | What it gives you |
| --- | --- |
| Predictive pressure control | EWMA + PID reacts before disks hit critical levels |
| Multi-volume ballast pools | Frees space on the exact filesystem under pressure |
| Safe artifact cleanup | Deterministic scoring + hard vetoes (`.git`, protected paths, too-recent files, open files) |
| Zero-write emergency mode | Recover from near-100% full disks without needing DB/config writes |
| Project protection | `.sbh-protect` markers and config globs prevent accidental cleanup in critical repos |
| Explainable decisions | Evidence ledger + `sbh explain` shows why each action happened |
| Strong observability | `status`, `dashboard`, `stats`, `blame`, structured logs, and decision traces |
| Production rollout safety | Shadow -> canary -> enforce modes with automatic fallback and guardrails |

## Quick Example

```bash
# 1) Install and bootstrap service
sbh install --systemd

# 2) Provision per-volume ballast pools
sbh ballast provision

# 3) Protect critical projects from cleanup
sbh protect /data/projects/critical-app

# 4) Inspect pressure and forecast
sbh check --target-free 15
sbh status --json

# 5) Run cleanup scan and review candidates
sbh scan /data/projects --top 20 --min-score 0.70

# 6) Execute safe cleanup with confirmation
sbh clean --target-free 20

# 7) Investigate decisions and trends
sbh explain --id <decision-id>
sbh stats --window 24h
sbh blame --json

# 8) Emergency recovery (zero-write mode)
sbh emergency /data --target-free 10 --yes
```

## Design Principles

1. **Safety before aggressiveness:** hard vetoes always win over reclaim pressure.
2. **Predict, then act:** pressure trends and controller outputs drive timing and scope.
3. **Deterministic decisions:** identical inputs produce identical ranking and policy outcomes.
4. **Explainability is mandatory:** every action has traceable evidence and rationale.
5. **Fail conservative:** policy/guard failures force fallback-safe behavior.

## The Problem in Depth

AI coding agents (Claude Code, Codex, Gemini CLI, etc.) spawn parallel build processes, download dependencies, generate intermediate artifacts, and write logs continuously. A single agent can produce gigabytes of build artifacts per hour. Run a dozen agents across multiple projects on the same machine, and disk consumption becomes unpredictable and bursty in ways that traditional monitoring tools were never designed for.

The failure mode is severe: when a disk hits 100%, everything breaks simultaneously. Builds fail mid-compilation, SQLite databases corrupt, daemon state files can't be written, and even basic shell operations stop working. Recovery from a completely full disk is painful because most cleanup tools themselves need to write temporary files.

Existing solutions fall short in specific ways:

- **Cron + rm scripts** are fragile, have no pressure awareness, and can't distinguish a 2-hour-old build artifact from a 2-hour-old source file. They run on fixed schedules regardless of whether the disk is at 10% or 99%.
- **Generic temp cleaners** (tmpreaper, systemd-tmpfiles) only handle `/tmp` and similar well-known paths. They don't understand build artifact structures, can't score candidates by reclaimability, and have no concept of project protection.
- **Filesystem quotas** prevent individual users from consuming too much space but don't help when the problem is aggregate consumption across legitimate workloads on the same volume.
- **Manual cleanup** doesn't scale and can't react faster than a human can type `du -sh` and decide what to delete.

`sbh` targets this environment directly: multiple concurrent agents, bursty disk consumption, safety-critical deletion decisions, and the need to react in seconds rather than minutes.

## How `sbh` Compares

| Capability | `sbh` | Cron + `rm` scripts | Generic temp cleaners | Manual cleanup |
| --- | --- | --- | --- | --- |
| Predictive pressure response | ✅ EWMA + PID | ❌ | ❌ | ❌ |
| Multi-volume awareness | ✅ | ⚠️ usually custom | ⚠️ partial | ⚠️ manual |
| Hard safety vetoes | ✅ built-in | ⚠️ fragile scripts | ⚠️ limited | ✅ human judgment |
| Explainability and traces | ✅ | ❌ | ❌ | ❌ |
| Emergency zero-write recovery | ✅ | ❌ | ❌ | ⚠️ slow |
| Service-grade observability | ✅ | ❌ | ⚠️ minimal | ❌ |

### Real-World Operator Perspective

This table comes from an operator who had been managing disk pressure across a fleet of AI coding VMs using hand-rolled cron scripts:

| Problem | Cron script | `sbh` |
| --- | --- | --- |
| Agents use unpredictable target dir names (`rch*`, `pi_agent_rust_*`, etc.) | Script misses them | Multi-factor scoring finds ANY stale build artifact by structure, not name |
| Disk fills in < 10 min between cron runs | Machine is stuck until next run | Continuous monitoring (1s polls), predicts exhaustion 30 min ahead |
| Cleaning active build dirs breaks agents | Age-based heuristic (fragile) | Checks for open file handles; hard veto on in-use dirs |
| `/dev/shm` keeps getting filled | Emergency kill at 90% | Continuous special location monitoring with configurable free buffer target |
| No audit trail | `fleet-maintenance.log` with one-liners | Full evidence ledger; `sbh explain` shows exactly why something was/wasn't deleted |
| Disk hits 100% before anything reacts | Dead until next cron | Ballast files: pre-allocated sacrificial space, released instantly under pressure |

Ballast files address the worst case: a completely full disk where nothing works. Pre-allocate 10+ GiB of sacrificial space per volume; when pressure spikes, release it instantly to buy time while the scanner identifies and removes actual artifacts.

## Installation

### Option 0: Unix One-Liner Installer

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash
```

Pin a specific version:

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash -s -- --version v0.1.0
```

### Option 1: From Git (Cargo)

```bash
cargo install --git https://github.com/Dicklesworthstone/storage_ballast_helper --bin sbh
```

### Option 2: From Source

```bash
git clone https://github.com/Dicklesworthstone/storage_ballast_helper.git
cd storage_ballast_helper
cargo build --release
./target/release/sbh --help
```

### Option 3: GitHub Release Artifact

```bash
gh release download --repo Dicklesworthstone/storage_ballast_helper --pattern "sbh-*.tar.xz"
```

## Quick Start

1. Check your config path:
```bash
sbh config path
```
2. Validate config:
```bash
sbh config validate
```
3. Install service:
```bash
sbh install --systemd        # Linux
sbh install --launchd        # macOS
```
4. Start monitoring:
```bash
sbh daemon
```
5. Open live dashboard:
```bash
sbh dashboard
```

## Command Reference

### Core

| Command | Purpose |
| --- | --- |
| `sbh daemon` | Run monitoring loop and policy engine |
| `sbh status` | Real-time health, pressure, and controller state |
| `sbh check` | Pre-flight space check and recommendations |
| `sbh scan` | Manual candidate discovery and scoring report |
| `sbh clean` | Manual cleanup with confirmation/dry-run |
| `sbh emergency` | Zero-write recovery mode on critically full disks |

### Ballast and Protection

| Command | Purpose |
| --- | --- |
| `sbh ballast status` | Show per-volume ballast inventory |
| `sbh ballast provision` | Create ballast pools/files idempotently |
| `sbh ballast release N` | Release ballast files on demand |
| `sbh ballast replenish` | Rebuild released ballast |
| `sbh ballast verify` | Verify ballast integrity |
| `sbh protect <path>` | Add `.sbh-protect` marker |
| `sbh protect --list` | List all protected paths |
| `sbh unprotect <path>` | Remove protection marker |

### Observability and Explainability

| Command | Purpose |
| --- | --- |
| `sbh stats` | Time-window activity/deletion statistics |
| `sbh blame` | Attribute artifact pressure by process/agent |
| `sbh dashboard` | Real-time TUI dashboard |
| `sbh explain --id <decision-id>` | Explain policy decision evidence |

### Configuration and Lifecycle

| Command | Purpose |
| --- | --- |
| `sbh config show|set|validate|diff|reset` | Manage effective config |
| `sbh update [--check] [--refresh-cache] [--offline PATH]` | Check/apply updates with cache control and optional offline manifest |
| `sbh install` / `sbh uninstall` | Install/remove service integration |

## Operator Docs

- Installer/update parity contract and security policy: `docs/installer-dx-parity-matrix.md`
- Dashboard/status baseline contract (pre-overhaul): `docs/dashboard-status-contract-baseline.md`
- Testing + log registration guide: `docs/testing-and-logging.md`

For installer/update changes, use the parity matrix as the source of truth for
flag semantics, integrity policy, rollback expectations, and release-gate tests.

## Update Cache and Notice Controls

`sbh update` supports local metadata caching and explicit refresh controls:

- `update.metadata_cache_ttl_seconds`: cache TTL for update metadata.
- `update.metadata_cache_file`: on-disk cache path (default in `~/.local/share/sbh/`).
- `update.notices_enabled`: enable/disable human follow-up prompts in update output.
- `sbh update --refresh-cache`: bypass cached metadata and fetch fresh release metadata.

Environment overrides are available for operator automation:

- `SBH_UPDATE_METADATA_CACHE_TTL_SECONDS`
- `SBH_UPDATE_METADATA_CACHE_FILE`
- `SBH_UPDATE_NOTICES_ENABLED`
- `SBH_UPDATE_ENABLED`
- `SBH_UPDATE_BACKGROUND_REFRESH`
- `SBH_UPDATE_OPT_OUT`

Useful operator checks:

```bash
# Inspect effective update policy/config
sbh config show --json | jq '.update'

# Force fresh metadata fetch for diagnostics
sbh update --check --refresh-cache --json
```

## Configuration Example

```toml
[scanner]
watched_paths = ["/data/projects", "/tmp", "/dev/shm"]
cross_device = false

[scanner.protected_paths]
paths = ["/data/projects/production-*", "/home/*/critical-builds"]

[monitor]
sample_interval_seconds = 2
pressure_green_pct = 35
pressure_yellow_pct = 20
pressure_orange_pct = 10
pressure_red_pct = 5

[ballast]
auto_provision = true
per_volume_file_count = 5
per_volume_file_size_mb = 1024

[ballast.overrides."/data"]
file_count = 10
file_size_mb = 2048

[ballast.overrides."/tmp"]
enabled = false

[scoring.weights]
location = 0.25
name = 0.25
age = 0.20
size = 0.15
structure = 0.15

[policy]
mode = "observe" # observe | canary | enforce
canary_delete_cap_per_hour = 5
fallback_safe = true

[guardrails]
calibration_floor = 0.75
consecutive_clean_windows_for_recovery = 5

[logging]
sqlite_path = "/var/lib/sbh/activity.db"
jsonl_path = "/var/log/sbh/activity.jsonl"
```

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

## How It Works

What follows covers the algorithms, control theory, safety mechanisms, and design rationale behind each component.

### The Daemon Loop

The daemon runs four threads connected by bounded channels:

1. **Monitor thread** polls filesystem stats at a configurable interval, feeds them to the EWMA forecaster and PID controller, and emits a `ScanRequest` when pressure warrants action.
2. **Scanner thread** receives scan requests, walks directories in parallel, scores every discovered artifact, and produces a ranked `DeletionBatch`.
3. **Executor thread** receives deletion batches and executes them through the circuit breaker and pre-flight safety checks.
4. **Logger thread** receives activity events and writes them to both SQLite and JSONL backends.

Channels use bounded capacities (scanner: 2, executor: 64, logger: 1024) to provide natural backpressure. If the scanner can't keep up with pressure changes, the newest request wins and older ones are dropped. If the logger falls behind, a dropped-event counter is incremented and reported periodically rather than blocking the monitor loop.

Each worker thread has panic recovery: up to 3 respawns within a 5-minute window before the daemon shuts down. Thread health is tracked by the self-monitor, which also watches RSS memory usage and state-file write success.

### The Control Loop: EWMA Forecasting + PID Controller

The pressure response system has two parts: an EWMA forecaster that predicts *when* the disk will run out, and a PID controller that determines *how aggressively* to respond.

#### EWMA Rate Estimation

The EWMA (Exponentially Weighted Moving Average) estimator tracks the rate of free-space change in bytes per second, with an adaptive smoothing factor that responds to burstiness:

```
burstiness = |instantaneous_rate - ewma_rate| / (|ewma_rate| + 1.0)
alpha = 0.20 * burstiness + base_alpha
alpha = clamp(alpha, 0.1, 0.8)
```

When disk consumption is steady, `burstiness` is low and alpha stays near the base value (0.3), producing smooth estimates. When a burst hits (e.g., a large `cargo build` starts), burstiness spikes, alpha increases, and the estimator tracks the new rate within a few samples rather than lagging behind.

The estimator also tracks acceleration (rate of rate change) using the same EWMA formula, enabling quadratic time-to-exhaustion predictions:

```
time_to_exhaustion = solve(distance = rate * t + 0.5 * accel * t^2)
```

For non-zero acceleration, the quadratic is solved using the numerically stable conjugate form to avoid catastrophic cancellation when the discriminant is close to `rate^2`.

A confidence metric combines sample count adequacy (70% weight) with residual tracking (30% weight). When confidence drops below 0.2 or fewer than 3 samples exist, the estimator enters fallback mode and reports uncertainty rather than potentially misleading predictions.

Trend classification uses fixed thresholds: recovering (rate < -1.0 bytes/sec), accelerating (accel > 64.0 bytes/sec^2), decelerating (accel < -64.0 bytes/sec^2), or stable.

#### PID Pressure Controller

The PID controller converts the gap between target free space and actual free space into an urgency signal (0.0 to 1.0) that drives scan frequency, deletion batch sizes, and ballast release counts.

Default gains: **Kp=0.25**, **Ki=0.08**, **Kd=0.02**, with an integral cap of 100.0 to prevent windup. The target setpoint defaults to 18.0% free space.

```
error = target_free_pct - current_free_pct
integral = clamp(integral + error * dt, -100.0, 100.0)
derivative = (error - last_error) / dt
raw = Kp * error + Ki * integral + Kd * derivative
urgency = 1 - exp(-max(0, raw))
```

The `1 - exp(-x)` transform maps the raw PID output to a 0-1 range with a natural saturation curve: small errors produce proportionally small urgency, while large errors quickly approach 1.0 without overshooting.

Pressure levels are defined by free-space thresholds:

| Level | Default Free % | Scan Interval | Ballast Release | Max Delete Batch |
| --- | --- | --- | --- | --- |
| Green | > 20% | base interval | 0 files | 2 |
| Yellow | 14-20% | base/2 | 0-1 files | 5 |
| Orange | 10-14% | base/4 | 1-3 files | 10 |
| Red | 6-10% | base/8 | 3-5 files | 20 |
| Critical | < 3% | 100ms | 10 files | 40 |

Critical is triggered when free space drops below half the Red threshold (`red_min / 2.0`). At Critical, the controller issues maximum-urgency responses regardless of PID output.

When predictive forecasting is enabled, time-to-exhaustion estimates boost urgency preemptively. If the forecast predicts Red-level pressure within the action horizon (default 30 minutes), urgency is raised to at least 0.70 even if current pressure is only Yellow. This lets the system start scanning and releasing ballast *before* pressure actually reaches dangerous levels.

### Artifact Scoring: Decision-Theoretic Ranking

Every file and directory discovered during a scan receives a composite score from five weighted factors, then passes through a Bayesian decision-theoretic framework that explicitly models the costs of wrong decisions.

#### The Five Scoring Factors

**Location** (default weight 0.25) rates directories by how likely they are to contain safely deletable artifacts:

| Path pattern | Score |
| --- | --- |
| `/tmp`, `/var/tmp`, `/dev/shm` | 0.95 |
| `*/.tmp_*` patterns | 0.90 |
| `*/.target` (hidden build dirs) | 0.85 |
| `*/target` (Rust/Java build dirs) | 0.80 |
| `*/.cache/*` | 0.60 |
| Generic `*/projects/*` | 0.40 |
| Default unknown | 0.30 |
| `*/documents/*` | 0.10 |
| System paths (`/`, `/bin`, `/lib`) | 0.00 |

**Name** (default weight 0.25) matches against a pattern registry of known artifact types: `.o` files, `node_modules`, `__pycache__`, `.class` files, `.wasm` intermediates, and hundreds of others. Each pattern carries a confidence score.

**Age** (default weight 0.20) uses time since last access/modification, with a non-monotonic curve that peaks at 4-10 hours (the sweet spot for stale build artifacts) and drops for very old files (which might be intentionally archived):

| Age | Score | Rationale |
| --- | --- | --- |
| < 30 min | 0.00 | Likely in active use |
| 30 min - 2 hours | 0.20 | Possibly still needed |
| 2 - 4 hours | 0.70 | Probably stale |
| 4 - 10 hours | 1.00 | Peak staleness for build artifacts |
| 10 - 24 hours | 0.85 | Likely stale |
| 1 - 7 days | 0.60 | Old but possibly intentional |
| 7 - 30 days | 0.40 | Probably forgotten |
| > 30 days | 0.25 | Ancient, but might be archived intentionally |

**Size** (default weight 0.15) favors larger artifacts (more space reclaimed per deletion) with diminishing returns at extremes:

| Size | Score |
| --- | --- |
| < 1 MiB | 0.05 |
| 1 - 10 MiB | 0.20 |
| 10 - 100 MiB | 0.40 |
| 100 MiB - 1 GiB | 0.70 |
| 1 - 10 GiB | 1.00 |
| 10 - 50 GiB | 0.90 |
| > 50 GiB | 0.75 |

**Structure** (default weight 0.15) examines directory contents for signals: presence of `.git/` (score 0.0, never delete), Cargo fingerprint/incremental directories (0.95), `deps` + `build` directories together (0.85), or mostly object files (0.90).

#### Pressure Multiplier

The composite score is scaled by current urgency to make the system more aggressive under pressure:

```
urgency <= 0.3:  multiplier = 1.0 + urgency          (range: 1.0 - 1.3)
urgency <= 0.5:  multiplier = 1.3 + (urgency - 0.3)  (range: 1.3 - 1.5)
urgency <= 0.8:  multiplier = 1.5 + (urgency - 0.5) * 1.67  (range: 1.5 - 2.0)
urgency > 0.8:   multiplier = 2.0 + (urgency - 0.8) * 5.0   (range: 2.0 - 3.0)
```

At Green-level pressure (urgency ~0.1), scores are barely inflated. At Critical (urgency ~1.0), scores are tripled, causing marginal candidates to cross the deletion threshold.

#### Bayesian Decision Framework

The scoring engine does not use the composite score directly as a delete/keep threshold. Instead, it models the decision as a Bayesian expected-loss problem.

First, the composite score is converted to a posterior probability that the artifact is abandoned (no longer needed by any running process):

```
scaled = min(total_score / 3.0, 1.0)
logit = 3.5 * (scaled - 0.5) + 2.0 * (confidence - 0.5)
posterior_abandoned = sigmoid(logit)
```

Then the expected loss of each action is computed:

- **Loss of keeping an abandoned artifact**: `posterior * false_negative_loss` (default: 30.0)
- **Loss of deleting a useful artifact**: `(1 - posterior) * false_positive_loss` (default: 100.0)

The asymmetric defaults (100 vs. 30) encode the design principle that wrongly deleting something useful is roughly 3x worse than failing to clean up something stale.

These base losses are then adjusted by epistemic uncertainty, which combines entropy of the posterior with calibration confidence:

```
entropy = -(p * ln(p) + (1-p) * ln(1-p)) / ln(2)
uncertainty = 0.65 * entropy + 0.35 * (1 - calibration)
```

High uncertainty inflates the deletion loss more than the keep loss, making the system conservative when it isn't confident. The final decision follows a threshold policy: delete only when the keep-loss significantly exceeds the delete-loss *and* the posterior exceeds a minimum threshold that scales with uncertainty.

When uncertainty is too high to decide, the artifact is placed in a **Review** category rather than being silently kept or deleted. Review items are surfaced in `sbh scan` output and dashboard displays.

### Progressive Delivery: The Policy Engine

The policy engine controls whether scored deletion decisions are actually executed, using a progressive delivery model borrowed from feature-flag rollout practice.

#### Four Modes

| Mode | Deletions Executed | Purpose |
| --- | --- | --- |
| **Observe** | No (shadow only) | Validate scoring and decisions without risk. Up to 25 hypothetical decisions logged per cycle. |
| **Canary** | Yes, capped at 10/hour | Limited real deletions to detect scoring errors before full rollout. |
| **Enforce** | Yes, normal pipeline | Full production mode. All scored deletions above threshold are executed. |
| **FallbackSafe** | No (emergency only) | Automatic safety mode when guardrails detect problems. Only ballast release allowed. |

#### Promotion and Demotion

Promotion between modes (`observe -> canary -> enforce`) is explicit. The system never auto-promotes; an operator or automation must call `promote()` after validating that the current mode is performing correctly.

Demotion to FallbackSafe is automatic and triggered by any of:

- **Calibration breach**: 3 consecutive observation windows where the guardrail status is Fail (prediction accuracy has degraded).
- **Guardrail drift**: The e-process alarm fires, indicating systematic miscalibration.
- **Canary budget exhaustion**: More than 10 deletions in a single hour while in Canary mode.
- **Serialization failure**: The daemon can't write its state file (possible disk-full condition).
- **Kill switch**: An environment variable or config flag forces immediate fallback.

#### Recovery with Mandatory Canary Gate

Recovery from FallbackSafe requires the guardrails to report 3 consecutive clean observation windows (configurable via `recovery_clean_windows`). When recovery occurs, the system does *not* return directly to its pre-fallback mode if that mode was Enforce. Instead, it recovers to Canary, requiring an explicit re-promotion to Enforce. This mandatory canary gate ensures the system re-proves itself under limited-deletion conditions before resuming full enforcement.

#### Guard Penalty

When guardrails report a non-Pass status, a penalty (default 50.0) is added to the expected-loss-of-deletion for high-impact candidates. This raises the bar for deletion decisions during periods of reduced confidence without completely halting cleanup.

### Safety Layers

`sbh` uses layered safety: five independent mechanisms, any one of which can veto a deletion regardless of what the others decide.

#### Layer 1: Protection Registry

Two protection mechanisms prevent cleanup of important directories:

- **Marker files**: Place a `.sbh-protect` file in any directory. That directory and all descendants are permanently excluded from scanning and deletion. No configuration needed.
- **Config globs**: Shell-style patterns in `scanner.protected_paths` (e.g., `/data/projects/production-*`). Evaluated at scan time against every candidate path.

#### Layer 2: Pre-Flight Safety Checks

Before any deletion is executed, a five-point pre-flight check must pass:

1. **Path still exists**: Uses `symlink_metadata()` (doesn't follow symlinks) to verify the target hasn't been removed by another process since scoring.
2. **Not a symlink**: Symlinks are rejected because `remove_dir_all` follows symlinks into the target, which could destroy data outside watched directories.
3. **Parent is writable**: Checks effective write permission via `access(W_OK)` to catch read-only mounts and permission changes since scan time.
4. **No `.git/` directory**: A final safety net that prevents deletion of any directory containing a Git repository, even if all other signals suggest it's an artifact.
5. **Not open by any process**: On Linux, scans `/proc/*/fd` symlinks to check if any file within the target directory tree is currently held open. Collects up to 20,000 inodes via depth-first traversal and checks each against the process file descriptor table.

Any single check failure causes the candidate to be skipped (not failed), so it doesn't trip the circuit breaker.

#### Layer 3: Circuit Breaker

The deletion executor tracks consecutive failures. After 3 consecutive deletion errors (not skips), the circuit breaker trips and halts the entire batch. The daemon waits 30 seconds before retrying. This prevents cascading failures when the filesystem is in a degraded state (e.g., hardware errors, NFS timeouts).

#### Layer 4: Policy Engine Gates

As described above, the progressive delivery system (observe/canary/enforce) ensures deletions are validated at each stage before reaching full production. The canary mode caps deletions at 10 per hour, limiting blast radius during initial rollout.

#### Layer 5: Guardrails and Drift Detection

The guardrail system continuously validates that the forecasting and scoring pipeline is well-calibrated. If predictions drift from reality, the system automatically falls back to safe mode. See the Guardrails section below for details.

### The Ballast System in Depth

Ballast files are pre-allocated sacrificial space that can be released instantly when disk pressure spikes, buying time for the scanner to find and delete actual artifacts.

#### Provisioning

Each watched volume gets its own ballast pool. Files are named `SBH_BALLAST_FILE_00001.dat` through `SBH_BALLAST_FILE_NNNNN.dat`, with a 4096-byte JSON header containing the magic string `SBH_BALLAST_v1`, file index, creation timestamp, and size metadata.

The data payload is written differently depending on the filesystem:

- **ext4/xfs**: Uses `fallocate()` for near-instant allocation without writing actual data.
- **btrfs/zfs**: Writes 4 MiB chunks of random data to defeat copy-on-write deduplication, which would otherwise make the ballast files share physical blocks and release nothing when deleted.

All writes are fsynced every 64 MiB to ensure durability. Provisioning aborts if free space drops below 20% to avoid filling the disk while trying to reserve space against future fills.

Per-volume configuration overrides allow different file counts and sizes for different mount points. A 2 TiB data volume might use 10 x 2 GiB ballast files (20 GiB total), while a 100 GiB root volume uses 5 x 512 MiB files (2.5 GiB).

#### Release Strategy

The PID controller's pressure response directly determines how many ballast files to release:

- **Low urgency** (< 0.3): No ballast release. The scanner handles cleanup.
- **Moderate urgency** (0.3 - 0.6): Release 1 file. Provides a buffer while scanning continues.
- **High urgency** (0.6 - 0.9): Release 3 files. Significant immediate space recovery.
- **Emergency** (> 0.9): Release all remaining files. Maximum immediate relief.

Release is instant (just `unlink()`), providing space recovery in milliseconds rather than the seconds-to-minutes required for scanning and deletion.

#### Replenishment

When pressure returns to Green, the replenishment controller begins rebuilding released ballast files. Replenishment is deliberately slow (one file per cycle, with a configurable cooldown) to avoid re-creating pressure immediately after recovery. The controller tracks how many files were released since the last Green period and only replenishes that many, preventing unnecessary churn.

All ballast operations (provision, release, replenish, verify) are serialized per-volume via `flock()` on a lockfile, preventing races between the daemon and CLI commands.

### VOI Scan Scheduling

Fixed-interval full scans waste IO bandwidth when most directories haven't changed. The Value-of-Information (VOI) scheduler allocates a limited scan budget (default: 5 paths per cycle) to the paths most likely to yield reclaimable space.

#### Per-Path Statistics

The scheduler maintains EWMA-smoothed statistics for each watched path:

- **Expected reclaim**: Bytes recovered per scan of this path (smoothed with alpha 0.3).
- **IO cost**: Estimated filesystem reads per scan (initialized at 1000, updated from actuals).
- **False positive rate**: Fraction of scanned candidates that were later skipped or failed pre-flight checks.

#### Utility Scoring

Each path's utility combines exploitation (scan paths with known high yield) and exploration (periodically re-scan paths that haven't been visited recently):

```
utility = expected_reclaim * uncertainty_discount
        - io_cost * 0.1
        - fp_rate * expected_reclaim * 0.15
        + exploration_bonus
```

The uncertainty discount ranges from 0.5 (fewer than 3 scans, high uncertainty) to 1.0 (well-established statistics). The exploration bonus is proportional to hours since last scan (capped at 24) and inversely proportional to total scan count, ensuring every path gets periodic attention even if its historical yield is low.

The scan budget is split: 80% exploitation (highest-utility paths) and 20% exploration (least-recently-scanned paths). This balance prevents the scheduler from permanently ignoring paths where a new project has started generating artifacts.

#### Fallback Mode

If the VOI scheduler's forecast error (MAPE) exceeds 50% for 3 consecutive windows, it falls back to simple round-robin scheduling. It recovers after 5 consecutive windows with acceptable MAPE. This prevents the scheduler from making poor allocation decisions when its model of the environment is wrong.

### Guardrails and Drift Detection

The guardrail system continuously validates that the EWMA forecaster's predictions match reality. When predictions diverge from actuals, the guardrails trigger policy fallback before bad predictions can drive bad deletion decisions.

#### Calibration Monitoring

Each observation window compares the forecaster's predictions against actual outcomes:

- **Rate error**: `|predicted_rate - actual_rate| / |actual_rate|`. Must stay below 0.30 (30%).
- **TTE conservatism**: The predicted time-to-exhaustion must be less than or equal to the actual time. Overestimates are acceptable (conservative); underestimates are not.

A window is considered well-calibrated if the rate error is below threshold *and* the TTE prediction was conservative. Over a rolling window of 50 observations, the median rate error and conservative fraction are tracked.

Guard status transitions from Unknown to Pass after 10 observations if calibration holds, and transitions to Fail if median rate error exceeds 0.30 or the conservative fraction drops below 0.70.

#### E-Process Drift Detection

The e-process is an anytime-valid sequential hypothesis test that detects systematic miscalibration without parametric assumptions. It works as a running likelihood ratio:

```
For each observation:
  if well-calibrated:  e_process_log += ln(0.8)   (reward, moves toward 0)
  if miscalibrated:    e_process_log += ln(1.5)   (penalty, moves toward alarm)

e_process_log = clamp(e_process_log, -5.0, 5.0)
e_process_value = exp(e_process_log)
alarm = (e_process_value >= 20.0)
```

The clamping bounds serve specific purposes:
- **Lower bound (-5.0)**: Prevents "banking" too much credit from long good streaks. `exp(-5) ~ 0.0067`, ensuring that even after extended good behavior, the alarm can fire within ~10-15 bad observations.
- **Upper bound (5.0)**: Prevents runaway alarm state. `exp(5) ~ 148`, ensuring recovery is possible within ~10 good observations after the anomaly passes.

When the e-process value reaches the threshold (20.0), it signals systematic drift in the forecaster's calibration and triggers GuardrailDrift fallback in the policy engine. On recovery from fallback, the e-process resets to 0.0 so accumulated history doesn't bias future detection.

### Dual Logging and Observability

Every significant event is logged to two independent backends: SQLite for queryable analytics and JSONL for crash-safe audit trails.

#### SQLite Backend

The SQLite logger operates in WAL (Write-Ahead Logging) mode with `synchronous=NORMAL`, trading some crash durability for write throughput. It stores structured rows for pressure changes, artifact deletions, ballast operations, errors, and policy transitions.

The stats engine queries this data for `sbh stats` reports: time-window aggregation, top-N deleted patterns, deletion success rates, and pressure-level distribution over time. The `sbh blame` command uses process attribution data from the SQLite store.

Automatic retention pruning removes rows older than 30 days, triggered every 3600 events (approximately hourly at typical event rates).

#### JSONL Backend

The JSONL writer appends one JSON object per line to a file, providing a portable, grep-friendly, append-only log. Lines are assembled in memory and written atomically to prevent interleaved partial lines when multiple tools tail the file.

Rotation triggers when the file exceeds 100 MiB, keeping up to 5 rotated files. Fsync runs every 10 seconds (frequent enough to limit data loss, infrequent enough to avoid IO stalls).

#### Degradation Chain

If the SQLite backend fails (disk full, corruption, permission error), the logger falls through a degradation chain:

1. Track consecutive SQLite failures.
2. After 50 consecutive failures, disable SQLite and log only to JSONL.
3. Periodically attempt to reopen the SQLite connection.
4. If JSONL also fails, fall back to a RAM-backed path (`/dev/shm/sbh.jsonl`).
5. If that fails, write to stderr with `[SBH-JSONL]` prefix.
6. If even stderr fails, silently discard (the daemon never blocks on logging).

The logger thread runs on a bounded channel (capacity 1024). When the channel is full, events are dropped and a counter is incremented. The drop count is reported periodically as a delta (not cumulative) to avoid alarm fatigue.

### Zero-Write Emergency Mode

When a disk is at 99%+ utilization, normal operations may fail because they need to write temporary files, state, or logs. `sbh emergency` operates in a zero-write mode that avoids all disk writes:

- No SQLite writes (database might be on the full disk).
- No JSONL writes (log file might be on the full disk).
- No state file updates.
- No configuration file reads that might trigger cache writes.
- Scoring uses in-memory defaults only.
- Output goes directly to stdout/stderr.

The emergency command scans the specified paths, scores candidates using the standard multi-factor engine, and presents them for immediate deletion. With `--yes`, it executes deletions immediately without interactive confirmation, prioritizing the highest-scoring candidates until the target free space is reached or all candidates are exhausted.

A completely full disk is precisely the situation where most cleanup tools fail, since they need to write temp files or state. By reducing to pure in-memory scoring and direct unlink calls, `sbh emergency` can recover a system that nothing else can touch.

### Source Layout

```
src/
  lib.rs                    Crate root: re-exports all modules
  main.rs                   Binary entry: CLI parse + dispatch
  cli_app.rs                Full CLI definition (clap derive) + command handlers
  decision_plane_tests.rs   Replay-based policy engine integration tests

  core/
    config.rs               TOML config model + env var overrides + validation
    errors.rs               SbhError enum with SBH-XXXX codes + retryable flag

  monitor/
    fs_stats.rs             Filesystem stats via statvfs with mount-aware caching
    ewma.rs                 Adaptive EWMA rate estimator with quadratic prediction
    pid.rs                  PID pressure controller with predictive urgency boost
    predictive.rs           Predictive action pipeline with early warning
    guardrails.rs           E-process drift detection + calibration monitoring
    special_locations.rs    /tmp, /data/tmp, swap surveillance
    voi_scheduler.rs        Value-of-Information scan budget allocator

  scanner/
    walker.rs               Parallel directory walker with open-file detection
    patterns.rs             Artifact pattern registry (~200 known patterns)
    scoring.rs              Multi-factor scoring + Bayesian decision framework
    deletion.rs             Circuit-breaker-guarded deletion executor
    protection.rs           .sbh-protect markers + config glob patterns
    merkle.rs               Incremental Merkle scan index with full-scan fallback

  ballast/
    manager.rs              Ballast pool lifecycle (provision, verify, inventory)
    release.rs              Pressure-responsive ballast release controller
    coordinator.rs          Multi-volume ballast coordination with flock

  daemon/
    loop_main.rs            Main monitoring loop (poll -> decide -> act -> log)
    policy.rs               Progressive delivery engine (observe/canary/enforce)
    signals.rs              Signal handling (SIGTERM, SIGHUP reload, SIGUSR1 scan)
    self_monitor.rs         Daemon health self-checks (RSS, state writes, panics)
    service.rs              systemd unit + launchd plist generation
    notifications.rs        Multi-channel notification system

  logger/
    dual.rs                 Dual-write logger with degradation chain
    sqlite.rs               SQLite WAL-mode activity logger with retention
    jsonl.rs                JSONL append-only log with rotation
    stats.rs                Stats engine for time-window queries + blame

  cli/
    mod.rs                  Shared installer/update contracts and types
    bootstrap.rs            Bootstrap migration and self-healing
    integrations.rs         AI tool integration bootstrap (Claude, Codex, etc.)
    assets.rs               Asset manifest download/verify/cache with SHA-256
    from_source.rs          From-source build fallback mode
    uninstall.rs            Uninstall with 5 cleanup modes
    wizard.rs               Guided first-run install wizard + --auto mode

  platform/
    pal.rs                  Platform abstraction (Linux: procfs, statvfs, mounts)
```

### Error Codes

`sbh` uses structured error codes in the format `SBH-XXXX` for machine-parseable error identification:

| Range | Category | Examples |
| --- | --- | --- |
| SBH-1xxx | Configuration | Invalid values (1001), missing config (1002), parse failure (1003), unsupported platform (1101) |
| SBH-2xxx | Runtime/IO | Filesystem stats failure (2001), safety veto (2003), SQL failure (2102) |
| SBH-3xxx | System | Permission denied (3001), IO failure (3002), channel error, runtime error |

All errors implement `code()` for the stable string code, `is_retryable()` to indicate whether retry might help, and standard `Display` formatting with the code prefix.

## Testing

```bash
# Unit tests
rch exec "cargo test --lib"

# Integration tests
rch exec "cargo test --test integration_tests"

# End-to-end scripts with detailed logs
./scripts/e2e_test.sh

# Stress scenarios
rch exec "cargo test --test stress_tests -- --nocapture"

# Quality gates
cargo fmt --check
rch exec "cargo check --all-targets"
rch exec "cargo clippy --all-targets -- -D warnings"
```

For test harness conventions and structured logging registration, see `docs/testing-and-logging.md`.

## Troubleshooting

### "No candidates found, but disk is full"
- Run `sbh scan <path> --min-score 0.0` to inspect vetoed items.
- Check protections via `sbh protect --list`.
- Use `sbh emergency <path>` for immediate zero-write triage.

### "Cleanup is too conservative"
- Inspect policy mode (`observe`/`canary`/`enforce`).
- Review `sbh explain --id <decision-id>` for veto/guard reasons.
- Adjust scoring weights and thresholds in config.

### "Ballast release did not free expected space"
- Verify target mount with `sbh ballast status`.
- Ensure the pressured path has a corresponding ballast pool.
- Check for read-only/tmpfs/NFS skip rules.

### "Dashboard or status looks stale"
- Confirm daemon is running.
- Check state/log paths and permissions.
- Validate config with `sbh config validate`.

### "Service fails to start"
- Linux: inspect `systemctl status` and journal logs.
- macOS: inspect `launchctl` output and plist paths.
- Run `sbh daemon` directly to capture startup errors.

## Limitations

- Process attribution relies on platform-specific process inspection and may be reduced on restricted environments.
- Extremely bursty workloads may require tighter sample intervals and controller tuning.
- Network and ephemeral filesystems are intentionally conservative for ballast and cleanup safety.

## FAQ

### Does `sbh` delete source code?
No. Safety vetoes and protection mechanisms are designed to avoid source directories and protected paths.

### Can I force cleanup during an incident?
Yes. Use `sbh emergency ...` for zero-write recovery, then return to normal policy modes.

### Can I run `sbh` without the daemon?
Yes. `scan`, `clean`, `check`, and `emergency` support operational workflows without a long-running service.

### How do I audit why something was deleted?
Use `sbh explain --id <decision-id>` and inspect structured logs/evidence records.

### Is this Linux-only?
No. It is cross-platform, with service integration for `systemd` (Linux) and `launchd` (macOS).

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT.
