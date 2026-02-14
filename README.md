# storage_ballast_helper (`sbh`)

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

## How `sbh` Compares

| Capability | `sbh` | Cron + `rm` scripts | Generic temp cleaners | Manual cleanup |
| --- | --- | --- | --- | --- |
| Predictive pressure response | ✅ EWMA + PID | ❌ | ❌ | ❌ |
| Multi-volume awareness | ✅ | ⚠️ usually custom | ⚠️ partial | ⚠️ manual |
| Hard safety vetoes | ✅ built-in | ⚠️ fragile scripts | ⚠️ limited | ✅ human judgment |
| Explainability and traces | ✅ | ❌ | ❌ | ❌ |
| Emergency zero-write recovery | ✅ | ❌ | ❌ | ⚠️ slow |
| Service-grade observability | ✅ | ❌ | ⚠️ minimal | ❌ |

## Installation

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
| `sbh install` / `sbh uninstall` | Install/remove service integration |

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

## Testing

```bash
# Unit and property tests
cargo test

# Integration tests
cargo test --test integration_tests

# End-to-end scripts with detailed logs
./scripts/e2e_test.sh

# Stress scenarios
cargo test --test stress_tests -- --nocapture

# Quality gates
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

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
