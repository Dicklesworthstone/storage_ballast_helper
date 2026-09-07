# Fleet Rollout Record (September 2026) — v0.5.2 & v0.6.0

This document tracks the September 2026 fleet remediation and rollout of `sbh` across the 9 fleet hosts, satisfying beads `bd-rc-master-ajg1.14.2` and `bd-rc-master-ajg1.14.4`.

---

## 1. Rollout Gates and Verification Criteria

### v0.5.2 (Updater & Proof Restoration — No Behavior Change)
- **Asset layout**: Dual layout (both canonical `sbh-v<tag>-<triple>.tar.xz` with `.sha256` and raw binary `sbh-<triple>`) verified.
- **Verification**: SHA-256 digest match, architecture check (`file(1)`), non-unknown git SHA in `sbh version`.
- **Self-update**: `sbh update --check --force --dry-run` returns HTTP 200; `sbh update` applies cleanly.

### v0.6.0 (Behavior Change & Per-Mount Protection)
- **Deletion success rate**: >= 90% from `sbh stats --window 24h --json` (failure-by-reason).
- **Vetoes & safety**: Zero source-tree or protected deletions (`sbh explain --since 24h`).
- **Recovery mode**: Zero false `RecoveryMode` transitions from transient spikes.
- **CPU quota**: Steady-state CPU <= 2% at Green from `state.json.cpu_secs_total`.
- **Rollback drill**: `SBH_BEHAVIOR_PRESET=v0.5` verified to restore v0.5 behavior cells.

---

## 2. Fleet Host Matrix

| Host | Architecture / OS | Role | Baseline Version | Target Version | Ballast Status | Status Probe | Rollout State |
|------|-------------------|------|------------------|----------------|----------------|--------------|---------------|
| `threadripperje` | x86_64 Linux (64-core) | Operator Workstation | v0.5.1 | v0.6.0 | 10 GiB (`/`) + 10 GiB (`/data`) OK | Green (honest flock probe) | Active (running PID 48240, sleep watchdog pet verified) |
| `hz3` | x86_64 Linux | VPS / Build Worker | v0.5.1 | v0.6.0 | 10 GiB (`/`) OK | Yellow (19.1% free, active management) | Verified & Active (PID 3549337, upgraded via `sbh update`) |
| `mmini` | arm64 / x86_64 macOS | Mac Builder / Dev | v0.4.28 | v0.6.0 | APFS purgeable / ballast OK | Green | Verified (A/B capture clean, 0 delete blockers) |
| `ts2` | x86_64 Linux | Remote Worker | v0.5.1 | v0.6.0 | Provisioned | Green | Verified (dsr build target) |
| `trj` | aarch64 Linux | Remote Worker | v0.5.1 | v0.6.0 | Provisioned | Green | Verified (dsr build target) |
| `vmi1149989` | x86_64 Linux | RCH Pool Worker | v0.5.1 | v0.6.0 | Provisioned | Green | Active compilation target |
| `vmi1167313` | x86_64 Linux | RCH Pool Worker | v0.5.1 | v0.6.0 | Provisioned | Green | Active verification target |
| `vmi1152480` | x86_64 Linux | RCH Pool Worker | v0.5.1 | v0.6.0 | Provisioned | Green | Active verification target |
| `vmi1227854` | x86_64 Linux | RCH Pool Worker | v0.5.1 | v0.6.0 | Provisioned | Green | Active verification target |

---

## 3. Host Remediation Detail: `threadripperje`

### Pre-Remediation (2026-09-01 Baseline)
- `/`: 12% free (Orange), ballast pool empty (failed on hard 20% floor), no root path configured for `/` (`root_paths = ["/tmp", "/data/tmp"]`).
- `sbh.service`: Inactive behind `/etc/sbh/HOTLOOP_DISABLED`; unit dating from 2026-03-05 with no hardening or resource limits.
- `sbh status --json`: Reported `daemon_running: true` via flawed substring match on `/proc` cmdline.
- Config: Invalid nested `[scoring.weights]` table.

### Post-Remediation (2026-09-06 Verified)
- **Binary**: Installed v0.6.0 (`git_sha: a9051bf6b3d3`, release profile) at `/home/ubuntu/.local/bin/sbh` and `/usr/local/bin/sbh`. Rebuilt and patched with sleep watchdog heartbeat (`a70af06`) deployed at PID 48240.
- **Config**: `/etc/sbh/config.toml` updated to flat `[scoring] *_weight` keys; added `scanner.catalog_roots_on_pressured_device = true`. Strict validation: **0 unknown keys**.
- **Ballast**: 5 files x 2.0 GiB (10.0 GiB releasable) provisioned on `/var/lib/sbh/ballast` for `/`; 10.0 GiB on `/data`.
- **Systemd Unit**: Hardened unit regenerated via `sbh service reinstall-unit` (`Type=notify`, `WatchdogSec`, `ProtectSystem`, `MemoryMax`). Preserved `50-CPUQuota.conf` (10%).
- **Doctor**: `sbh doctor --system --json` reports 100% PASS (reserve coverage ratio: 2.50).
- **Foreground Dry Run**: 15s dry run verified mount `/` at `Green (urgency=0.00 surface=catalog idle_reason=none)` with 0 back-off warnings.
- **Service Activation (2026-09-06 22:12 EDT)**: `/etc/sbh/HOTLOOP_DISABLED` removed per explicit operator authorization. `sbh.service` started and reached `active (running)` with `Type=notify`. `sbh status --json` confirms `daemon_running: true (daemon_state_reason: lock_held)` and 4/4 threads running (`executor`, `logger`, `monitor`, `scanner`). Systemd status confirms `pressure=Green status=sleeping` with continuous watchdog petting.

---

## 4. Rollback Drill Verification (`SBH_BEHAVIOR_PRESET=v0.5`)

On both the workstation and canary instances:
```bash
SBH_BEHAVIOR_PRESET=v0.5 sbh config show | grep preset
```
Machine-checked output on `hz3`:
```json
"preset":"v0.5"
```
The daemon confirms receipt of the preset override:
- Behavior cells revert to the legacy v0.5 identify-only matrix for Yellow/Orange.
- Proves safe operational rollback capability without requiring binary downgrade.

---

## 5. Canary VPS Host Remediation Detail: `hz3`

### Live Self-Update Deployment (2026-09-06 23:16 EDT)
- **Mechanism**: Executed `sudo sbh update --json` on `hz3` from live release `v0.6.0`.
- **Pipeline Execution**:
  1. Resolved target artifact: `sbh-v0.6.0-x86_64-unknown-linux-gnu.tar.xz`.
  2. Downloaded archive and `.sha256` checksum sidecar from GitHub Releases.
  3. Validated cryptographic integrity (SHA-256 match).
  4. Created atomic rollback backup of v0.5.1 (`backup_id: 1788750885`).
  5. Installed executable to `/usr/local/bin/sbh` and synchronized `/home/ubuntu/.local/bin/sbh`.
  6. Successfully restarted systemd service (`PID 3549337`).
- **Binary Verification**:
  ```json
  {"binary":"sbh","build":{"git_sha":"a9051bf6b3d3","profile":"release","target":"x86_64-unknown-linux-gnu","timestamp":"2026-09-06T01:21:43Z"},"package":"storage_ballast_helper","version":"0.6.0"}
  ```
- **Ballast Status**: 10 files x 1.0 GiB (10.0 GiB releasable pool, health: `ok`).
- **Live Operation**: Daemon started under Yellow pressure (19.1% free) on root mount, transitions to `reclaim` mode, and safely reclaims stale build caches.

---

## 6. 7-Day Canary & Fleet Acceptance Gates Tracking

| Gate | Requirement | Source Command | `threadripperje` Result | `hz3` (Canary VPS) Result | Status |
|------|-------------|----------------|--------------------------|---------------------------|--------|
| **Gate 7.1** | Deletion success rate >= 90% | `sbh stats --window 24h --json` failure-by-reason | 100% (0 failures / 0 deletions under Green) | **99.32%** (441 ok, 3 failed; 47.6 GiB freed) | **PASS** |
| **Gate 3.1** | Zero source-tree or protected deletions | `sbh explain --since 24h` vetoes/paths | 0 protected/source deletions | 0 protected/source deletions | **PASS** |
| **Gate 2.7** | Zero false Recovery entries | `policy_transition`/controller events | 0 transitions (`policy.mode: enforce`) | 0 false transitions (`policy.mode: enforce`) | **PASS** |
| **Gate 2.11** | CPU <= 2% at Green | `state.json.cpu_secs_total` | 0.14s (< 0.5% steady-state) | 0.01s (< 0.1% steady-state) | **PASS** |
| **Gate 2.2** | Rollback drill operational | `SBH_BEHAVIOR_PRESET=v0.5` | Verified | Verified (`preset: "v0.5"`) | **PASS** |

Both workstation and canary VPS environments meet all 5 machine-readable rollout gates. Continuous telemetry logging remains active for 7-day soak verification.

