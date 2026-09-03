# storage_ballast_helper (`sbh`)

<div align="center">
  <img src="sbh_illustration.webp" alt="sbh - Storage Ballast Helper illustration">
</div>

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash
```

macOS users: jump straight to the [macOS quick start](#macos-quick-start) for
the launchd, Homebrew, manual install, and Full Disk Access checklist.
For the incident that drove the Mac port, see the
[2026-05-03 macOS case study](docs/macos-incident-case-study.md).

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

### Implementation Constraints

`sbh` enforces several hard constraints that shape the codebase:

- **`#![forbid(unsafe_code)]`** in both `lib.rs` and `main.rs`. No unsafe blocks, no raw pointer arithmetic, no manual memory management. All platform-specific behavior goes through safe abstractions (`nix`, `libc` bindings, `signal-hook`).
- **No async runtime.** Concurrency uses OS threads with `crossbeam-channel` for bounded message passing and `parking_lot` for synchronization. This avoids the complexity and debugging opacity of async runtimes while providing predictable scheduling behavior for a daemon that needs to respond to pressure signals in bounded time.
- **Pedantic + nursery Clippy lints** are enabled project-wide. The code is held to strict Rust idiom standards beyond the default warning set.
- **Deterministic builds.** The release profile uses `opt-level = "z"` (size optimization), `lto = true` (link-time optimization), `codegen-units = 1`, `panic = "abort"`, and `strip = true` for a lean, predictable binary.

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

The one-liner detects Linux versus macOS, downloads the matching release
artifact, installs the `sbh` binary, and updates an existing systemd or launchd
service binary when one is already registered. First-time daemon registration is
still handled by `sbh install --auto`, which chooses systemd on Linux and
launchd on macOS.

Pin a specific version:

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash -s -- --version v0.1.0
```

### macOS Quick Start

For the default user LaunchAgent install:

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/storage_ballast_helper/main/scripts/install.sh | bash
sbh install --auto
sbh doctor --pal
sbh status
```

`sbh install --auto` detects macOS, chooses launchd, installs a user-scoped
LaunchAgent, uses native Application Support paths, and provisions the default
ballast preset. Use system scope only when `sbh` must inspect system-wide paths
or all users' process activity:

```bash
sudo sbh install --launchd --scope system --auto
sudo sbh doctor --pal
```

Homebrew is supported by the packaged formula skeleton and the
`Dicklesworthstone/homebrew-sbh` tap. Tagged releases copy
`packaging/homebrew/Formula/sbh.rb` into the tap, replace the per-architecture
SHA-256 placeholders from the release artifacts, and publish the formula
update to the tap using the `HOMEBREW_TAP_SSH_KEY` release secret. That secret is
the private half of a write-enabled deploy key scoped only to the tap repository;
the release workflow verifies the key can see `main` and dry-runs a branch push
before building release artifacts. After the tap update lands, the operator path
is:

```bash
brew tap Dicklesworthstone/sbh
brew install sbh
sbh install --launchd --scope user --auto
sbh doctor --pal
```

Manual macOS install from source is the same Cargo path as Linux, followed by
launchd setup:

```bash
cargo install --git https://github.com/Dicklesworthstone/storage_ballast_helper --bin sbh
sbh install --launchd --scope user --auto
sbh doctor --pal
```

Grant Full Disk Access before relying on cleanup scans that need protected
locations under `~/Library`; `sbh doctor --pal` reports the exact FDA status and
links to `docs/macos-full-disk-access.md`.

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

## Environment Health and Migration

The bootstrap system detects and repairs common installation problems, from stale PATH entries to misconfigured service files. It runs automatically during `sbh install` and can be invoked manually with `sbh bootstrap`.

### Environment Health States

| State | Meaning |
| --- | --- |
| Healthy | All checks pass |
| Degraded | Minor issues detected, `sbh` remains functional |
| Broken | Significant issues preventing correct operation |
| NotInstalled | No installation footprint detected |

### Migration Reasons

The bootstrap scanner checks for 16 migration conditions:

| Reason | Description |
| --- | --- |
| `binary-not-on-path` | Binary exists but shell PATH does not include its directory |
| `stale-path-entry` | Shell profile references a binary location that no longer exists |
| `duplicate-path-entries` | Multiple `sbh` PATH entries in the same shell profile |
| `systemd-unit-stale-binary` | systemd `ExecStart` points to a missing binary |
| `systemd-unit-stale-paths` | systemd `ReadWritePaths=` does not cover the configured scan roots, ballast or data directories (the daemon could not delete or write there under `ProtectSystem=strict`); repaired by rewriting the line and `daemon-reload` |
| `launchd-plist-stale-binary` | launchd `ProgramArguments` references a missing binary |
| `deprecated-config-key` | Config uses renamed keys (`scan_interval_secs`, `max_ballast_mb`, `log_level`) |
| `legacy-config-path` | Config exists in an older Linux/XDG, manual, or Homebrew path and should be copied to the canonical platform path |
| `legacy-data-path` | State/log files exist in an older Linux/XDG, manual, or Homebrew data path and should be copied to the canonical platform data directory |
| `missing-state-file` | Data directory exists but `state.json` is absent |
| `orphaned-completion` | Shell completion script installed for an unavailable shell |
| `stale-completion` | Completion script out of date |
| `empty-ballast-pool` | Ballast directory is undersized or empty |
| `binary-permissions` | Binary is not executable |
| `stale-backup-file` | Old backup from a previous install past the cleanup threshold |
| `interrupted-install` | Marker file indicates an incomplete prior installation |

### Repair Actions

Each detected issue maps to one of 10 action types: `RemoveProfileLine`, `DeduplicateProfile`, `FixPermissions`, `UpdateServicePath`, `CopyLegacyConfig`, `CopyLegacyState`, `RemoveOrphanedFile`, `CleanupBackup`, `CreateDirectory`, `InitStateFile`.

All mutations create timestamped backups before writing. Legacy config/state migration is copy-only and never overwrites an existing canonical file, so older XDG/manual/Homebrew sources remain in place until the operator removes them deliberately. A 7-day default threshold governs automatic cleanup of old backup files.

```bash
# Run bootstrap scan and repair
sbh bootstrap

# Dry-run to see what would change
sbh bootstrap --dry-run

# Machine-readable report (reasons use the kebab-case codes above)
sbh bootstrap --dry-run --json

# Read-only scan as part of doctor
sbh doctor --env

# Skip the automatic install-time repairs
sbh install --no-bootstrap
```

During `sbh install` only the actions that fix the install being produced run automatically: `RemoveProfileLine`, `DeduplicateProfile`, `FixPermissions`, `UpdateServicePath`, `CreateDirectory`, `InitStateFile`. Legacy config/state copies, orphaned-file removal, and backup cleanup are planned and reported but left for an explicit `sbh bootstrap`. A non-dry-run `sbh bootstrap` exits non-zero when the environment is still `Broken` afterwards or any action failed.

Source: `src/cli/bootstrap.rs`

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

### Config and State Paths

`sbh` uses platform-native defaults unless you explicitly override them:

| Platform | Config | State, logs, ballast, update cache |
| --- | --- | --- |
| Linux | `~/.config/sbh/config.toml` | `~/.local/share/sbh/` |
| Linux system service | `/etc/sbh/config.toml` | `/var/lib/sbh/` |
| macOS user service | `~/Library/Application Support/sbh/config.toml` | `~/Library/Application Support/sbh/` |
| macOS system service | `/Library/Application Support/sbh/config.toml` | `/private/var/sbh/` |

The default ballast pool is `~/.local/share/sbh/ballast` for Linux user installs, `/var/lib/sbh/ballast` for Linux system services, `~/Library/Application Support/sbh/ballast.bin` for macOS LaunchAgents, and `/private/var/sbh/ballast.bin` for macOS LaunchDaemons. Override `[paths].ballast_dir` in the config file when the ballast pool must live on a specific volume.

Precedence is: `--config`, then `SBH_CONFIG`, then the platform default. On macOS, setting `SBH_USE_XDG_PATHS=1`, setting `XDG_CONFIG_HOME`/`XDG_DATA_HOME`, or already having `~/.config/sbh/config.toml` without a native App Support config opts into the XDG layout.

### Install Wizard

Running `sbh install` without prior configuration launches the install wizard, which guides through four steps:

1. **Service manager** -- systemd (Linux default), launchd (macOS default), or none (manual start).
2. **Service scope** -- user service or system-wide (system scope requires root).
3. **Watched paths** -- auto-detects `/data/projects`, `/tmp`, and `$HOME` if they exist. Custom paths can be added interactively.
4. **Ballast sizing** -- choose a preset or enter custom file counts:

| Preset | Files | Per-File Size | Total |
| --- | --- | --- | --- |
| Small | 5 | 1 GiB | 5 GiB |
| Medium (default) | 10 | 1 GiB | 10 GiB |
| Large | 20 | 1 GiB | 20 GiB |
| Custom | user-specified | 1 GiB | varies |

For non-interactive environments (CI, automation), `sbh install --auto` applies platform-detected defaults: the platform-native service manager, auto-discovered watched paths, user-scope service, and Medium ballast preset.

### macOS Configure Checklist

- **LaunchAgent vs LaunchDaemon:** user scope is the default and writes under
  `~/Library/Application Support/sbh/`; system scope requires `sudo`, installs a
  LaunchDaemon, writes under `/private/var/sbh/`, and can inspect all users'
  process activity.
- **Full Disk Access:** run `sbh doctor --pal` after install. If the
  `macos.full_disk_access` check warns or fails, follow
  `docs/macos-full-disk-access.md`, then restart the launchd service.
- **Service control:** use `sbh service --launchd --scope user status` and
  `sbh service --launchd --scope user restart` for user installs; replace
  `--scope user` with `--scope system` for LaunchDaemons.
- **Homebrew paths:** Apple Silicon installs normally live under
  `/opt/homebrew`, Intel installs under `/usr/local`; bootstrap and doctor
  checks inspect both families and repair stale launchd plist paths.

## Command Reference

### Core

| Command | Purpose |
| --- | --- |
| `sbh daemon` | Run monitoring loop and policy engine |
| `sbh status` | Real-time health, pressure, and controller state |
| `sbh check` | Pre-flight space check and recommendations |
| `sbh scan` | Manual candidate discovery and scoring report |
| `sbh clean` | Manual cleanup with confirmation/dry-run |
| `sbh undo` | Restore quarantined entries (`<decision-id>`, `--path`, `--all-since`, `--list`) |
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
| `sbh lease run --target PATH --max-bytes SIZE -- COMMAND...` | Run a command with a process-bound active-target lease |
| `sbh lease status [--target PATH]` | Inspect active lease state and machine-readable bounds |
| `sbh lease renew [--target PATH] [--extend DURATION]` | Authenticated soft-deadline renewal from inside the leased process tree |

`sbh protect` is permanent operator policy; `sbh lease` is ephemeral process
lifetime protection for fresh build/test output. On Linux and macOS, `lease run`
locks a stable sidecar before creating the target, places the command in its own
process group, injects `CARGO_TARGET_DIR`, and replaces `sbh` with the command.
The kernel releases protection when that process tree exits or crashes. A
separate watchdog terminates that process group if its renewable deadline,
declared byte budget, hard eight-hour lifetime, or the 10 GiB emergency reserve
is crossed. It never deletes the target.

The target must be absent, absolute, and an immediate child of one configured
`scanner.root_paths` entry. A root admits at most four concurrent leases, 64 GiB
per lease, and 128 GiB in aggregate. Renewal uses a 256-bit token inherited in
`SBH_ACTIVE_LEASE_TOKEN`; durable metadata stores only its SHA-256 digest. Use
`--json` with `status` or `renew` for automation. The command's stdout remains
its own; lease lifecycle diagnostics go to stderr.

```bash
lease_target=/data/tmp/mtdt-check-$$
sbh lease run --target "$lease_target" --max-bytes 32G --ttl 2h -- \
  cargo check --workspace --all-targets

# From the leased command or one of its descendants:
sbh --json lease status
sbh --json lease renew --extend 30m
```

### Observability and Explainability

| Command | Purpose |
| --- | --- |
| `sbh stats` | Time-window activity/deletion statistics |
| `sbh blame` | Attribute artifact pressure by process/agent |
| `sbh dashboard` | Real-time TUI dashboard |
| `sbh doctor --pal` | Validate platform integration and macOS runtime prerequisites |
| `sbh doctor --system` | Check host kernel tuning (writeback / dirty-page limits) |
| `sbh doctor --service [--user]` | Compare the installed systemd unit (or launchd plist) with what sbh generates: FAIL on missing hardening, a different `Type=`/binary, a drop-in overriding hardening, or a `Condition*=` gate that keeps the unit from starting; WARN on foreign drop-ins and cosmetic differences |
| `sbh service --systemd reinstall-unit [--purge-dropins]` | Rewrite the unit from the generator with a timestamped backup beside it and `daemon-reload`; drop-ins stay in effect unless `--purge-dropins` moves them into the backup directory |
| `sbh explain (--id ID \| --last N \| --path P \| --since W) [--level 0-3]` | Explain recorded cleanup decisions: the daemon records one per evaluated candidate, `sbh clean` records its plan; ids are stable per artifact version and appear in `scan --json` and `artifact_delete` events |

On macOS, `sbh doctor --pal` adds PASS/WARN/FAIL checks for the binary signature,
Gatekeeper assessment, launchd service state, Full Disk Access, APFS inventory,
and free space on the state volume. Each warning or failure includes the
remediation command or system setting to check before installing the daemon.

### Configuration and Lifecycle

| Command | Purpose |
| --- | --- |
| `sbh config show|set|validate|diff|reset` | Manage effective config |
| `sbh update [flags]` | Check/apply updates with rollback, cache control, and backup management |
| `sbh install` / `sbh uninstall` | Install/remove service integration |

## Dashboard

The `sbh dashboard` command opens a real-time TUI cockpit for monitoring disk pressure, reviewing scan candidates, inspecting policy decisions, and managing ballast pools. It replaces the legacy single-screen status display with a seven-screen navigation model, overlay system, and incident workflow shortcuts.

### Launching

```bash
# Open the dashboard (requires a running daemon for live data)
sbh dashboard

# Start with a specific screen
sbh dashboard --start-screen ballast

# Use legacy single-screen mode (fallback)
sbh dashboard --legacy-dashboard

# Force new cockpit even if kill switch is set
sbh dashboard --new-dashboard
```

Rollout controls (in `config.toml`):

```toml
[dashboard]
mode = "new"       # "legacy" | "new" (default: "new")
kill_switch = false # Emergency fallback to legacy
```

Environment overrides: `SBH_DASHBOARD_MODE`, `SBH_DASHBOARD_KILL_SWITCH`.

### Screens

| Key | Screen | Purpose |
| --- | --- | --- |
| `1` | Overview | Dense cockpit grid: pressure matrix, forecasts, decision pulse, hotlist, ballast, special-locations watch, counters |
| `2` | Timeline | Event stream with severity filtering and detail drill-down |
| `3` | Explainability | Decision evidence, posterior traces, factor contributions |
| `4` | Candidates | Ranked scan results with score breakdown and veto visibility |
| `5` | Ballast | Per-volume ballast inventory, release, and replenish controls |
| `6` | LogSearch | JSONL/SQLite log viewing with search and filter |
| `7` | Diagnostics | Daemon health, frame performance, thread status, RSS |

### Keybindings

**Navigation:**

| Key | Action |
| --- | --- |
| `1`-`7` | Jump directly to screen |
| `[` / `]` | Previous / next screen |
| `Tab` / `Shift-Tab` | Cycle focused pane on Overview |
| `Enter` / `Space` (Overview) | Open focused pane target screen |
| `b` | Jump to Ballast screen |
| `Esc` | Close overlay, then close open detail pane, then back, then quit |
| `q` | Quit dashboard |
| `Ctrl-C` | Immediate quit |

**Overlays:**

| Key | Action |
| --- | --- |
| `?` | Toggle help overlay (contextual keybinding reference) |
| `Ctrl-P` or `:` | Open command palette (fuzzy search 36 actions) |
| `v` | Toggle VOI scheduler overlay |
| `r` | Force data refresh |

**Incident shortcuts (active during pressure events):**

| Key | Action |
| --- | --- |
| `!` | Open incident triage playbook overlay |
| `x` | Quick-release ballast (jumps to Ballast + opens release confirmation) |

**Screen-specific keys:**

| Key | Screens | Action |
| --- | --- | --- |
| `j` / `k` or arrows | Timeline, Candidates, Explainability, Ballast | Cursor navigation |
| `Enter` or `Space` | Candidates, Explainability, Ballast | Toggle detail view |
| `d` | Candidates, Explainability, Ballast | Close detail panel |
| `f` | Timeline | Cycle severity filter |
| `Shift-F` | Timeline | Toggle follow mode (auto-scroll to latest) |
| `s` | Candidates | Cycle sort order (Score, Size, Age, Path) |
| `Shift-V` | Diagnostics | Toggle verbose frame metrics |

**Mouse support:**

| Input | Action |
| --- | --- |
| Move | Hover-highlight Overview panes |
| Left click | Focus + open Overview pane target screen |
| Wheel on hotlist | Scroll candidate hotlist selection |

### Command Palette

Press `:` or `Ctrl-P` to open the command palette. Type to fuzzy-search through 36 available actions including navigation, preference changes, overview pane controls, and incident commands. Press `Enter` to execute, `Esc` to cancel. Palette actions include:

- `nav.overview` through `nav.diagnostics` (screen navigation)
- `pref.density.compact`, `pref.density.comfortable` (visual density)
- `pref.hints.off`, `pref.hints.minimal`, `pref.hints.full` (hint verbosity)
- `pref.start.*` (startup screen)
- `action.overview.focus-next`, `action.overview.focus-prev`, `action.overview.open-focused` (overview pane navigation)
- `incident.playbook`, `incident.quick-release`, `incident.triage` (incident shortcuts)

### Incident Workflows

During disk pressure events, the dashboard provides guided triage shortcuts. The incident system classifies pressure into four severity levels based on the daemon's pressure state:

| Severity | Trigger | Dashboard behavior |
| --- | --- | --- |
| Normal | Green pressure | Standard operation, no hints |
| Elevated | Yellow/warning | Context-aware hints appear on relevant screens |
| High | Orange pressure | Alert banner + all triage hints visible |
| Critical | Red/emergency | Urgent alert banner + maximum triage guidance |

**Triage playbook** (`!` key): Opens a 7-entry guided playbook ordered by triage priority:
1. Release ballast (Ballast screen)
2. Review scan candidates (Candidates screen)
3. Check decision rationale (Explainability screen)
4. Inspect timeline events (Timeline screen)
5. Verify ballast inventory
6. Review diagnostics
7. Assess overall pressure (Overview screen)

Use `j`/`k` to navigate entries and `Enter` to jump to the target screen.

**Quick-release** (`x` key): One-keystroke shortcut that navigates to the Ballast screen and opens a release confirmation dialog. Reduces the typical pressure-triage path from 8 steps (legacy) to 1 keystroke.

### Degraded Mode

When the daemon is unreachable (not running, state file missing, or permissions issue), the dashboard enters degraded mode:

- A `DEGRADED` indicator appears on the Overview screen.
- Mount pressure data falls back to direct filesystem probes via `statvfs`.
- Telemetry screens (Timeline, Candidates, Explainability, Ballast) show stale or empty data.
- All navigation and overlay features remain functional.

Check Diagnostics (key `7`) for daemon connection details and error counts.

### Preferences

Dashboard preferences persist across sessions in `~/.config/sbh/dashboard-preferences.json`:

- **Start screen**: Which screen to show on launch (`overview`, `timeline`, etc.)
- **Density**: Visual density mode (`compact`, `comfortable`)
- **Hint verbosity**: How much context to show (`off`, `minimal`, `full`)
- **Contrast**: High-contrast mode (respects `NO_COLOR` environment variable)
- **Motion**: Reduced-motion mode (respects `REDUCE_MOTION` environment variable)
- **Startup help modal**: `show_help_on_start` defaults to `false` (open help with `?`)

Configure via command palette (`:` then type `pref`) or directly in the preferences file.

## Operator Docs

- Installer/update parity contract and security policy: `docs/installer-dx-parity-matrix.md`
- macOS Full Disk Access grant guide and screenshot refresh manifest:
  `docs/macos-full-disk-access.md`, `docs/images/macos/README.md`
- macOS operations guide: `docs/macos.md`
- macOS incident case study with the 264 GB trash staging dir, 9.8 GB Claude
  cache, and active build-target footprint: `docs/macos-incident-case-study.md`
- Migrating from CleanMyMac, OmniDiskSweeper, DaisyDisk, or GrandPerspective:
  `docs/migrating-from-other-tools.md`
- Sample Mac configs for developer, creative, and shared LaunchDaemon machines:
  `docs/configs/`
- macOS launchd troubleshooting guide: `docs/launchd-troubleshooting.md`
- Sacred path catalog and per-pattern safety reasoning: `docs/sacred-paths.md`
- Dashboard/status baseline contract (pre-overhaul): `docs/dashboard-status-contract-baseline.md`
- Dashboard IA + navigation map (overhaul design baseline): `docs/dashboard-information-architecture.md`
- TUI acceptance gates + performance/error budgets: `docs/tui-acceptance-gates-and-budgets.md`
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

### Update Command Flags

| Flag | Description |
| --- | --- |
| `--check` | Check for updates without applying |
| `--version V` | Pin to a specific version tag (e.g. `v0.2.1`) |
| `--force` | Re-download even if already at the target version |
| `--rollback [ID]` | Roll back to the most recent backup, or a specific backup by ID |
| `--list-backups` | List available backup snapshots |
| `--prune N` | Remove old backups, keeping only the N most recent |
| `--max-backups N` | Maximum backups to retain (default: 5) |
| `--refresh-cache` | Bypass local metadata cache and fetch fresh release metadata |
| `--offline PATH` | Use an offline bundle manifest for airgapped updates |
| `--system` | Install to system-wide location (requires root) |
| `--user` | Install to user-local location (`~/.local/bin`) |
| `--dry-run` | Print what would be done without making changes |
| `--no-verify` | Skip artifact verification, including macOS trust checks (unsafe; debugging only) |

Useful operator checks:

```bash
# Inspect effective update policy/config
sbh config show --json | jq '.update'

# Force fresh metadata fetch for diagnostics
sbh update --check --refresh-cache --json

# Roll back to the previous version
sbh update --rollback

# List and prune old backups
sbh update --list-backups
sbh update --prune 3
```

## Configuration Example

```toml
[scanner]
quarantine_enabled = true # Layer 7: Green and `sbh clean` candidates go to <root>/.sbh/quarantine (`sbh undo`)
quarantine_ttl_hours = 24
quarantine_max_bytes_pct = 5
engine = "v2"  # default since v0.4.32; set "v1" to opt back into the legacy full-descent walker
event_source = "auto"
event_watch_budget = 8192
root_paths = ["/data/projects", "/tmp", "/dev/shm"]
cross_devices = false
protected_paths = ["/data/projects/production-*", "/home/*/critical-builds"]

[core]
strict_config = false  # true: refuse to start when the file has keys no section declares
control_socket_enabled = true  # serve control.sock beside state.json for `sbh daemon ping|scan-now|reload|shutdown`, `sbh policy`, live `sbh status`

[pressure]
green_min_free_pct = 35.0
yellow_min_free_pct = 20.0
orange_min_free_pct = 10.0
red_min_free_pct = 5.0
poll_interval_ms = 2000

[ballast]
auto_provision = true          # false: the daemon never builds the pool; use `sbh ballast provision`
file_count = 5
file_size_bytes = 1073741824   # 1 GiB per file

[ballast.overrides."/data"]
file_count = 10
file_size_bytes = 2147483648

[ballast.overrides."/tmp"]
enabled = false

[scoring]
location_weight = 0.25
name_weight = 0.25
age_weight = 0.20
size_weight = 0.15
structure_weight = 0.15
calibration_floor = 0.75

[policy]
initial_mode = "observe"       # observe | canary | enforce
max_canary_deletes_per_hour = 5
kill_switch = false            # true holds the daemon in fallback-safe (no deletions)
# What each fallback trigger does. Unset calibration_breach_action means
# "demote" unless initial_mode is "enforce" (then "advisory"); unset
# emergency_escalation means on for enforce fleets, off otherwise.
# calibration_breach_action = "demote"      # demote | advisory
# canary_budget_action = "keep"             # keep | demote
# serialization_failure_action = "demote"   # demote | advisory
# auto_recover_to = "canary"                # none | canary | previous
# emergency_escalation = false

[paths]
sqlite_db = "/var/lib/sbh/activity.sqlite3"
jsonl_log = "/var/lib/sbh/activity.jsonl"

[pressure.prediction]
enabled = true
action_horizon_minutes = 30.0
warning_horizon_minutes = 60.0
min_confidence = 0.7
min_samples = 5
imminent_danger_minutes = 5.0
critical_danger_minutes = 2.0

[pressure.controller]
# Per-mount PID gains (see "PID Pressure Controller"); the setpoint is green_min_free_pct.
kp = 0.25
ki = 0.08
kd = 0.02
kf = 0.8                        # forecast feedforward gain
integral_cap = 100.0
hysteresis_pct = 1.0
reference_total_bytes = 1099511627776   # 1 TiB: kp applies unscaled here
kp_scale_min = 0.5
kp_scale_max = 2.0

[scheduler]
enabled = true
scan_budget_per_interval = 5
exploration_quota_fraction = 0.20
io_cost_weight = 0.1
fp_risk_weight = 0.15
exploration_weight = 0.25
forecast_error_threshold = 0.5
fallback_trigger_windows = 3
recovery_trigger_windows = 5

[notifications]
enabled = true
channels = ["journal", "file"]
min_notify_interval_secs = 60
urgent_notify_interval_secs = 300

[notifications.desktop]
enabled = false
min_level = "orange"

[notifications.webhook]
enabled = false
url = ""
min_level = "red"
template = '{"text": "sbh: ${SUMMARY}"}'

[notifications.file]
path = "~/.local/share/sbh/notifications.jsonl"

[notifications.journal]
min_level = "warning"

[dashboard]
mode = "new"       # "legacy" | "new"
kill_switch = false

[system_tuning]
# Kernel writeback (dirty-page) tuning. Linux-only; macOS treats it as not-applicable.
writeback_enabled = true
writeback_auto_apply_on_install = true   # apply + persist during `sbh install` when run as root
writeback_target_drain_secs = 1.0        # size dirty_background_bytes to drain in ~1s
writeback_hard_ratio = 4                  # dirty_bytes = 4 × dirty_background_bytes
writeback_min_background_bytes = 268435456    # 256 MiB floor
writeback_max_background_bytes = 2147483648   # 2 GiB ceiling
writeback_benchmark_enabled = true        # measure device bandwidth on --apply
writeback_benchmark_bytes = 100663296     # 96 MiB micro-benchmark budget
writeback_pool_warn_bytes = 4294967296    # doctor WARN above ~4 GiB effective dirty pool
writeback_sysctl_path = "/etc/sysctl.d/99-sbh-writeback.conf"
```

Every section rejects keys it does not declare. `sbh config validate` lists unknown keys with a did-you-mean (legacy names such as `[monitor]`, `[scoring.weights]`, `per_volume_file_size_mb` or `policy.mode` get their replacement spelled out), the daemon warns about them at startup, and `sbh config validate --strict` or `[core] strict_config = true` turns them into errors. Path-typed values expand a leading `~` or `$HOME`. This example is parsed by the test suite, so it cannot drift from the code.

## Environment Variable Overrides

Operator automation can override configuration via environment variables. These take precedence over config file values.

| Variable | Controls |
| --- | --- |
| `SBH_UPDATE_ENABLED` | Enable/disable update checks |
| `SBH_UPDATE_BACKGROUND_REFRESH` | Background metadata refresh |
| `SBH_UPDATE_OPT_OUT` | Opt out of update system entirely |
| `SBH_UPDATE_METADATA_CACHE_TTL_SECONDS` | Cache TTL for update metadata |
| `SBH_UPDATE_METADATA_CACHE_FILE` | On-disk cache path |
| `SBH_UPDATE_NOTICES_ENABLED` | Human follow-up prompts in update output |
| `SBH_DASHBOARD_MODE` | Dashboard mode (`legacy` or `new`) |
| `SBH_DASHBOARD_KILL_SWITCH` | Emergency fallback to legacy dashboard |
| `SBH_PREDICTION_ENABLED` | Enable/disable predictive forecasting |
| `SBH_SCANNER_REPEAT_DELETION_BASE_COOLDOWN_SECS` | Base cooldown for repeat-deletion dampening |
| `SBH_SCANNER_REPEAT_DELETION_MAX_COOLDOWN_SECS` | Max cooldown for repeat-deletion dampening |
| `SBH_SYSTEM_TUNING_WRITEBACK_ENABLED` | Enable/disable kernel writeback tuning detection |
| `SBH_SYSTEM_TUNING_WRITEBACK_AUTO_APPLY_ON_INSTALL` | Apply writeback tuning during `sbh install` (root) |
| `SBH_SYSTEM_TUNING_WRITEBACK_TARGET_DRAIN_SECS` | Background dirty-pool drain target (seconds) |
| `SBH_SYSTEM_TUNING_WRITEBACK_HARD_RATIO` | `dirty_bytes` as a multiple of `dirty_background_bytes` |
| `SBH_SYSTEM_TUNING_WRITEBACK_MIN_BACKGROUND_BYTES` | Floor for `vm.dirty_background_bytes` |
| `SBH_SYSTEM_TUNING_WRITEBACK_MAX_BACKGROUND_BYTES` | Ceiling for `vm.dirty_background_bytes` |
| `SBH_SYSTEM_TUNING_WRITEBACK_BENCHMARK_ENABLED` | Allow the on-volume bandwidth micro-benchmark |
| `SBH_SYSTEM_TUNING_WRITEBACK_BENCHMARK_BYTES` | Byte budget for the bandwidth micro-benchmark |
| `SBH_SYSTEM_TUNING_WRITEBACK_POOL_WARN_BYTES` | Dirty-pool size above which `doctor` warns |

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
2. **Scanner thread** receives scan requests, selects `scanner.engine = "v2"` (the default since v0.4.32) or `"v1"`, scores discovered artifacts, and produces a ranked `DeletionBatch`. v2 adds opaque-tree pruning, a persistent candidate index, filesystem event invalidation where available, and pressure-gated reconciliation; v1 is the legacy full-descent directory walker kept as an opt-out.
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

There is one controller per mount. Default gains (`[pressure.controller]`): **Kp=0.25**, **Ki=0.08**, **Kd=0.02**, **Kf=0.8**, integral cap 100.0, hysteresis 1.0 point. The setpoint is `green_min_free_pct` (20% by default). The block below is `monitor::pid::FORMULAS`, and a test keeps this copy identical to the code:

```
error = target_free_pct - current_free_pct
kp_m = Kp * clamp(sqrt(total_bytes / reference_total_bytes), kp_scale_min, kp_scale_max)
integral = clamp(integral + error * dt, -integral_cap, integral_cap)   # frozen while the mount cannot act
derivative = 0.3 * (error - last_error) / dt + 0.7 * last_derivative
feedforward = Kf * clamp(1 - seconds_to_red / action_horizon_secs, 0, 1)   # 0 without a forecast
raw = kp_m * error + Ki * integral + Kd * derivative + feedforward
urgency = 1 - exp(-max(0, raw))
```

Three things make this a controller that cannot wind up while it has no actuator:

- **Capacity gain scheduling.** Errors are in percent, and one point is 55 GiB on a 5.5 TB pool but 1 GiB on a small root. `Kp` is scaled by `sqrt(total / reference_total_bytes)` (reference 1 TiB), clamped to `[0.5, 2] x Kp`, so large volumes answer a one-point error harder and tiny ones softer.
- **Forecast feedforward.** The EWMA forecast enters as a smooth term that grows from 0 at the action horizon (`pressure.prediction.action_horizon_minutes`, 30 by default) to `Kf` at zero seconds-to-red, instead of stepped urgency boosts. Urgency is monotone in the forecast: a nearer red never lowers it.
- **Anti-windup on actionability.** The integral is frozen while the mount's controller is observe-only (no root path on the device), idle after an empty pass, or recovering from a read-only or full filesystem. A mount sbh cannot act on no longer accumulates a Red urgency it could do nothing with; the integral also resets on every level change.

The `1 - exp(-x)` transform maps the raw output to a 0-1 range with a natural saturation curve: small errors produce proportionally small urgency, while large errors quickly approach 1.0 without overshooting.

Pressure levels are defined by free-space thresholds:

| Level | Default Free % | Scan Interval | Ballast Release | Max Delete Batch |
| --- | --- | --- | --- | --- |
| Green | > 20% | base interval | 0 files | 2 |
| Yellow | 14-20% | base/2 | 0-1 files | 5 |
| Orange | 10-14% | base/4 | 1-3 files | 10 |
| Red | 6-10% | base/8 | 3-5 files | 20 + urgency scaling |
| Critical | < 3% | 100ms | 10 files | 40 + urgency scaling |

Critical is triggered when free space drops below half the Red threshold (`red_min / 2.0`). At Red and Critical levels, delete batch sizes scale dynamically with PID urgency output, allowing the system to be more aggressive when pressure is rising rapidly versus slowly. At Critical, the controller issues maximum-urgency responses regardless of PID output.

When predictive forecasting is enabled, the time-to-red estimate feeds the controller's feedforward term: a forecast inside the action horizon (default 30 minutes) raises urgency smoothly, up to `Kf` at zero seconds, even while current pressure is only Yellow. This lets the system start scanning and releasing ballast *before* pressure actually reaches dangerous levels.

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

**Age** (default weight 0.20) uses an effective age timestamp that differs by entry type. For **files**, the modification time (`mtime`) is used because content change is what matters. For **directories**, the creation (birth) time is preferred when available, because directory `mtime` updates whenever any direct child is added or removed — making active build caches like `target/` appear perpetually young when `mtime` is used alone. Birth time reflects when the directory was actually created and is stable across rebuilds. If birth time is unavailable, `mtime` is used as a fallback.

The age-to-score curve is non-monotonic, peaking at 4-10 hours (the sweet spot for stale build artifacts) and dropping for very old files (which might be intentionally archived):

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
scaled = min(total_score / 1.5, 1.0)
logit = 3.5 * (scaled - 0.5) + 2.0 * (confidence - 0.5)
posterior_abandoned = sigmoid(logit)
```

Then the expected loss of each action is computed:

- **Loss of keeping an abandoned artifact**: `posterior * false_negative_loss` (default: 30.0)
- **Loss of deleting a useful artifact**: `(1 - posterior) * false_positive_loss` (default: 50.0)

The asymmetric defaults (50 vs. 30) encode the design principle that wrongly deleting something useful is costlier than failing to clean up something stale, while remaining aggressive enough to actually reclaim space under pressure.

These base losses are then adjusted by epistemic uncertainty, which combines entropy of the posterior with calibration confidence:

```
entropy = -(p * ln(p) + (1-p) * ln(1-p)) / ln(2)
uncertainty = 0.65 * entropy + 0.35 * (1 - calibration)
```

High uncertainty inflates the deletion loss more than the keep loss, making the system conservative when it isn't confident. The final decision follows a threshold policy: delete only when the keep-loss significantly exceeds the delete-loss *and* the posterior exceeds a minimum threshold that scales with uncertainty.

When uncertainty is too high to decide, the artifact is placed in a **Review** category rather than being silently kept or deleted. Review items are surfaced in `sbh scan` output and dashboard displays.

#### macOS Xcode DerivedData

On macOS, `sbh` recognizes immediate children of `~/Library/Developer/Xcode/DerivedData/` as `xcode-derived-data` cleanup candidates. The DerivedData root itself is not deleted as one broad target; per-project subdirectories are ranked independently and still pass through age, active-file, parent, and sacred-overlap checks.

DerivedData cleanup is classified as definite because Xcode regenerates indexes and intermediate build data on the next build. The tradeoff is latency: the first Xcode build after cleanup can be slower while those caches and indexes are rebuilt.

#### macOS Time Machine Local Snapshots

On macOS, `sbh status` estimates bytes retained by local Time Machine snapshots when APFS inventory data exposes a retained-snapshot estimate. The status output includes the exact reclaim command for the affected mount:

```bash
sudo tmutil thinlocalsnapshots / 9999999999999999 4
```

`sbh clean --thin-local-snapshots --dry-run` prints the same command, the selected mount, and the current estimated reclaimable bytes when available. `sudo sbh clean --thin-local-snapshots --yes` runs the macOS `tmutil thinlocalsnapshots` wrapper for `/` by default; pass `--local-snapshot-mount <MOUNT>` to target another APFS mount.

Thinning can take 30 seconds or longer. It asks macOS to free up to the estimated retained snapshot bytes, but the exact amount released is controlled by Time Machine and APFS. System-wide thinning requires sudo/root.

This matters for ballast release. If a local Time Machine snapshot references the ballast files, `sbh ballast release` can unlink those files immediately but `df` may not show the recovered space until the snapshots that still reference those blocks are thinned or expire. On default Time Machine settings that retention window is commonly about 24 hours. When `sbh` reports retained local snapshots, run the thin command above before relying on ballast release as visible free space.

#### macOS Electron App Caches

On macOS, `sbh` recognizes Electron application cache directories under `~/Library/Application Support/<app>/`. This covers common regenerated cache shapes used by Cursor, Claude Desktop, VS Code, Slack, Discord, and similar apps:

- `Cache/`
- `Service Worker/CacheStorage/`
- `Code Cache/`
- `GPUCache/`
- `IndexedDB/`
- `vm_bundles/`

These are classified as likely cleanup candidates, not sacred app data. The cache directory still passes through age, active-file, parent, and sacred-overlap checks before deletion, so a running app with open files can keep its active cache out of the deletion plan.

#### macOS Release Work Buildroots

On macOS, `sbh` recognizes stale staging directories that match `~/release-work/*[-_]buildroot` as `release-work-buildroot` candidates after they are at least seven days old. These are operator-created release build roots that are easy to forget after a release or verification run; the 2026-05-03 `~/release-work/mcp_agent_mail_rust_buildroot` incident left a 39 GB buildroot idle for 11 days.

The detector treats the exact `release-work/*[-_]buildroot` shape as a staging artifact even when the directory contains a copied `Cargo.toml`, but it still passes through active-reference, parent, bundle-extension, and sacred-overlap checks before deletion. Newer buildroots are kept until they cross the seven-day age threshold.

#### macOS User-Named Trash Directories

In volatile temporary roots such as `/tmp` and `/private/tmp`, `sbh` recognizes immediate children named `trash`, `trashed`, or `*-trash-*` as `user-named-trash` candidates. These names are ambiguous by design, so they are never auto-promoted straight to deletion; high-pressure scoring can only place them in **Review** unless another hard veto applies.

Before any review recommendation is surfaced, `sbh` scans three levels inside the candidate for stowaway state markers such as `.git/`, `.beads/`, `beads.db`, `*.db`, `*.sqlite`, and `*.sqlite3`. If one is found, the candidate is kept with an explicit sacred-overlap explanation instead of being treated as disposable trash.

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

`sbh` uses layered safety: six independent mechanisms, any one of which can veto a deletion regardless of what the others decide.

#### Layer 1: Protection Registry

Two protection mechanisms prevent cleanup of important directories:

- **Marker files**: Place a `.sbh-protect` file in any directory. That directory and all descendants are permanently excluded from scanning and deletion. `sbh protect <path>` creates this marker and records the path in `sacred.toml` next to the active config file so future scan/clean/daemon runs also load it through `scanner.protected_paths`. An empty marker file is valid; optional TOML metadata can record why it exists:
  ```toml
  reason = "year-end backup"
  added_by = "jemanuel"
  protected_at = "2026-05-07T03:50:00Z"
  ```
- **Config globs**: Shell-style patterns in `scanner.protected_paths` (e.g., `/data/projects/production-*`). Evaluated at scan time against every candidate path.
- **Sacred status**: `sbh status --sacred` lists active marker/config protections, the sacred catalog size, and how many current scan candidates overlap sacred paths.

#### Layer 2: Pre-Flight Safety Checks

Before any deletion is executed, an eight-point pre-flight check must pass:

1. **Path still exists**: Uses `symlink_metadata()` (doesn't follow symlinks) to verify the target hasn't been removed by another process since scoring.
2. **Not a symlink**: Symlinks are rejected because `remove_dir_all` follows symlinks into the target, which could destroy data outside watched directories.
3. **Parent is writable**: Checks effective write permission via `access(W_OK)` to catch read-only mounts and permission changes since scan time.
4. **No `.git/` directory**: A final safety net that prevents deletion of any directory containing a Git repository, even if all other signals suggest it's an artifact.
5. **Not a Cargo source root**: A direct `Cargo.toml` without Cargo build-output markers vetoes deletion, even when a directory name matches `target`, `target_*`, `*_target`, or `*-target`. Broad target-like names outside temporary storage also require Cargo build-output markers before they can become deletion candidates; `/private/tmp` target caches still require open-file checks.
6. **No stowaway sacred state**: Depth-limited scans reject cleanup candidates that contain protected marker directories or database state such as `.git/`, `.beads/`, `*.db`, `*.sqlite`, or `*.sqlite3`.
7. **Not open by any process**: The deletion executor checks platform open-file evidence before reclaiming a target tree. Linux scans `/proc/*/fd` symlinks; macOS uses the PAL/libproc open-file collector. If that pre-flight evidence is incomplete, the batch fails conservative instead of deleting an in-use directory.
8. **No active-target lease**: The executor probes the stable kernel lock derived from the candidate and its ancestors, both during pre-flight and immediately before mutation. A locked target is skipped even when its metadata is expired, over quota, unreadable, or tampered; the watchdog cancels the owner and deletion waits for the kernel to release the lock. This closes the gap where open-file evidence can miss build outputs between compiler phases.

Any single check failure causes the candidate to be skipped (not failed), so it doesn't trip the circuit breaker.

#### Layer 3: Circuit Breaker

The deletion executor tracks consecutive failures. After 3 consecutive deletion errors (not skips), the circuit breaker trips and halts the entire batch. The daemon waits 30 seconds before retrying. This prevents cascading failures when the filesystem is in a degraded state (e.g., hardware errors, NFS timeouts).

#### Layer 4: Policy Engine Gates

As described above, the progressive delivery system (observe/canary/enforce) ensures deletions are validated at each stage before reaching full production. The canary mode caps deletions at 10 per hour, limiting blast radius during initial rollout.

#### Layer 5: Guardrails and Drift Detection

The guardrail system continuously validates that the forecasting and scoring pipeline is well-calibrated. If predictions drift from reality, the system automatically falls back to safe mode. See the Guardrails section below for details.

#### Layer 6: Repeat-Deletion Dampening

When an artifact path is deleted and then recreated (common with build directories in active projects), the dampening tracker applies exponential-backoff cooldowns to prevent deletion loops:

```
cooldown = base_cooldown * 2^(cycle_count - 1), capped at max_cooldown
```

The first deletion of a given path has no cooldown. After the second deletion, cooldown starts at the base value and doubles with each subsequent cycle.

| Parameter | Config Key | Default |
| --- | --- | --- |
| Base cooldown | `scanner.repeat_deletion_base_cooldown_secs` | 300s (5 min) |
| Maximum cooldown | `scanner.repeat_deletion_max_cooldown_secs` | 3600s (1 hour) |

Red and Critical pressure bypasses all dampening. Disk safety takes priority over anti-churn protection.

#### Layer 7: Quarantine-First Deletion and `sbh undo`

Hard vetoes make the known mis-scorings impossible; they cannot make the next one recoverable. At Green there is time to keep the bytes around, so the daemon does: a Green batch (and every `sbh clean` unless `--no-quarantine`) does not unlink a candidate, it renames it into `<root>/.sbh/quarantine/<decision-id>/<basename>` on the same filesystem, next to a `<decision-id>.json` record naming the original path. The quarantine root carries a `.sbh-protect` marker so no scan ever scores it. The event is still `artifact_delete` with `"quarantined": true` and no bytes freed.

Quarantined space is reclaimable on demand:

| Condition | What happens |
| --- | --- |
| Green or Yellow | Once a minute, entries older than `scanner.quarantine_ttl_hours` are removed for good and the store is capped at `scanner.quarantine_max_bytes_pct` of the volume (oldest first). |
| Orange, Red, Critical | The mount's quarantines are drained oldest-first on the tick, ahead of any new deletion: that space was decided already and costs no scoring. New candidates are removed for good (`Unlink`). |
| `sbh emergency` | Drains every quarantine under the scan roots before it scans anything. |

Restore with `sbh undo <decision-id>` (the id is on the `[SBH-QUARANTINE]` line, in `sbh explain`, and in `sbh undo --list`), `sbh undo --path <original>`, or `sbh undo --all-since 2h`. A restore is a rename back, byte-identical; it refuses when the original path exists again unless `--force-suffix`, which restores beside it as `<name>.restored-<decision-id>`. The ledger marks the decision `restored`.

A candidate that cannot be quarantined (different filesystem from the root, unusable store) is removed for good and the fallback is logged as `quarantine_unavailable` with its reason. `status` shows the bytes held per mount in the Reserve column; `stats` reports `quarantined_count` and `quarantined_bytes` and excludes held bytes from `total_bytes_freed`.

| Parameter | Config Key | Default |
| --- | --- | --- |
| Quarantine on/off | `scanner.quarantine_enabled` | `true` |
| Time an entry is held | `scanner.quarantine_ttl_hours` | 24 |
| Size cap per volume | `scanner.quarantine_max_bytes_pct` | 5 |

The tracker periodically prunes entries whose last deletion is older than `max_cooldown`, preventing unbounded memory growth in long-running daemon sessions.

Source: `src/daemon/loop_main.rs`

### The Ballast System in Depth

Ballast files are pre-allocated sacrificial space that can be released instantly when disk pressure spikes, buying time for the scanner to find and delete actual artifacts.

#### Provisioning

Each watched volume gets its own ballast pool. Files are named `SBH_BALLAST_FILE_00001.dat` through `SBH_BALLAST_FILE_NNNNN.dat`, with a 4096-byte JSON header containing the magic string `SBH_BALLAST_v1`, file index, creation timestamp, and size metadata.

On macOS, service scope controls the default pool path: user LaunchAgents use `~/Library/Application Support/sbh/ballast.bin`; system LaunchDaemons use `/private/var/sbh/ballast.bin`. This path is still a ballast pool directory in the current multi-file implementation, and `[paths].ballast_dir` remains the override for custom placement.

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

On macOS/APFS, local Time Machine snapshots can retain the released ballast blocks. In that case the release operation succeeds, but apparent free space in `df`, Finder, and some system APIs may not increase until one of these happens:

- The relevant local snapshots are thinned with `sudo tmutil thinlocalsnapshots <mount> 9999999999999999 4`.
- The snapshot retention window expires, commonly about 24 hours with default Time Machine behavior.

When local snapshots are present, `sbh ballast release` emits a warning for the affected mount. Treat that warning as part of the incident workflow: thin snapshots, then re-run `sbh status` or `df -h` to confirm that APFS made the released blocks visible as free space.

#### Replenishment

When a mount has been Green for the full `ballast.replenish_cooldown_minutes`, the replenishment controller rebuilds its missing ballast files one per cycle, at most one every five minutes, while the volume stays above the headroom floor. The cooldown is observed on every daemon tick, whatever the mount is doing: a Yellow or Orange excursion of more than three ticks (a compilation burst is forgiven, a real pressure episode is not) restarts it, and any release resets it. The controller also counts the files it released on each mount since the last completed Green cooldown, so the reserve being rebuilt is visible; a reserve that is short for any other reason (an operator deleted files, a floor-limited provision) is rebuilt the same way, up to the configured count.

All ballast operations (provision, release, replenish, verify) are serialized per-volume via `flock()` on a lockfile, preventing races between the daemon and CLI commands. Read paths never mutate a pool: `sbh ballast status` opens the configured directory without creating it and reports files outside the configured index range as **orphans** instead of deleting them; only `provision` and `replenish` prune orphans, under the lock.

The daemon manages one pool per eligible mount, not just the configured `ballast_dir`: every mount that hosts a scan root, a special location, the state dir or the ballast dir gets `<mount>/.sbh/ballast` (RAM-backed, network, read-only and override-disabled mounts are skipped with a reason). `sbh ballast status` lists every such volume with its health, file counts, releasable bytes and skip reason, and `--json` carries them under `volumes`, so a pool the daemon built on another volume is never invisible to the operator.

### VOI Scan Scheduling

Fixed-interval full scans waste IO bandwidth when most directories haven't changed. For v1, the Value-of-Information (VOI) scheduler allocates a limited scan budget (default: 5 paths per cycle) to the paths most likely to yield reclaimable space. For v2, the same pressure signal decides when to use the persistent candidate index, event-dirty roots, or bounded reconciliation instead of recursively walking every configured root.

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

### Special Location Monitoring

RAM-backed filesystems (`/dev/shm`, tmpfs, ramfs) require tighter monitoring than disk-backed volumes because they directly compete with application memory. The special location monitor runs independent scan loops with per-location parameters:

| Location Type | Free Buffer Target | Scan Interval | Priority |
| --- | --- | --- | --- |
| `/dev/shm` | 20% | 3s | 255 |
| ramfs | 18% | 4s | 220 |
| tmpfs | 15% | 5s | 200 |
| User-defined (`/tmp`, `/data/tmp`) | 15% | 5s | 155-160 |
| Custom paths | 15% | 5s | 140 |

Priority determines scan order when multiple locations need attention in the same cycle. Higher-priority locations are checked first.

The registry asks the active Platform Abstraction Layer (PAL) for mount inventory. Linux reads `/proc/mounts`; macOS uses its PAL mount inventory from `statfs`/`getmntinfo` and APFS metadata. Fallback entries for `/tmp` and `/data/tmp` are added when they are not already covered. Operator-provided custom paths can override auto-discovered defaults. Duplicate paths are deduplicated, with later entries taking precedence.

#### Swap-Thrash Detection

The daemon monitors swap usage relative to available RAM. When swap utilization exceeds 70% while at least 8 GiB of RAM remains free, the system flags a swap-thrash risk. This condition indicates the host experienced memory pressure and is now paging memory back in slowly, which degrades IO performance for both scanning and deletion.

Swap-thrash warnings are rate-limited to one per 15-minute window to avoid log noise during sustained pressure.

```bash
# View swap status in the status report
sbh status --json | jq '.memory'
```

Source: `src/monitor/special_locations.rs`, `src/daemon/loop_main.rs`

### Temp Artifact Fast-Track

Under Orange or Red pressure, recognized temporary artifacts in `/tmp`, `/var/tmp`, `/data/tmp`, and `/private/tmp` receive an adjusted age that allows them to cross the deletion threshold sooner. This accelerates cleanup of build debris in temp directories during pressure spikes without bypassing the scoring system entirely.

Constraints:
- A 2-minute minimum observed age safety floor prevents deletion of very recently created files, even under pressure.
- `NodeModules` and `PythonCache` artifact categories are excluded from fast-tracking because they may contain active dependency trees.
- Only artifacts with high-confidence pattern matches (>= 0.85 name confidence or specific known patterns like `cargo-target-prefix`, `agent-ft-suffix`, `tmp-codex`) qualify.

Green and Yellow pressure levels do not trigger fast-tracking.

Source: `src/daemon/loop_main.rs`

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

### Notification Channels

The daemon dispatches alerts through four notification channels, each with independent severity filtering:

| Channel | Transport | Default Min Level |
| --- | --- | --- |
| Desktop | `notify-send` (Linux) / `osascript` (macOS) | Orange |
| Webhook | HTTP POST via `curl` (5-second timeout) | Red |
| File | JSONL append to `~/.local/share/sbh/notifications.jsonl` | Info |
| Journal | systemd/launchd stdout and stderr capture | Warning |

Default active channels are `journal` and `file`. Desktop and webhook channels are opt-in.
On macOS, the desktop channel uses `osascript -e 'display notification ...'` as the
first supported user-notification path. Red and Critical events are still
throttled per event category by `urgent_notify_interval_secs` (default five
minutes), so a Critical+Critical memory/disk event can alert promptly without
spamming Notification Center.

**Notification event types:** `PressureChanged`, `PredictiveWarning`, `CleanupCompleted`, `BallastReleased`, `BallastReplenished`, `BehaviorEmergency`, `DaemonStarted`, `DaemonStopped`, `Error`.

**Severity levels (ordered):** Info, Warning, Orange, Red, Critical. Each channel only dispatches events at or above its configured `min_level`.

The webhook channel supports template strings with placeholder substitution:

```toml
[notifications.webhook]
enabled = true
url = "https://hooks.example.com/sbh"
min_level = "red"
template = '{"text": "sbh: ${SUMMARY}", "level": "${LEVEL}", "mount": "${MOUNT}", "free_pct": "${FREE_PCT}"}'
```

Source: `src/daemon/notifications.rs`

### Zero-Write Emergency Mode

When a disk is at 99%+ utilization, normal operations may fail because they need to write temporary files, state, or logs. `sbh emergency` operates in a zero-write mode that avoids all disk writes:

- No SQLite writes (database might be on the full disk).
- No JSONL writes (log file might be on the full disk).
- No state file updates.
- No configuration file reads that might trigger cache writes.
- Scoring uses in-memory defaults only.
- Output goes directly to stdout/stderr.

The emergency command scans the specified paths, scores candidates using the standard multi-factor engine, and presents them for immediate deletion. With `--yes`, it executes deletions immediately without interactive confirmation, prioritizing the highest-scoring candidates until the target free space is reached or all candidates are exhausted. Because no config is read, `--min-age <MINUTES>` (default 5) is the only age floor: artifacts modified more recently are left alone, and `--min-age 0` reclaims fresh builds too. Every candidate is printed with its decision id (`id <hex>` in the plan, `candidates[].decision_id` in `--json`), the same id `sbh scan` and `sbh clean` would record, so a later `sbh explain --id` can be matched against what emergency acted on.

**Emergency escalation:** unlike `sbh clean`, emergency mode also acts on candidates whose decision-theoretic outcome is `Review` (score cleared the threshold and nothing vetoed them, but the keep-vs-delete loss margin was too ambiguous for unattended deletion). `Review` means "a human should look" — in emergency mode the human *is* looking, via the interactive confirmation or an explicit `--yes`. Without this escalation, a candidate corpus that is 100% `Review` would make the last line of defence a silent no-op on a critically full disk. Unambiguous `Delete` decisions are still executed first; every hard safety rail (vetoes, sacred paths, `.sbh-protect` markers, and the `.git`/Cargo-manifest/source-tree/open-file/active-lease pre-flight checks) applies unchanged.

A completely full disk is precisely the situation where most cleanup tools fail, since they need to write temp files or state. By reducing to pure in-memory scoring and direct unlink calls, `sbh emergency` can recover a system that nothing else can touch.

### Scanner Indexes

The live daemon has two index-related code paths:

- `src/scanner/index.rs` is the v2 daemon candidate index. It stores one record per candidate root keyed by filesystem identity, persists to `scanner-index-v2.json`, records event generations, and keeps per-candidate deletion-failure backoff. It is active only when `scanner.engine = "v2"`.
- `src/scanner/merkle.rs` is an older Merkle-tree index implementation. It remains tested library code, but it is not the live daemon scanner index and should not be read as the current daemon behavior.

v2 uses the candidate index to avoid cold full walks under pressure. At Green or Yellow pressure with no dirty event roots, it can report a no-op scan without recursively walking configured roots. Under Orange or higher pressure, it ranks persisted candidates first and only runs bounded reconciliation when the index or event state requires it. All deletion still goes through the same policy engine and final pre-flight safety checks.

What feeds the index is platform-specific, and the daemon says which at startup (`scanner_events: backend=... complete=... reason=...` in the activity log, `sbh scan --json` capability fields):

- **Linux:** recursive `inotify` watches over the configured roots, planned against `scanner.event_watch_budget` (8,192 by default). When the budget runs out the uncovered roots are marked dirty and the maintenance pass reconciles them; on the operator workstation `/data/projects` exhausts the budget, so that root is always dirty. `fanotify` is **not implemented**: the crate forbids `unsafe`, the safe wrapper available to it does not report file handles (`FAN_REPORT_FID`), and filesystem-wide marks need `CAP_SYS_ADMIN`, which a user-scope service does not have. The capability probe reports it as deferred.
- **macOS and everything else:** reconciliation only. There is no FSEvents backend; the bound on staleness is the maintenance cadence (`pressure.maintenance_interval_secs`) plus the pressure-driven passes. An FSEvents backend through a safe crate is a decision recorded on bd-rc-master-ajg1.8.5 and needs the macOS CI lane to prove it before it ships.

For validation and A/B artifacts, `sbh scan --json` reports `scanner_engine`, `scanner_dispatch`, `opaque_pruning`, `opaque_pruned_dirs`, `scanned_entries`, and nullable `process_cpu_micros` alongside the existing candidate totals. Daemon `scan_complete` activity events also include the selected dispatch, pruning state, dirty event-root count, index generation, indexed-record count, candidate bytes seen, and timeout state in their `details` payload. These fields are intended to make v1/v2 scan captures auditable without scraping human output.

The in-repo scanner-v2 validation tests emit focused JSON artifacts for synthetic v1/v2 walk effort and safety parity, event-overflow reconciliation fallback, and memory-pressure transition latency. v2 has been the default engine since v0.4.32 (it is what the production fleet runs and it is required for structural detection of caches under arbitrary names, such as Go's `GOCACHE`); the A/B evidence measured on 2026-09-02 is in `docs/internal/scanner-ab-2026-09-02.md` and does not yet meet the design document's promotion criteria (a one-shot `sbh scan` of a large project tree costs v2 3.4x the CPU of v1 because of its opaque-root size probes, and the daemon's v2 steady state was a replay hot loop rather than a cheap rescan), so `engine = "v1"` remains available as the rollback.

For a live A/B capture, run the same scan root twice with only the engine override changed:

```bash
SBH_SCANNER_ENGINE=v1 sbh --json scan /data/projects --top 200 > scan-v1.json
SBH_SCANNER_ENGINE=v2 sbh --json scan /data/projects --top 200 > scan-v2.json
```

Compare `scanned_entries`, `process_cpu_micros`, candidates, vetoes/explanations, and matching daemon `scan_complete` activity events before considering v2 promotion.

The v2 checkpoint contains a version, root/config fingerprint, event generation, serialized candidate records, and a SHA-256 integrity hash. If it is missing, stale, or corrupt, v2 rebuilds conservatively through bounded reconciliation rather than trusting stale state.

Source: `src/scanner/index.rs`; legacy Merkle implementation: `src/scanner/merkle.rs`

### Parallel Directory Walker

The walker is the scanner's "eyes": it discovers candidate files and directories, collects structural markers for the scoring engine, and integrates with the protection system to skip `.sbh-protect`ed subtrees.

#### Work-Stealing Parallelism

The walker uses a bounded work queue (capacity 4096) shared across `N` worker threads (configurable via `scanner.parallelism`). Root paths are seeded into the queue, and each worker pulls a directory, processes its entries, and enqueues discovered subdirectories back onto the shared queue. Workers that find an empty queue wait briefly (50ms timeout) before checking whether all work is complete. This design provides natural load balancing — workers that finish fast directories steal work from threads processing slower ones — without requiring explicit work-stealing data structures.

An atomic `in_flight` counter tracks work items that have been dequeued but not yet processed. When the last item completes (counter reaches zero), workers exit. Results flow through an unbounded channel for throughput: the walker should never block on result delivery.

#### Per-Directory Iteration Cap

Directories with tens of thousands of entries (e.g., `/data/tmp` with 60K+ children, `node_modules` flats) can monopolize a worker thread for seconds. Each directory is capped at 65,536 child entries. Structural signals (`.git`, `Cargo.lock`, `deps/`, `build/`) are detected early during iteration, so the cap rarely affects scoring accuracy. This prevents any single pathological directory from starving other workers.

#### Open-File Detection

Before any candidate is scored for deletion, the walker collects active-reference evidence across visible processes. On Linux, this scans `/proc/*/fd` symlinks to build a set of `(device_id, inode)` pairs representing currently open files. On macOS, it uses PAL/libproc process, fd, executable, and mmap probes to produce the same safety signal. Two budget limits prevent this scan from hanging the daemon on busy machines:

| Budget | Limit | Purpose |
| --- | --- | --- |
| Time | 5 seconds | Prevents hanging on machines with many processes |
| PIDs | 50,000 | Caps scan even if individual PIDs are fast |

If either budget is exhausted, the scan returns a partial set. The system fails conservative: a partial open-file set means some open files might be missed, but the pre-flight safety checks provide a second layer of defense.

During scoring, an `OpenPathCache` provides memoized subtree-open checks. For each candidate directory, it walks the directory tree checking inodes against the open set, caching results so that parent directories are not re-scanned for sibling candidates.

#### Cross-Device and Symlink Safety

Two invariants prevent the walker from escaping its intended scope:

- **Cross-device guard**: Unless `scanner.cross_devices` is explicitly enabled, the walker records each root path's device ID at seed time. When processing subdirectories, any entry on a different device (i.e., a mount point) is skipped entirely. This prevents accidentally walking into large foreign filesystems mounted under a watched path.

- **Symlink safety**: By default, the walker uses `symlink_metadata()` (lstat) rather than `metadata()` (stat), so symlinks are examined without following them. Symlinks to directories are not enqueued for traversal, preventing symlink loops and escapes outside watched paths. The pre-flight safety checks independently reject symlinks at deletion time.

Source: `src/scanner/walker.rs`

### Signal Handling and Daemon Lifecycle

The daemon responds to Unix signals for graceful lifecycle management. All signal flags are polled by the main loop each iteration rather than processed in signal handler context, avoiding async-signal-safety concerns.

| Signal | Effect |
| --- | --- |
| `SIGTERM` / `SIGINT` | Graceful shutdown: completes the current operation, writes final state, exits cleanly |
| `SIGHUP` | Configuration reload: re-reads `config.toml` and applies changes without restart |
| `SIGUSR1` | Immediate scan trigger: bypasses the VOI scheduler and runs a full scan on the next iteration |

Signal registration uses the `signal-hook` crate for safe, portable signal handling. Registration is best-effort: failures are logged to stderr but do not prevent daemon startup. The `SignalHandler` can also be triggered programmatically (e.g., by the watchdog timeout or error escalation logic) for shutdown requests that originate from within the daemon.

#### Control Socket

A running daemon also answers requests on a Unix domain socket,
`control.sock` beside `state.json` (mode `0600`, so only the daemon's user
can connect). One JSON line in, one JSON line out:

```text
{"cmd": "ping", "args": {}, "token": "<32 hex characters>"}
{"ok": true, "result": {"pid": 4242, "started_at": "...", "version": "0.5.1", "uptime_secs": 91, "policy_mode": "enforce"}}
{"ok": false, "result": null, "error": {"code": "unauthorized", "message": "token does not match the running daemon's lock file"}}
```

The token is minted at every start and written into `daemon.lock`, so a
client that can read the lock file can talk and a client left over from a
previous boot cannot. Every command that changes state is logged with the
caller's uid and pid.

| Command | What it does |
| --- | --- |
| `sbh daemon ping` | Identity and liveness from the process itself: pid, start time, version, uptime, policy mode |
| `sbh status` | Asks the daemon to rewrite `state.json` first; the JSON reports `"source": "socket"` (or `"state_file"` when no daemon answered) |
| `sbh daemon scan-now` | Queues a forced scan of the configured roots on the next tick (the `SIGUSR1` path) |
| `sbh daemon reload` | Re-reads the config (the `SIGHUP` path) |
| `sbh policy status\|promote\|demote` | Shows or moves the policy mode (observe → canary → enforce and back) and persists the new mode to `[policy] initial_mode` after backing the config file up |
| `explain {id}` (protocol only) | The decision ledger record for a decision id, read-only |
| `ballast {release: N \| replenish: true}` (protocol only) | Releases or rebuilds ballast through the coordinator |
| `sbh daemon shutdown` | A clean stop; the socket file is removed as part of it |

The socket serves eight connections at a time, ten requests per second,
and drops request lines over 64 KiB. `[core] control_socket_enabled = false`
turns it off, in which case the daemon answers signals and the state file
only and `sbh daemon ping` explains that no socket exists.

#### Systemd Watchdog

When running as a system-scope systemd service (`Type=notify`), the daemon sends `sd_notify` heartbeats at a configurable interval (default: `WatchdogSec=60`). If the main loop stalls (blocked IO, deadlock, infinite loop), systemd detects the missing heartbeat and restarts the service automatically via `Restart=on-failure`. The restart delay (`RestartSec=10`) prevents tight restart loops.

User-scope services use `Type=simple` instead, since user session supervisors typically do not support the `sd_notify` protocol.

#### Shutdown Coordinator

On receiving a shutdown signal, the daemon runs this sequence:

1. Tells the service manager an orderly stop has begun (`sd_notify STOPPING=1`).
2. Sets the shutdown flag (atomic boolean, visible to all threads) and drops the
   work channels; the scanner and executor stop at their next check.
3. Joins the scanner and executor within one shared 25-second budget, five
   seconds under the unit's `TimeoutStopSec=30`; a worker still running at the
   deadline is abandoned rather than trapping the stop behind it.
4. Writes the final `state.json` (`stopped_at`, `exit_reason`, final counters)
   so `sbh status` reports a clean exit rather than a stalled daemon.
5. Logs `daemon_stop`, flushes the logger, releases the lock and exits with
   code 0.

`state.json` also carries a `threads` block (`monitor`, `scanner`, `executor`,
`logger`) with each thread's status and seconds since its last heartbeat; a
worker is reported `stalled` after 60 seconds without a beat and `dead` when
its thread has exited.

Source: `src/daemon/signals.rs`, `src/daemon/loop_main.rs`

### Daemon Self-Monitoring

The self-monitor tracks daemon health from within, providing introspection data for the dashboard's Diagnostics screen and for `sbh status` queries.

#### Thread Heartbeats

Each worker thread (monitor, scanner, executor, logger) periodically calls a heartbeat function that updates a monotonic timestamp. The self-monitor checks these timestamps against a staleness threshold (60 seconds). If a thread misses its window, its status transitions from `Running` to `Stalled`. If a thread panics and is not respawned, its status becomes `Dead` with the captured error message.

The heartbeat uses a process-local monotonic clock (`Instant`) rather than `SystemTime` to avoid false readings when the system clock is adjusted (NTP corrections, daylight saving changes, manual adjustments).

Thread statuses are reported in the state file and displayed on the dashboard Diagnostics screen (`key 7`).

#### RSS Memory Tracking

The daemon samples its own RSS through the PAL `self_stats()` method on each state file write. Linux uses `/proc/self` data; macOS uses Mach task and libproc resource usage. If RSS exceeds the configured limit (256 MB by default, matching the systemd `MemoryMax` directive on Linux), a warning is logged to stderr. The RSS value is included in the state file for external monitoring tools.

The 256 MB limit ensures `sbh` never competes with build workloads for memory. On machines with constrained RAM, the limit can be adjusted via the systemd unit file or by direct configuration.

#### State File Protocol

The state file (`state.json`) is the primary mechanism for CLI-to-daemon communication. It is written atomically (write to `.tmp`, then `rename()`) to prevent readers from seeing partial writes.

| Parameter | Value | Purpose |
| --- | --- | --- |
| Write interval | 30 seconds | Balances freshness with IO overhead |
| Stale threshold | 90 seconds | `>= 2x` write interval, prevents false "daemon absent" reports |
| Write method | Atomic rename | Guarantees CLI always reads a complete JSON document |

The schema uses `#[serde(default)]` on all fields, so minor version differences between daemon and CLI (e.g., during a rolling update) degrade gracefully: new fields are ignored by old CLI versions, and missing fields use defaults rather than causing parse failures. The dashboard adapter layer detects schema drift and surfaces warnings rather than crashing.

Source: `src/daemon/self_monitor.rs`

### Service Management

`sbh` generates platform-native service configurations for both Linux (systemd) and macOS (launchd), with security hardening appropriate to each platform.

#### Systemd (Linux)

The generated systemd unit file includes several layers of hardening:

**Scheduling (lowest priority):**
- `Nice=19` — lowest CPU scheduling priority
- `IOSchedulingClass=idle` — only uses disk IO when no other process needs it
- `IOSchedulingPriority=7` — lowest IO priority within the idle class

This keeps `sbh` at background priority. System-scope systemd units also add a cgroup CPU quota; v2 adds in-process scan budgeting so a relaxed or stale service override does not make the scanner unbounded.

**Security sandboxing (system scope only):**
- `ProtectSystem=strict` — mounts the entire filesystem read-only except explicitly allowed paths
- `ReadWritePaths=` — only the data directory and watched paths are writable
- `NoNewPrivileges=true` — prevents privilege escalation via setuid/setgid binaries
- `ProtectKernelTunables=true` — blocks writes to `/proc/sys`, `/sys`
- `ProtectControlGroups=true` — prevents cgroup manipulation
- `RestrictSUIDSGID=true` — blocks creation of setuid/setgid files
- `LimitNOFILE=4096` — caps file descriptor count

**Resource limits:**
- `MemoryMax=256M` — hard memory ceiling enforced by the cgroup controller
- `CPUQuota=10%` — limits CPU usage to 10% of one core

**Lifecycle:**
- `Type=notify` (system scope) with `WatchdogSec=60` for automatic restart on stall
- `Type=simple` (user scope) for compatibility with user session managers
- `Restart=on-failure` with `RestartSec=10` and `TimeoutStopSec=30`
- `ExecReload=/bin/kill -HUP $MAINPID` for live configuration reload

User-scope services skip `ProtectSystem` and kernel/cgroup protections because these directives are not available in user session scope.

#### Launchd (macOS)

The generated launchd plist provides equivalent lifecycle management:

- `RunAtLoad=true` — starts the daemon on login (user agent) or boot (system daemon)
- `KeepAlive` with `SuccessfulExit=false` — auto-restarts on non-zero exit, stays stopped on clean shutdown
- `ThrottleInterval=60` — minimum 60 seconds between restart attempts
- `Nice=19` — lowest scheduling priority
- `LowPriorityIO=true` — marks all IO as low-priority

User agents install to `~/Library/LaunchAgents/`, system daemons to `/Library/LaunchDaemons/`. Log output goes to `~/Library/Logs/sbh/` (user) or `/var/log/sbh/` (system).

Source: `src/daemon/service/systemd.rs`, `src/daemon/service/launchd.rs`

### Kernel Writeback Tuning

Running the daemon at `Nice=19` + `IOSchedulingClass=idle` keeps *sbh* out of the way, but it cannot fix the most common interactive-latency problem on a busy build host, because that problem is in the kernel, not in any one process.

On a high-RAM machine the default percentage-based dirty-page limits are too coarse. With `vm.dirty_ratio=10` on a 247 GiB host the kernel lets roughly **24 GiB** of dirty pages accumulate before it throttles writers, and `vm.dirty_background_ratio=5` waits for ~12 GiB before starting background flush. Those huge pools then flush in **bursts** through kernel writeback threads (`btrfs-endio-write` and friends) that run *outside* the ionice class of the build processes that produced the writes — so even with every build `ionice`-idled, the interactive terminal stalls behind each multi-GiB flush.

The fix is to replace the ratio knobs with **absolute byte limits** (`vm.dirty_bytes` / `vm.dirty_background_bytes`) so writeback is continuous and gentle instead of bursty. sbh sizes those limits to the backing device's write bandwidth:

```
dirty_background_bytes = clamp(bandwidth × target_drain_secs, min, max)   # default drain 1.0s
dirty_bytes            = hard_ratio × dirty_background_bytes               # default ratio 4
```

Bandwidth is **measured** by a short, bounded, non-destructive on-volume micro-benchmark (random data so btrfs/zfs cannot compress or dedup it away); `--no-benchmark` falls back to an NVMe/SSD/HDD device-class heuristic. At a typical ~512 MiB/s SSD this yields `dirty_background_bytes=512 MiB` / `dirty_bytes=2 GiB`.

```bash
# Show the recommendation (read-only; uses the device-class heuristic)
sbh tune

# Measure bandwidth, apply to the running kernel, and persist (root)
sudo sbh tune --apply --yes

# Flag a dangerous configuration without changing anything (WARN, escalated on btrfs/zfs)
sbh doctor --system

# Undo: restore the backup of the sbh snippet (or remove it) and reload sysctl
sudo sbh tune --revert-writeback
```

`--apply` writes the live `/proc/sys/vm` knobs **and** persists a backup-first, self-documenting `/etc/sysctl.d/99-sbh-writeback.conf`, validates it with `sysctl -p`, and warns about any later-loading `sysctl.d` file that would override the byte limits with a ratio (setting `vm.dirty_bytes` auto-zeros `vm.dirty_ratio` — they are mutually exclusive). `sbh install` applies the same tuning automatically when run as root.

**The daemon never applies this at runtime.** The hardened system-scope unit sets `ProtectKernelTunables=true`, which makes `/proc/sys` read-only for the daemon, and silently mutating global kernel state from a background daemon would violate sbh's explainability and least-surprise principles. All writeback mutation is operator-invoked (or install-time), root-gated, backup-first, and reversible. On platforms without tunable writeback limits (macOS) the recommendation is simply not generated and `doctor --system` reports not-applicable.

Configure under `[system_tuning]` (see the config example) or via `SBH_SYSTEM_TUNING_WRITEBACK_*` environment variables.

`sbh uninstall` deliberately does **not** revert this tuning — the byte limits are a beneficial host setting that should outlive sbh, and undoing them would silently reintroduce the write-burst stalls. Run `sudo sbh tune --revert-writeback` first if you want the original `vm.dirty_*` behavior back.

Source: `src/tuning/writeback.rs`, `src/tuning/bandwidth.rs`, `src/platform/linux/writeback.rs`

### Supply Chain Verification

Binary releases, installers, and updates pass through a verification pipeline before installation. The pipeline has three layers where applicable: mandatory checksum verification, optional cryptographic signature verification, and macOS binary trust checks.

#### SHA-256 Checksums

Every release artifact ships with a `.sha256` checksum file. During install or update, the pipeline downloads the artifact, computes its SHA-256 hash, and compares it against the expected value from the checksum file. A mismatch halts installation with a structured `IntegrityDecision::Deny` outcome that includes both expected and actual hashes for diagnostics.

The checksum parser handles both bare hex digests and BSD-style `sha256sum` output (hash followed by filename), normalizing to lowercase hex for comparison.

#### Sigstore Signature Verification

When a Sigstore bundle (`.sigstore` file) is present alongside the release artifact, the pipeline upgrades to cryptographic signature verification using `cosign`. The verification policy is determined by the presence of the bundle:

| Bundle Present | Policy | Behavior |
| --- | --- | --- |
| No | `Disabled` | Checksum-only verification |
| Yes | `Required` | Must pass `cosign verify-blob` or install is denied |

If the `cosign` binary is not installed on the system, the pipeline probes for it at verification time. When `cosign` is absent and the policy is `Required`, the outcome is `Deny` with reason code `sigstore_required_unavailable`. When the policy is `Optional`, missing `cosign` degrades to checksum-only with a warning.

#### macOS Binary Trust Checks

On macOS, the Unix installer and self-update path also run `codesign --verify --strict --verbose=2` and inspect `codesign --display --verbose=4` output before installing or replacing `sbh`. This rejects unsigned, malformed, or incorrectly signed binaries unless they are signed by the expected `Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)` identity and `TeamIdentifier=AU8V2Z6NKY`.

#### Bypass and Audit Trail

The `--no-verify` flag explicitly bypasses release-binary artifact verification, including checksum, signature, and macOS trust checks. This is a loud operation: the outcome includes `bypass_used: true`, a warning message, and reason code `verify_bypass`. The structured `VerificationOutcome` captures the full decision trail (bypass, checksum status, signature status, reason codes, warnings) for audit logging. On macOS, `sbh install --no-verify --offline <bundle-manifest.json>` forwards the same unsafe bypass into the release-binary install path; use it only for deliberate recovery from a trusted local bundle.

For airgapped environments, the `--offline` flag accepts a local bundle manifest, allowing updates without network access while maintaining checksum verification.

Source: `src/cli/mod.rs`, `src/cli/assets.rs`

### Uninstall and Cleanup Modes

`sbh uninstall` supports five cleanup modes that control how aggressively the system is cleaned up, from conservative to full purge:

| Mode | Binary | Service | Config | Data/Logs | Assets | Ballast |
| --- | --- | --- | --- | --- | --- | --- |
| **Conservative** (default) | removed | removed | kept | kept | kept | kept |
| **KeepData** | removed | removed | removed | kept | removed | removed |
| **KeepConfig** | removed | removed | kept | removed | removed | removed |
| **KeepAssets** | removed | removed | removed | removed | kept | removed |
| **Purge** | removed | removed | removed | removed | removed | removed |

Every removal action includes:

- **Category tagging**: Each item is classified (binary, config-file, data-directory, state-file, sqlite-db, jsonl-log, asset-cache, systemd-unit, launchd-plist, shell-completion, shell-profile-entry, ballast-pool, backup-file) for structured reporting.
- **macOS service teardown**: `sbh uninstall --launchd` calls `launchctl bootout`, removes the matching LaunchAgent or LaunchDaemon plist, and exits successfully when the service is already unloaded or the plist is already absent.
- **Custom launchd labels**: Uninstall discovery checks both `com.sbh.daemon` and a valid `SBH_LAUNCHD_LABEL`, so isolated CI/test installs clean up the same plist label they installed.
- **Backup-first semantics**: Items marked with `backup_first: true` are copied to a timestamped backup before removal.
- **Dry-run support**: `sbh uninstall --dry-run` generates the full removal plan without unloading the service or executing any deletions, showing exactly what would be removed and backed up. A dry run of a system-scope install does not need root.
- **Structured output**: The plan and execution results are available as JSON (`--json`) as one payload: the service teardown result (`service_type`, `scope`, `unit_path`, `success`, `error`) plus `cleanup` (the plan or results, with `actions`, `kept`, `removed_count`, `failed_count`, `bytes_freed`).
- **Scope-safe discovery**: a user-scope uninstall only touches the home footprint (`~/.local/bin/sbh`, `~/.cargo/bin/sbh`, the user unit or LaunchAgent, user completions, shell-profile PATH lines) and the paths in the loaded config; a system-scope uninstall only touches `/usr/local/bin/sbh`, the system unit or LaunchDaemon, and system completions.
- **Confirmation**: data-removing modes (`--purge`, `--keep-*`) prompt on a terminal and require `--yes` when stdin is not a terminal. The conservative default needs no confirmation.

```bash
# Preview what would be removed (conservative mode)
sbh uninstall --dry-run

# Full cleanup with --purge (prompts; --yes for scripts)
sbh uninstall --purge --yes

# Remove everything except logs and database
sbh uninstall --keep-data

# Keep backups of config/database in one place
sbh uninstall --purge --backup-dir ~/sbh-backups --yes

# Machine-readable plan
sbh uninstall --dry-run --json
```

Source: `src/cli/uninstall.rs`

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
    mod.rs                  Shared installer/update contracts, supply chain verification
    bootstrap.rs            Bootstrap migration and self-healing
    assets.rs               Asset manifest download/verify/cache with SHA-256
    dashboard.rs            Dashboard launcher and mode selection
    install.rs              Install orchestration with wizard, auto mode, and service setup
    from_source.rs          From-source build fallback mode
    uninstall.rs            Uninstall with 5 cleanup modes
    update.rs               Self-update with rollback, cache control, and backup management
    wizard.rs               Guided first-run install wizard + --auto mode

  tui/
    model.rs                Elm-style state model (7 screens, overlays, telemetry)
    update.rs               Pure update function (message → model mutation + command)
    render.rs               Text-mode render pipeline (all screens + overlays)
    input.rs                Three-layer key routing (overlay → global → screen)
    incident.rs             Severity classification, playbook, incident shortcuts
    adapters.rs             State-file adapter with schema drift detection
    layout.rs               Responsive layout builders with priority-based hiding
    preferences.rs          Persisted UX preferences with atomic writes
    runtime.rs              Terminal lifecycle, event loop, panic safety
    theme.rs                Color palette with NO_COLOR/high-contrast support
    telemetry.rs            Telemetry data types for timeline/candidates/decisions
    widgets.rs              Reusable gauge, badge, sparkline components
    terminal_guard.rs       Raw mode cleanup and signal-safe terminal restore

  platform/
    pal.rs                  Platform abstraction (Linux: procfs/statvfs; macOS: statfs/APFS/libproc)
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
# Unit tests (core)
rch exec "cargo test --lib"

# TUI tests (requires tui feature flag)
rch exec "cargo test --lib --features tui -- tui::"

# Dashboard operator benchmarks
rch exec "cargo test --lib --features tui -- tui::test_operator_benchmark"

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
- Ask the scorer directly: `sbh explain --why-not <dir>` scores that directory now, runs the deletion preflight, and prints the first thing standing in the way (a `.sbh-protect` marker or protected pattern, an exclusion, a scoring veto, a preflight refusal such as a source tree or an active lease, or a score below `scoring.min_score`) followed by the full factor table. Add `--counterfactual` to see the smallest change of age, size, or pressure that would flip it to Delete, and `--json` for the same report as data.
- `sbh scan <path> --min-score 0.0` lists everything the scorer saw; each line ends with an id for `sbh explain --id`.
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
- macOS/APFS: local Time Machine snapshots may retain released ballast blocks.
  Run `sbh clean --thin-local-snapshots --dry-run` and, if appropriate,
  `sudo sbh clean --thin-local-snapshots --yes`.

### "macOS Full Disk Access is missing"
- Run `sbh doctor --pal` and check the `macos.full_disk_access` entry.
- Follow `docs/macos-full-disk-access.md`.
- Restart the launchd service after changing the grant:
  `sbh service --launchd --scope user restart`.

### "Dashboard shows DEGRADED"
- Confirm daemon is running: Linux `systemctl status sbh-daemon`; macOS
  `sbh service --launchd --scope user status`; foreground debugging `sbh daemon`.
- Check state file path and permissions (default: `/var/lib/sbh/state.json`).
- Validate config with `sbh config validate`.
- Press `7` to view Diagnostics screen for connection error details.
- Press `r` to force a data refresh.

### "Dashboard or status looks stale"
- Press `r` to force a data refresh.
- Confirm daemon is running.
- Check state/log paths and permissions.
- Validate config with `sbh config validate`.

### "Dashboard keybindings don't work"
- Check if an overlay is active (help, palette, playbook). Overlays consume input before screen keys.
- Press `Esc` to close any active overlay.
- Press `?` to see available keybindings for the current context.

### "Incident shortcuts not appearing"
- Incident hints only appear at Elevated severity or higher (Yellow/Orange/Red pressure).
- Check that hint verbosity is not set to `off` (use `:` then type `pref.hints.full`).
- Press `!` to manually open the incident playbook regardless of severity.

### "Service fails to start"
- Linux: inspect `systemctl status sbh` and `journalctl -u sbh -e` for logs.
- macOS: run `sbh service --launchd --scope user status`, inspect
  `launchctl list | grep sbh`, and check `~/Library/Logs/sbh/` for log output.
  See `docs/launchd-troubleshooting.md` for interpreting `launchctl print`
  output and stale-state recovery.
- Run `sbh daemon` directly to capture startup errors.
- Verify binary path is correct: `sbh config show --json | jq '.paths'`.

### "Daemon seems stuck or unresponsive"
- Send `SIGUSR1` to trigger an immediate scan: `kill -USR1 $(pidof sbh)`.
- Send `SIGHUP` to reload configuration: `kill -HUP $(pidof sbh)`.
- Check the Diagnostics screen (`key 7`) for thread health — a `Stalled` thread indicates a blocked operation.
- If using systemd with `Type=notify`, the watchdog will auto-restart after 60 seconds of no heartbeat.

### "Memory usage keeps growing"
- The daemon enforces a 256 MB RSS limit. Check `sbh status --json | jq '.memory_rss_bytes'`.
- Systemd's `MemoryMax=256M` provides a hard ceiling.
- Large Merkle scan indexes on machines with many directories can increase baseline memory. Consider reducing `scanner.root_paths` scope.

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
Yes. `scan`, `clean`, `check`, and `emergency` support operational workflows without a long-running service. The dashboard will enter degraded mode but remains functional for navigation and overlay features.

### How do I switch back to the legacy dashboard?
Use `sbh dashboard --legacy-dashboard`, set `dashboard.mode = "legacy"` in config, or set `SBH_DASHBOARD_KILL_SWITCH=true` as an environment variable for emergency fallback.

### How do I audit why something was deleted?
Use `sbh explain --id <decision-id>` and inspect structured logs/evidence records.

### How do I reload configuration without restarting?
Send `SIGHUP` to the daemon process: `kill -HUP $(pidof sbh)`. On systemd, use `systemctl reload sbh`. The daemon re-reads `config.toml` and applies changes on the next loop iteration.

### How do I trigger an immediate scan?
Send `SIGUSR1` to the daemon: `kill -USR1 $(pidof sbh)`. This bypasses the VOI scheduler and runs a full scan on the next iteration, useful for verifying cleanup behavior after a configuration change.

### Does the Merkle index persist across daemon restarts?
Yes. The index is checkpointed to disk with SHA-256 integrity verification. On restart, the daemon loads the checkpoint and resumes incremental scanning. If the checkpoint is corrupt or missing, it falls back to a full scan.

### How much memory does `sbh` use?
Under normal operation, 20-60 MB of RSS. The hard limit is 256 MB (enforced by both the daemon self-monitor and the systemd `MemoryMax` directive). Machines with hundreds of thousands of directories in watched paths will use more due to the Merkle scan index.

### Is this Linux-only?
No. It is cross-platform, with service integration for `systemd` (Linux) and `launchd` (macOS). Open-file vetoes are platform-specific internally: Linux uses `/proc/*/fd`, while macOS uses PAL/libproc evidence for visible processes. Other safety layers, including age, sacred-path, protected-path, active executable/mmap, and `.git` guards, remain active on both platforms.

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT License (with OpenAI/Anthropic Rider). See [LICENSE](LICENSE).
