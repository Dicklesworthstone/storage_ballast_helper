# Command Reference

## Global Flags

| Flag | Purpose |
|------|---------|
| `--config <PATH>` | Override config file path |
| `--json` | Machine-readable JSON output |
| `--no-color` | Disable ANSI colors |
| `-v, --verbose` | Increase verbosity |
| `-q, --quiet` | Errors only |

## Core Commands

| Command | Purpose | Key Flags |
|---------|---------|-----------|
| `sbh daemon` | Run monitoring loop | `--verbose` |
| `sbh status` | Health + pressure | `--watch`, `--json` |
| `sbh check` | Pre-flight space check | `--target-free N`, `--need N`, `--predict N` |
| `sbh scan` | Discover artifacts | `PATHS...`, `--top N`, `--min-score N` |
| `sbh clean` | Manual cleanup | `PATHS...`, `--target-free N`, `--dry-run`, `--yes` |
| `sbh emergency` | Zero-write recovery | `PATHS...`, `--target-free N`, `--dry-run`, `--yes` |

## Ballast Commands

| Command | Purpose |
|---------|---------|
| `sbh ballast status` | Per-volume inventory |
| `sbh ballast provision` | Create/rebuild pool |
| `sbh ballast release <N>` | Release N files immediately |
| `sbh ballast replenish` | Rebuild released files |
| `sbh ballast verify` | Check file integrity |

## Observability

| Command | Purpose | Key Flags |
|---------|---------|-----------|
| `sbh stats` | Time-window statistics | `--window WINDOW`, `--top-patterns N`, `--top-deletions N` |
| `sbh blame` | Attribute pressure by process | `--top N` |
| `sbh dashboard` | Live TUI (7 screens) | — |
| `sbh explain` | Decision evidence | `--id <decision-id>` |

## Configuration

| Command | Purpose |
|---------|---------|
| `sbh config path` | Show config file location |
| `sbh config show` | Display current config |
| `sbh config validate` | Check for errors |
| `sbh config diff` | Show changes from defaults |
| `sbh config reset` | Reset to defaults |
| `sbh config set <KEY> <VALUE>` | Change a config value |

## Lifecycle

| Command | Purpose | Key Flags |
|---------|---------|-----------|
| `sbh install` | Install as service | `--systemd`, `--launchd`, `--user`, `--from-source`, `--wizard`, `--auto`, `--ballast-count N`, `--ballast-size MB`, `--dry-run` |
| `sbh uninstall` | Remove service | `--systemd`, `--launchd`, `--purge` |
| `sbh setup` | Post-install setup | `--all`, `--path`, `--verify`, `--completions SHELLS` |
| `sbh update` | Check/apply updates | — |
| `sbh tune` | Tuning recommendations | `--apply`, `--yes` |

## Protection

| Command | Purpose |
|---------|---------|
| `sbh protect <PATH>` | Protect path subtree (.sbh-protect marker) |
| `sbh protect --list` | List all protected paths |
| `sbh unprotect <PATH>` | Remove protection |

## Utility

| Command | Purpose |
|---------|---------|
| `sbh version [--verbose]` | Version + build metadata |
| `sbh completions <SHELL>` | Generate completions (bash, zsh, fish) |

---

## Pressure Levels

| Level | Free % | Daemon Response |
|-------|--------|-----------------|
| Green | > 20% | Normal monitoring, no action |
| Yellow | 14-20% | Increased scan frequency |
| Orange | 10-14% | Ballast release + artifact cleanup |
| Red | 6-10% | Aggressive cleanup |
| Critical | < 3% | Emergency mode, maximum reclaim |

---

## Dashboard (7 Screens)

| Key | Screen | Content |
|-----|--------|---------|
| `1` | Overview | Pressure matrix, forecasts, hotlist, ballast, counters |
| `2` | Timeline | Event stream with severity filtering |
| `3` | Explainability | Decision evidence, factor contributions |
| `4` | Candidates | Ranked scan results, score breakdown |
| `5` | Ballast | Per-volume inventory and controls |
| `6` | LogSearch | Log viewer with search and filter |
| `7` | Diagnostics | Daemon health, thread status, RSS |

**Keybindings:** `1-7` jump to screen, `Tab` cycle panes, `b` ballast, `x` quick-release, `?` help overlay, `v` VOI overlay, `!` incident playbook, `:` or `Ctrl-P` command palette, `Esc` close overlay, `q` quit.

---

## Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `SBH_CONFIG` | Config file override | `~/.config/sbh/custom.toml` |
| `SBH_PRESSURE_POLL_INTERVAL_MS` | Override poll interval | `500` |
| `SBH_PREDICTION_ENABLED` | Toggle prediction | `true` |
| `SBH_SCANNER_DRY_RUN` | Force dry-run mode | `true` |
| `SBH_DASHBOARD_MODE` | Dashboard mode | `New` or `Legacy` |

All config keys: prefix `SBH_`, replace dots with `_`, uppercase.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / healthy |
| 1 | Pressure detected / operation failed |
| 2 | Configuration or usage error |

## Signal Handling

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown (flush logs, release locks) |
| `SIGHUP` | Reload config without restart |
| `SIGUSR1` | Force immediate scan cycle |

## File Paths

| Path | Purpose |
|------|---------|
| `~/.config/sbh/config.toml` | Configuration |
| `~/.local/share/sbh/state.json` | Runtime state |
| `~/.local/share/sbh/activity.sqlite3` | SQLite activity log |
| `~/.local/share/sbh/activity.jsonl` | JSONL activity log |
| `~/.local/share/sbh/ballast/` | Ballast file pool |
