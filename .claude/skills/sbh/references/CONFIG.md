# Configuration Reference

**File:** `~/.config/sbh/config.toml`
**Fallback:** `/etc/sbh/config.toml`
**Override:** `--config <PATH>` or `SBH_CONFIG` env var

## [pressure]

| Key | Default | Description |
|-----|---------|-------------|
| `green_min_free_pct` | 20.0 | Free % above which everything is healthy |
| `yellow_min_free_pct` | 14.0 | Free % threshold for increased monitoring |
| `orange_min_free_pct` | 10.0 | Free % threshold for ballast release + cleanup |
| `red_min_free_pct` | 6.0 | Free % threshold for aggressive cleanup |
| `poll_interval_ms` | 1000 | Milliseconds between pressure checks (min: 100) |

**Constraint:** Thresholds must strictly descend: green > yellow > orange > red.

## [pressure.prediction]

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | true | Enable predictive pressure forecasting |
| `action_horizon_minutes` | 30.0 | Pre-emptive scan when exhaustion predicted within this window |
| `warning_horizon_minutes` | 60.0 | Early notification horizon |
| `min_confidence` | 0.7 | Minimum confidence to act on prediction |
| `min_samples` | 5 | Minimum EWMA samples before prediction |
| `imminent_danger_minutes` | 5.0 | Imminent danger threshold |
| `critical_danger_minutes` | 2.0 | Critical danger threshold |

**Constraint:** critical < imminent < action < warning.

## [scanner]

| Key | Default | Description |
|-----|---------|-------------|
| `root_paths` | `["/data/projects"]` | Directories to scan for artifacts |
| `excluded_paths` | `[]` | Directories to skip entirely |
| `protected_paths` | `[]` | Glob patterns for protection |
| `min_file_age_minutes` | 10 | Minimum age before an artifact can be deleted |
| `max_depth` | 10 | Maximum directory traversal depth |
| `parallelism` | auto | Number of walker threads (defaults to CPU count) |
| `follow_symlinks` | false | Follow symlinks during traversal |
| `cross_devices` | false | Cross filesystem boundaries |
| `dry_run` | false | Preview mode (no deletions) |
| `max_delete_batch` | 20 | Maximum items per deletion batch |
| `repeat_deletion_base_cooldown_secs` | 300 | Base cooldown between repeated deletions of same pattern |
| `repeat_deletion_max_cooldown_secs` | 3600 | Max cooldown (exponential backoff cap) |

## [scoring]

| Key | Default | Description |
|-----|---------|-------------|
| `min_score` | 0.45 | Minimum total score for candidacy |
| `location_weight` | 0.25 | Weight for directory-type signal |
| `name_weight` | 0.25 | Weight for known artifact name patterns |
| `age_weight` | 0.20 | Weight for time since last access |
| `size_weight` | 0.15 | Weight for reclaimable bytes |
| `structure_weight` | 0.15 | Weight for directory structure signals |
| `false_positive_loss` | 50.0 | Cost of wrongly deleting a file |
| `false_negative_loss` | 30.0 | Cost of missing a deletable artifact |
| `calibration_floor` | 0.55 | Minimum calibration for adaptive decisions |

**Constraint:** All five weights must sum to exactly 1.0.
**Constraint:** `min_score` <= `calibration_floor`.

## [ballast]

| Key | Default | Description |
|-----|---------|-------------|
| `file_count` | 10 | Number of ballast files to provision |
| `file_size_bytes` | 1073741824 | Size per file (1 GiB) |
| `replenish_cooldown_minutes` | 30 | Wait time before replenishing after release |
| `auto_provision` | true | Auto-provision on daemon start |

**Constraint:** `file_count` <= 100000, `file_size_bytes` >= 4096.

### Per-volume overrides

```toml
[ballast.overrides."/data"]
enabled = true
file_count = 20
file_size_bytes = 2147483648
```

## [scheduler] (VOI)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | true | Enable Value-of-Information scan scheduling |
| `scan_budget_per_interval` | 5 | Max scans per monitoring interval |
| `exploration_quota_fraction` | 0.20 | Fraction of budget for exploratory scans |
| `io_cost_weight` | 0.1 | IO cost penalty weight |
| `fp_risk_weight` | 0.15 | False-positive risk weight |
| `exploration_weight` | 0.25 | Exploration bonus weight |

## [notifications]

| Key | Default | Description |
|-----|---------|-------------|
| `desktop.enabled` | false | Desktop notifications (notify-send / osascript) |
| `desktop.min_level` | "Orange" | Minimum severity for desktop |
| `webhook.enabled` | false | HTTP webhook notifications |
| `webhook.url` | — | Webhook endpoint URL |
| `webhook.min_level` | "Red" | Minimum severity for webhook |
| `file.enabled` | false | File-based notifications |
| `file.path` | — | Notification log file path |
| `journal.enabled` | false | systemd journal notifications |

## [paths]

| Key | Default | Description |
|-----|---------|-------------|
| `config_file` | `~/.config/sbh/config.toml` | Config file location |
| `ballast_dir` | `~/.local/share/sbh/ballast/` | Ballast pool directory |
| `state_file` | `~/.local/share/sbh/state.json` | Runtime state file |
| `sqlite_db` | `~/.local/share/sbh/activity.sqlite3` | SQLite log database |
| `jsonl_log` | `~/.local/share/sbh/activity.jsonl` | JSONL log file |

## [dashboard]

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | "New" | Dashboard mode: "New" or "Legacy" |
| `kill_switch` | false | Disable dashboard entirely |

## [policy]

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | "enforce" | Policy mode: "observe", "canary", "enforce" |

## Environment Variable Overrides

Any config key can be overridden by setting an environment variable:
- Prefix: `SBH_`
- Convert section separators to `_`
- Uppercase everything

Examples:
```bash
SBH_PRESSURE_POLL_INTERVAL_MS=500
SBH_PREDICTION_ENABLED=false
SBH_SCANNER_DRY_RUN=true
SBH_SCORING_MIN_SCORE=0.6
SBH_BALLAST_FILE_COUNT=20
SBH_DASHBOARD_MODE=Legacy
```

## Config Loading Order

1. Explicit `--config <PATH>` flag
2. `SBH_CONFIG` environment variable
3. `~/.config/sbh/config.toml`
4. `/etc/sbh/config.toml`
5. Built-in defaults
6. Environment variable overrides applied last

## Validation

```bash
sbh config validate            # Check all constraints
sbh config diff                # Show delta from defaults
```

Config validation checks:
- Pressure thresholds strictly descend
- Scoring weights sum to 1.0
- File paths are accessible
- Glob patterns compile
- Numeric bounds are respected
