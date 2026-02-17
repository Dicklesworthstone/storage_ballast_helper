# Troubleshooting

**First step**: `sbh status --json` to check current pressure and daemon health.

## Symptom Index

| Symptom | Jump To |
|---------|---------|
| Disk full, can't write anything | [Emergency Recovery](#emergency-recovery) |
| Daemon not running / won't start | [Daemon Issues](#daemon-issues) |
| Ballast not freeing space | [Ballast Issues](#ballast-issues) |
| Scanner finds nothing / 0 scans | [Scanner Issues](#scanner-issues) |
| CLI can't read daemon state | [Permissions](#permissions) |
| Config errors on startup | [Configuration](#configuration) |
| Service won't install | [Service Issues](#service-issues) |
| Error code SBH-XXXX | [Error Codes](#error-codes) |

---

## Emergency Recovery

**Disk at 100% — can't even write config or log files:**

```bash
# Zero-write mode: no config needed, hardcoded heuristics
sbh emergency /data --yes

# Release ballast immediately (if provisioned)
sbh ballast release 5

# Preview first
sbh emergency /data --dry-run
```

**If sbh binary won't run** (disk too full for /tmp):
```bash
# Free /tmp manually first
rm -rf /tmp/cargo-* /tmp/rustc-* /tmp/*.tmp
# Then run emergency mode
sbh emergency / --yes
```

---

## Daemon Issues

| Symptom | Check | Fix |
|---------|-------|-----|
| Not running | `systemctl --user status sbh` | `systemctl --user start sbh` |
| Crashes on start | `journalctl --user -u sbh -n 50` | Check config: `sbh config validate` |
| Watchdog restart loops | `journalctl --user -u sbh --since "1h ago"` | Check disk space and permissions |
| Scans never complete | `sbh status --json \| jq '.scanner'` | Check `scanner.root_paths` accessibility |
| High CPU usage | `top -p $(pidof sbh)` | Reduce `scanner.parallelism`, increase `poll_interval_ms` |

**Start daemon in foreground for debugging:**
```bash
sbh daemon --verbose
```

**Force immediate scan:**
```bash
kill -USR1 $(pidof sbh)
```

---

## Ballast Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Ballast on wrong filesystem | Ballast dir and pressure source on different mounts | Set `paths.ballast_dir` to same mount as monitored path |
| Provision fails | Disk already too full | Free space first, then `sbh ballast provision` |
| Release doesn't help | Ballast files on different volume than the one under pressure | Check `sbh ballast status` — verify mount points match |
| Verify reports corruption | Ballast header overwritten or file truncated | `sbh ballast provision` rebuilds corrupted files |
| Replenish skipped | Cooldown not elapsed or still under pressure | Wait for green pressure + cooldown (default: 30 min) |

**Check which mount has ballast vs pressure:**
```bash
sbh ballast status --json | jq '.volumes[].mount_point'
sbh status --json | jq '.pressure.mount_point'
```

---

## Scanner Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Zero scans completed | Scanner channel starvation (known production issue) | Update to latest sbh version |
| No candidates found | `scanner.root_paths` empty or wrong | `sbh config show \| grep root_paths` |
| Important files scored | Needs protection | `sbh protect /path/to/important` |
| Slow scanning | Too many files, deep trees | Reduce `scanner.max_depth`, add `excluded_paths` |
| "SBH-2003 Safety veto" | Hard veto triggered | Expected behavior — file is protected or too recent |

**Test scanner manually:**
```bash
sbh scan /data/projects --top 10 --json
```

---

## Permissions

| Symptom | Cause | Fix |
|---------|-------|-----|
| CLI can't read state.json | Daemon runs as root, CLI as user | Use `--user` scope for daemon |
| Can't write config | Config dir permissions | `chmod 755 ~/.config/sbh` |
| Can't provision ballast | Ballast dir not writable | `chmod 755 ~/.local/share/sbh/ballast` |
| Systemd unit denied | Need sudo for system scope | Use `--user` or `sudo sbh install --systemd` |

---

## Configuration

| Error | Cause | Fix |
|-------|-------|-----|
| SBH-1001 Invalid config | Bad value in config.toml | `sbh config validate` shows exact issue |
| SBH-1002 Missing config | No config file found | `sbh install --auto` creates default config |
| SBH-1003 Parse failure | Invalid TOML syntax | Check for missing quotes, wrong bracket style |
| Weights don't sum to 1.0 | Scoring misconfiguration | Adjust `scoring.*_weight` values |
| Thresholds not descending | Pressure misconfiguration | Ensure green > yellow > orange > red |

**Reset to known-good config:**
```bash
sbh config reset
sbh config validate
```

---

## Service Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `systemctl start` fails | Unit file not installed | `sbh install --systemd --user` |
| Service starts but daemon exits | Config error or missing paths | `journalctl --user -u sbh -n 20` |
| Launchd plist errors | Plist malformed | `sbh install --launchd` regenerates |
| Two sbh binaries on PATH | Old install at `~/.local/bin`, new at `/usr/local/bin` | Remove old: check `which -a sbh` |
| HOME not set in systemd | Data goes to /tmp, lost on reboot | Add `Environment=HOME=/home/youruser` to unit override |

**Fix HOME for systemd:**
```bash
sudo systemctl edit sbh
# Add under [Service]:
# Environment=HOME=/home/youruser
sudo systemctl restart sbh
```

---

## Error Codes

### Configuration (SBH-1xxx)

| Code | Error | Fix |
|------|-------|-----|
| SBH-1001 | Invalid config value | Check `sbh config validate` output |
| SBH-1002 | Config file missing | Run `sbh install --auto` or create manually |
| SBH-1003 | TOML parse error | Fix TOML syntax (missing quotes, brackets) |
| SBH-1101 | Unsupported platform | Feature not available on this OS |

### Runtime (SBH-2xxx)

| Code | Error | Fix |
|------|-------|-----|
| SBH-2001 | Filesystem stats failed | Check path exists and is accessible |
| SBH-2002 | Mount table parse error | `/proc/mounts` or `mount` output changed |
| SBH-2003 | Safety veto | Expected: file is protected, too new, or open |
| SBH-2101 | Serialization error | State file corrupted — daemon will recreate |
| SBH-2102 | SQLite error | Check DB permissions, disk space |

### System (SBH-3xxx)

| Code | Error | Fix |
|------|-------|-----|
| SBH-3001 | Permission denied | Check file/directory ownership and permissions |
| SBH-3002 | IO failure | Check disk health, permissions, available space |
| SBH-3003 | Channel closed | Internal thread died — daemon will restart thread (up to 3x) |
| SBH-3900 | Runtime failure | Check logs: `journalctl --user -u sbh` |

**Retryable errors:** SBH-2001, SBH-2102, SBH-3002, SBH-3003, SBH-3900.

---

## Diagnostic Report

```bash
# Comprehensive status dump
sbh status --json > /tmp/sbh-diag.json
sbh config show >> /tmp/sbh-diag.json
sbh ballast status --json >> /tmp/sbh-diag.json
sbh stats --json >> /tmp/sbh-diag.json
```

---

## Getting Help

```bash
sbh --help                     # General help
sbh <command> --help           # Command-specific help
sbh version --verbose          # Build metadata
```
