# launchd Troubleshooting

This guide is for macOS installs managed by launchd. It covers the common
failure modes for `sbh install --launchd`, `sbh service --launchd`, and daemon
startup after a reboot or login.

Prefer the `sbh service` wrapper first because it already selects the correct
domain, label, plist path, and remediation text:

```bash
sbh service --launchd --scope user status
sbh service --launchd --scope user logs
sbh doctor --pal
```

For system LaunchDaemons, use `sudo` and `--scope system`.

## Paths And Labels

| Scope | Plist | Logs | State |
| --- | --- | --- | --- |
| User LaunchAgent | `~/Library/LaunchAgents/com.sbh.daemon.plist` | `~/Library/Logs/sbh/` | `~/Library/Application Support/sbh/` |
| System LaunchDaemon | `/Library/LaunchDaemons/com.sbh.daemon.plist` | `/var/log/sbh/` | `/private/var/sbh/` |

The default launchd label is `com.sbh.daemon`. Isolated test installs can set
`SBH_LAUNCHD_LABEL`; discovery commands inspect the default label and the
configured label when it is safe to use as a plist filename.

launchd targets use this shape:

```text
gui/<uid>/com.sbh.daemon     # user LaunchAgent when a GUI domain exists
user/<uid>/com.sbh.daemon    # user service fallback without GUI domain
system/com.sbh.daemon        # system LaunchDaemon
```

## Fast Triage

1. Confirm the binary and config paths:

```bash
sbh config show --json | jq '.paths'
command -v sbh
```

2. Inspect platform prerequisites:

```bash
sbh doctor --pal
```

3. Inspect launchd state:

```bash
sbh service --launchd --scope user status
launchctl print gui/$(id -u)/com.sbh.daemon
```

If the GUI domain is absent, use:

```bash
launchctl print user/$(id -u)/com.sbh.daemon
```

For system scope:

```bash
sudo sbh service --launchd --scope system status
sudo launchctl print system/com.sbh.daemon
```

4. Read logs:

```bash
sbh service --launchd --scope user logs
tail -n 100 ~/Library/Logs/sbh/sbh.err
tail -n 100 ~/Library/Logs/sbh/sbh.log
```

System logs live in `/var/log/sbh/`.

### Notification Events In Unified Logging

The default `journal` notification channel also submits events directly to
macOS unified logging from the daemon process. It uses subsystem
`org.storage-ballast-helper.sbh` and category `notifications`:

```bash
log show --last 1h --style compact \
  --predicate 'process == "sbh" AND subsystem == "org.storage-ballast-helper.sbh" AND category == "notifications"'
```

Records include `SBH_EVENT=...` and `SBH_LEVEL=...`. Warning and Orange events
use Apple's default log level; Red and Critical events use error level.
Info events use info level: if you lower `notifications.journal.min_level`
from its default `warning` to `info`, add `--info` when reading the log.
The existing notification rate limits still apply, including the default
five-minute interval per Red/Critical event category. Desktop delivery remains
opt-in.

macOS controls filtering and retention; successful submission does not prove
that a message was saved. Native records are capped at 1 KiB and end with
`[truncated]` when shortened. The complete original notification summary is
still written to stderr (`sbh.err` under launchd), independently of native
delivery, and the configured file channel remains available. This bridge
covers notification events, not every daemon activity record. See Apple's
[`os_log_with_type` documentation](https://developer.apple.com/documentation/os/os_log_with_type)
for logging and retention behavior.

## Reading `launchctl print`

The most useful fields are:

| Field | Meaning | Action |
| --- | --- | --- |
| `state = running` | launchd loaded the job and it has a live process | Check `pid`, logs, and `sbh status` if behavior is wrong |
| `state = waiting` | job is loaded but not currently running | Check `KeepAlive`, last exit status, and logs |
| `pid = <n>` | daemon process ID | Use `ps -p <n> -o pid,ppid,etime,command` |
| `path = ...plist` | plist launchd loaded | Confirm it points at the expected user or system plist |
| `last exit code = <n>` | daemon exited with a status | Inspect stderr log and run `sbh daemon` foreground if needed |
| `active count` | launchd reference count | Nonzero count with no PID usually means launchd is holding state |

If `launchctl print` reports "Could not find service", the job is not loaded in
that domain. Check whether you used the wrong scope or whether the plist was
never bootstrapped.

## Common Errors

### Service Is Not Loaded

Symptoms:

- `sbh service --launchd --scope user status` reports not loaded.
- `launchctl print gui/$(id -u)/com.sbh.daemon` says it cannot find the
  service.

Fix:

```bash
sbh install --launchd --scope user --auto
sbh service --launchd --scope user status
```

If the plist exists but launchd has stale state, reload through the wrapper:

```bash
sbh service --launchd --scope user restart
```

Raw recovery commands, when the wrapper tells you to use them:

```bash
launchctl bootout gui/$(id -u)/com.sbh.daemon
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sbh.daemon.plist
launchctl kickstart -k gui/$(id -u)/com.sbh.daemon
```

### Bootstrap Failed With Exit 5

Exit 5 often means launchd already has state for the label or the plist failed
validation.

Fix:

```bash
plutil -lint ~/Library/LaunchAgents/com.sbh.daemon.plist
launchctl print gui/$(id -u)
launchctl bootout gui/$(id -u)/com.sbh.daemon
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.sbh.daemon.plist
```

For system scope, replace `gui/$(id -u)` with `system` and use the
`/Library/LaunchDaemons/com.sbh.daemon.plist` path.

### Service Starts And Immediately Exits

Symptoms:

- launchd shows a recent nonzero exit.
- `sbh.err` contains a config, permission, or filesystem error.

Fix:

```bash
sbh config validate
sbh daemon
tail -n 100 ~/Library/Logs/sbh/sbh.err
```

Common causes:

- The plist points at a stale binary path after moving between manual and
  Homebrew installs.
- The config path exists but is unreadable.
- Full Disk Access is missing for scans that touch protected user locations.
- The ballast or state directory is on a read-only or unavailable volume.

Run bootstrap repair when paths moved:

```bash
sbh bootstrap --dry-run
sbh bootstrap
sbh service --launchd --scope user restart
```

### Full Disk Access Is Missing

Symptoms:

- `sbh doctor --pal` reports `macos.full_disk_access` as WARN or FAIL.
- cleanup scans cannot inspect protected data under `~/Library`.

Fix:

1. Follow `docs/macos-full-disk-access.md`.
2. Restart the launchd service:

```bash
sbh service --launchd --scope user restart
sbh doctor --pal
```

Development builds installed at a different path need their own Full Disk
Access grant.

### Logs Are Empty

Check that the plist contains `StandardOutPath` and `StandardErrorPath`:

```bash
plutil -p ~/Library/LaunchAgents/com.sbh.daemon.plist | grep Standard
```

Then check directory ownership and run a foreground daemon for direct output:

```bash
ls -ld ~/Library/Logs/sbh
sbh daemon
```

For system scope, inspect `/var/log/sbh/` with sudo.

### Wrong Scope

User LaunchAgents can inspect the current user's process activity. System
LaunchDaemons can inspect system-wide process activity and write to
`/private/var/sbh/`, but require root for install and service control.

Use user scope for normal developer Macs:

```bash
sbh install --launchd --scope user --auto
```

Use system scope when `sbh` must monitor all users or system-wide paths:

```bash
sudo sbh install --launchd --scope system --auto
sudo sbh service --launchd --scope system status
```

## Recovery Procedures

### Restart A Healthy Loaded Service

```bash
sbh service --launchd --scope user restart
sbh service --launchd --scope user status
```

### Recreate A Stale Plist

Use this when `sbh bootstrap --dry-run` or `sbh doctor --pal` reports a stale
launchd binary path:

```bash
sbh bootstrap --dry-run
sbh bootstrap
sbh install --launchd --scope user --auto
sbh service --launchd --scope user status
```

### Foreground Debugging

Foreground mode bypasses launchd so startup errors are visible immediately:

```bash
RUST_LOG=debug sbh daemon
```

Stop with `Ctrl-C`, then return to launchd:

```bash
sbh service --launchd --scope user restart
```

### Last Resort: Reinstall Service Integration

Preview first:

```bash
sbh uninstall --launchd --scope user --dry-run
sbh install --launchd --scope user --auto
```

Only run mutating uninstall/install commands after the dry-run matches the
service scope and plist you intend to change.
