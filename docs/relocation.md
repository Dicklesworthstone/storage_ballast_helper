# Relocating dormant protected scratch

`sbh relocate` reports, moves and restores protected trees that have been dormant for weeks.

A `.sbh-protect` marker never expires. Agents mark live caches and scratch so that cleanup leaves them alone, and the marker then outlives the work. Protection still means "never delete". It does not mean "never move".

## The rule

A unit becomes **eligible** when all of these hold:

- It is a marked tree, or a directory up to `unit_depth` (default 2) levels below one, under a scratch root. The default roots are `/tmp`, `/var/tmp`, `/dev/shm` and `/data/tmp`.
- It is at least `min_bytes` (default 256 MiB).
- Nothing below it has changed for `min_idle_days` (default 14). "Changed" means the newest mtime or ctime of any entry, the unit directory included.
- Nothing below it has been read for `min_idle_days`. "Read" is measured in one of two ways:
  - **atime mounts** (relatime or strictatime): the newest atime of any regular file. Directory atimes are ignored, because every scanner's `readdir` bumps them. relatime updates atime at most once a day, which is precise enough for a 14-day window.
  - **noatime mounts**: no read leaves a trace, so the evidence comes from the ledger. Every sweep records the units it finds unchanged and unheld. A unit qualifies once that record spans the whole window with no gap between sweeps longer than `max_gap_hours` (default 36). A gap restarts the window, because nothing was watching then. As a result, a noatime host can relocate nothing until the sweeps have run for 14 days.
- No process holds it. This uses the same sweep the deletion executor uses: open files, working directories, executables, mappings, and the cargo home or target directory named by a live build. If the sweep is incomplete, the unit is treated as held.
- It is readable throughout, contains no other mount, and fits in the walk budget.
- No component from its configured scratch root through any descendant matches a never-relocate pattern. The built-in patterns are `.cargo`, `.rustup`, `.sbh`, `rch*`, `*cargo-cache*`, `*cargo_cache*`, `cass*`, `*agent_search*`, `*agent_mail*` and `*agent-mail*`. A quiet fortnight does not prove that a shared cache is dead. A parent containing an excluded cache cannot move as a whole.
- No marker on an ancestor within the configured scratch roots, on the unit itself, or anywhere below it says `relocatable = false`. A nested opt-out also protects every parent that would contain it in a move. A deeper `relocatable = true` cannot override it. Malformed, unreadable, oversized, and nonregular markers refuse permission rather than being treated as consent.

When a whole marked tree is eligible, it moves as one unit. Otherwise, dormant children (and grandchildren) of a tree that is still in use elsewhere move on their own.

Opt-outs and exclusions follow their own branch: a pinned child keeps its enclosing unit in place while a safe sibling can still qualify. Checks reach below `unit_depth`; that setting limits the units that can be selected, not how far protection is inspected. Overlapping roots cannot bypass an opt-out in their shared outer root. JSON candidate evidence includes `stats.relocation_veto` with the responsible path and reason. Empty markers and valid TOML or JSON metadata remain supported; marker reads on Linux preserve their access age.

## What `--apply` does

1. rsync the unit to `<target>[/<host>]/<run stamp>/<original path>/`.
2. Verify with a checksum dry run. Any itemized difference aborts the move.
3. Upload the relocation record next to the copy as `<copy>.sbh-relocated.json`.
4. Rename the unit aside, so a writer that opens by path fails instead of writing into a tree that is about to go.
5. Renew relocation permission, survey it and sweep processes again. If anything changed, opted out, or holds it, the rename is undone.
6. Put a stub at the original path: `RELOCATED.md`, `.sbh-relocated.json`, and the marker if the unit was the marked tree.
7. Durably save the completed relocation in the ledger.
8. Renew relocation permission and the content comparison once more, then sweep processes again immediately before removing the original bytes.

Nothing is deleted before the copy verifies. To bring a tree back:

```
sudo sbh relocate --restore /dev/shm/old-scratch
```

This copies the tree back next to the stub, verifies it, swaps it in, and keeps the backup copy.

If the completion ledger cannot be saved, the command reports failure and keeps all three recovery locations: the original tree at `.<name>.sbh-relocating`, the verified backup, and the restore stub. The error names those paths. Repair the state directory or ledger before continuing; the preserved original is not automatically removed.

Permission is also renewed before the first copy starts. An owner can add an opt-out after planning or while a transfer runs. If a new veto appears after the stub and completion record are installed, the command reports failed removal and preserves the original aside, verified copy, and stub; its error names all three locations. No original bytes are removed on that refusal.

The final policy walk also supplies the current content evidence, and the last process sweep runs after that walk. A tree changed or newly held since the earlier checks is preserved too. If content changed, the error distinguishes the earlier verified backup from the preserved source, which may now contain newer work; use the preserved source when recovering that work.

## Configuration: `/etc/sbh/relocation.toml`

This file is separate from the daemon's config, so relocation can be enabled, retargeted or disabled without touching the daemon. If the file is absent, the command only reports.

```toml
enabled = true
# A key restricted with rrsync to /bulk/sbh-relocated/<host> on the target:
target = "backup@backup-host:"
include_hostname = false
target_note = "backup-host:/bulk/sbh-relocated/<host>"
ssh_identity = "/etc/sbh/relocate_ed25519"
# Needed when tailscaled runs without a tun device:
# ssh_options = ["ProxyCommand=tailscale nc %h %p"]
# The receiver is not root; ownership is kept in xattrs (rsync --fake-super).
fake_super = true
min_idle_days = 14
max_bytes_per_run = 536870912000
# exclude = ["keep-*"]
```

All other keys (`roots`, `unit_depth`, `marker_depth`, `min_bytes`, `max_gap_hours`, `state_dir`, `max_entries`, `bwlimit_kib`, `ssh_port`, `ssh_options`) have defaults. `target_note` is shown in each stub's readme, which helps when an rrsync key hides the real directory behind a relative path. Unknown keys are rejected.

Every remote step is an rsync, so a key confined by `rrsync` is enough. Put this on the target's account:

```
command="/usr/bin/rrsync /bulk/sbh-relocated/<host>",restrict ssh-ed25519 AAAA… sbh-relocate@<host>
```

## Running it

- `sbh relocate` prints a report: a total per verdict, the units that are selected, and whether this run saved its observations.
- `sbh relocate --all --json` lists every unit with its evidence.
- `sudo sbh relocate --apply` relocates the selected units. It is limited by `max_bytes_per_run`, holds a lock, and logs one JSON line per unit to stderr.

The ledger is `relocation-ledger.json` in `state_dir` (`/var/lib/sbh`). Every writer, including report-only sweeps and disabled `--apply` runs, holds the same `relocate.lock` from before reading the ledger through its last save. Each save uses a private, exclusively created staging file, syncs the file, atomically replaces the ledger, then syncs the state directory.

A report that cannot acquire the writer lock or write the state directory remains useful and records no observations. It cannot overwrite a running transfer's resumable destination or newer history, even if that transfer finishes while the report is scanning. JSON reports expose `observation_save.saved` and `observation_save.reason`; human reports print the same status.

A missing ledger starts a new observation window. A corrupt or unreadable existing ledger is preserved. Reports can still survey the trees, but use no unavailable historical observations and do not save over the damaged state; noatime trees cannot qualify from missing history. `--apply` refuses an unreadable ledger, unavailable writer lock, or failed observation save before starting any transfer. Lock contention exits with status 3; other initial state failures exit with status 1.

A timer that runs every 6 hours keeps the ledger's observations continuous:

```ini
# /etc/systemd/system/sbh-relocate.service
[Unit]
Description=sbh: relocate dormant protected scratch
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sbh relocate --apply
Nice=19
IOSchedulingClass=idle

# /etc/systemd/system/sbh-relocate.timer
[Timer]
OnCalendar=*-*-* 00/6:17:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
```

With `enabled = false`, the same timer runs the sweep and records observations but moves nothing. That is a safe way to start a host.
