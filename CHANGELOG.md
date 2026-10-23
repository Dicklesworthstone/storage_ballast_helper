# Changelog

All notable changes to `storage_ballast_helper` (`sbh`) are documented here.

Versions with published GitHub Release assets are marked **[release]**. Versions without that marker were tagged or referenced in commit messages but not published as GitHub Releases. `scripts/changelog_check.sh --all` audits the markers against GitHub, and `scripts/dsr_release.sh publish` refuses to publish a tag that has no section here. Commit links point to the canonical repository at `https://github.com/Dicklesworthstone/storage_ballast_helper`.

## Unreleased

### Changed

- **The evidence ledger records a repeated verdict that deletes nothing once
  a day, not on every scan pass** (bd-jl92). Every candidate is re-evaluated
  each pass, and each verdict was written in full to `decision_log` and the
  JSONL log: on fmd 1.5M rows for 153k paths filled 6.3 GB inside the 30-day
  retention, about 21 GB across the fleet. A keep, review or veto that repeats
  the last record for the same artifact version (stable decision id: path,
  device, inode, size) and policy mode is now skipped for 24 hours. A changed
  verdict, a new artifact version, and every decision that may delete are
  always recorded, so the deletion audit trail is unchanged and `sbh explain`
  still finds the current verdict.
- **The daemon's scan walk no longer stats every file** (bd-gh0x;
  `c858c27`). It stat-ed each file of every directory it listed to size the
  directory, though only entries that classify as candidates use the size.
  Those now read their own files, so candidates are sized as before. On a
  180,000-file test tree a walk issued 6,580 `statx` calls instead of
  186,537 and used about a tenth of the CPU (cold btrfs, 8 threads: 1.0 s
  instead of 10.8 s). With file stats, CPU also grew with walker threads,
  from btrfs's per-root inode lock; without them it stays flat. Trees with
  fewer files per directory gain less. CLI walks are unchanged.
- **`sbh status` shows the daemon's RAM-scratch warning** (bd-paeg). The
  observer that relates tmpfs occupancy to RAM and swap logged its warnings
  only to the activity log; `status` now prints the latest one from the last
  35 minutes (tmpfs, swap and process-swap figures, reasons, and the largest
  idle trees) and adds `ram_scratch` to its JSON. Report only: nothing is
  deleted on its account.
- **The I/O-history sampler reads one `/proc` file per process** (bd-du48;
  `678707e`). Every 30 s the monitor thread listed every process with its
  `comm`, `status` and `stat` files and `exe` and `cwd` links, though the
  sampler uses only the pid and start time, both in `/proc/<pid>/stat`.

### Fixed

- **Evidence deduplication waits for a successful SQLite write** (bd-jl92).
  Failed inserts remain retryable, KEEP → DELETE → KEEP records the return
  to KEEP, and fallback/suspension/comparator changes remain visible. JSONL
  logging and SQLite recovery continue while the database is unavailable;
  suppressed duplicate traffic still services the JSONL durability timer.
- **Queued deletions recheck live policy and dry-run before each mutation.**
  Observe, FallbackSafe, dry-run, and Enforce-to-Canary transitions defer
  candidates for fresh evaluation. These deferrals do not apply per-path
  failure backoff.

- **Daemon quarantine sweeps now respect Observe, FallbackSafe, and dry-run.**
  These modes retain quarantined payloads while continuing to report held
  inventory. Previously, TTL/cap sweeps and pressure-driven purges could
  permanently remove data even while ordinary candidate deletion was disabled.
- **macOS desktop notifications from the daemon reach the person at the
  screen** (bd-z1nm). The daemon runs as a root LaunchDaemon, where a bare
  `osascript display notification` reaches no one's Notification Center, so
  the desktop channel was silent on every Mac (on 2026-10-22 a memory and disk
  emergency was logged 40 minutes before a kernel panic, and nobody saw it).
  As root it now runs in the console user's GUI session as that user
  (`launchctl asuser`, `sudo -u`), and with nobody at the console it does
  nothing. The channel is still off by default.
- **The ballast headroom floor honors the absolute pressure floors**
  (bd-lxga). It was one percentage for every volume, the Orange threshold but
  at least two points above Red, so `pressure.*_min_free_bytes` lowered a large
  volume's pressure level but not its provisioning floor. A 1.86 TB Mac that
  the byte floors held at Yellow refused every ballast file below about 100 GB
  free and kept an empty reserve. The floor is now worked out per volume from
  the thresholds in force on it. The daemon (at start and on reload),
  `sbh ballast`, the dashboard and the `ballast.reserve` doctor check use it.
  Without byte floors nothing changes.
- **A special-location alert no longer releases ballast, and repeats are one
  alert** (bd-uttn). Each alert released ballast at once, on the location's
  mount or else on the fullest pool, which bypassed the mount's own pressure
  level. On macOS `/tmp` is a special location on the Data volume, and its
  "filling fast" rule fired on ordinary write bursts (about 100 alerts a
  day), so the reserve was spent and never rebuilt. A RAM-backed location
  such as `/dev/shm` gained nothing from freeing disk at all. The alert still
  queues a scan. It now notifies when an episode starts or escalates, with
  the real previous level, and an episode ends only after a whole alert
  interval without an alert.
- **A directory named `target` under a temp root is no longer a cargo target
  on its name alone** (bd-u9ua; `14f5b71`). Without a `Cargo.toml` beside it,
  it now needs cargo's own markers (`CACHEDIR.TAG`, `.rustc_info.json`,
  `debug/`, ...). hfdt stores keep a `target/` of their own: on ts2 the
  daemon deleted it from two agent store copies (2026-09-29), and a 5 GB
  `target/doctor-undo` scored as a 0.93 cargo target.
- **`sbh clean`, `sbh emergency`, and the daemon's pre-scan and index replay
  classify a directory as the walk does** (bd-10yj; `93c6c4f`). They classified by name
  and ignored the walker's verdict, so `clean` missed a Go build cache that
  `scan` nominated, and a tree the walk only descends into (an hfdt store's
  own `target/`, a repo copy's scripts/build directory) could still be nominated by
  its name. On ts2 the daemon made 472 such name-only `target` decisions
  between 10-13 and 10-18.
- **A scan pass that stops on its budget no longer hides unexplored ground
  from the next one** (bd-y70k; `efc01b1`, `ad7fcaf`). After such a pass
  (on ts2, every pass: they stop at 500,000 entries) the daemon cached as
  barren for 30 minutes every listed directory that was not the direct
  parent of a candidate, and the next walk skipped it. That took in a
  candidate's grandparents and the candidate directory itself, and every
  listed directory whose children were still queued, being listed, or
  emitted but never read when the pass stopped. The v2 index still replayed
  candidates it knew; new ones below those directories were not found. The
  walker now reports what a stopped pass left unseen, and nothing at or
  above it is cached. If the walker threads have not stopped 5 seconds
  after the stop, the pass caches nothing.
- **CPU scan budgets apply at Critical, and survive a failed first CPU
  sample** (`41ad7f5`, `de7bb8a`). Sustained Critical pressure bypassed the
  token bucket, and a pass whose first CPU reading failed ran without a CPU
  limit.
- **Zero-byte size hints no longer crowd real candidates out of index
  replay** (`c707669`). Empty estimates are dropped before the replay's
  result limit applies.
- **The compression tier resumes after the files it processed** (`ecd7d1a`).
  A pass that stopped early no longer moved its cursor past the files
  discovery selected but the pass never reached.
- **Target-only reclaim re-checks a target before deleting it** (bd-232u;
  `715913c`). The tier nominates a cargo target dir only while its top level
  holds nothing but cargo's own entries; the executor then checked only that
  it was the same inode. A trace dir or log written into the target while
  its batch waited is now noticed, and the target is kept.
- **`install.sh --dest DIR` leaves the installed service alone** (`2e913dc`).
  It went on to sync the system service from the copy, so an install into a
  scratch directory replaced `/usr/local/bin/sbh` and restarted the daemon
  (two hosts on 2026-10-19, with an e2e fixture's debug build).
- **`install.sh` never downgrades an installed service unasked** (bd-zuuq;
  `2931767`). Its service sync replaced the service's binary whenever it
  differed from the one just installed. A nightly ACFS update, installing
  the latest release (v0.7.9), so put v0.7.9 over a v0.7.10
  `/usr/local/bin/sbh` and restarted the daemon (ts2, 2026-10-20). Without
  `--version`, a service binary that reports a newer release is now left as
  it is, as `sbh update` already did; `--version` still installs an older
  release on purpose.
- **A dropped walk stream stops its walk** (`4a6baa8`). A consumer that went
  away without cancelling, such as a scanner thread that panicked and was
  respawned, left its walker threads listing the rest of the tree with
  nobody reading.
- **The daemon no longer reads its own cgroup's stall as memory pressure**
  (bd-90af). Since 0.7.10 the memory level took the larger of host PSI and
  the PSI of sbh's own cgroup. In a service cgroup that holds only sbh,
  that PSI is the daemon reclaiming its own walk's dentries and page cache
  against `MemoryMax`: on ts2 it rose from 3% to 35% within 10 s while host
  PSI stayed near 2%, and the daemon changed behavior mode 53-146 times an
  hour, narrowing its scan and raising 3-8 Critical+Critical emergency
  notifications an hour. A cgroup that holds only sbh (`cgroup.procs`, no
  descendants in `cgroup.stat`) now defers to host PSI; a shared one, such
  as an agent's scope or a container, still counts.
- **The priority pre-scan no longer starves the walk at Critical**
  (bd-6ydh). Since
  CPU budgets apply at Critical, a pre-scan that probes each nominee's tree
  could spend a pass's whole CPU allowance by itself: on ts2 every pass
  after the sixth stopped inside it after 38-1,041 of /data/tmp's 23,301
  top-level entries, and the walk did not run. The pre-scan now stops at
  half the pass's allowance and the walk gets the rest.

### Removed

- **Five config keys that had no effect** (bd-65vb):
  `scheduler.exploration_quota_fraction`, `scheduler.fp_risk_weight` and
  `scheduler.exploration_weight` (the scheduler's hazard index replaced
  them); `update.background_refresh`, which nothing read; and
  `platform.macos.query_foundation_purgeable`, since the macOS code reads only
  the `SBH_MACOS_QUERY_FOUNDATION_PURGEABLE` environment variable, which stays.
  `update.background_refresh` defaulted to true and was refused together
  with `update.enabled = false`, so turning updates off in `config.toml`
  failed validation unless both lines were set. A file that still sets these
  keys loads; each one is reported as removed (an error only with
  `strict_config = true`). The dashboard's VOI panel no longer shows an
  exploit/explore split computed from the dead quota; each planned path
  still says whether it was an exploration pick. `SBH_UPDATE_BACKGROUND_REFRESH`
  is gone, and `SBH_UPDATE_OPT_OUT` is documented as the environment switch
  it is rather than as a config key.

## v0.7.10 **[release]**

Compare: [`v0.7.9...v0.7.10`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.9...v0.7.10)

On Btrfs the daemon can now compress cold files instead of deleting
anything (opt-in `[compress]`). It also reclaims idle cargo targets inside
agent scratch that is otherwise protected (`scanner.target_only_roots`).
Most of the fixes come from a Linux host whose `/` sat at Critical for
days:
- the activity database no longer grows by about 0.4 GB a day of
  empty-candidate records;
- the generated unit's memory cap no longer stalls the daemon;
- the RSS limits no longer restart it on a normal working set.

On macOS, the checks for processes using a candidate now report what they
could not see. Running them on a Mac found cases that would have held
every deletion: zombies, unlinked files and guarded descriptors. Those are
fixed. The dashboard leaves the terminal usable after a panic or a kill,
and the release binaries now include it. The native Btrfs and systemd
checks run through dsr before each release; sbh has no GitHub workflows.

### Added

- **Btrfs: the daemon can compress cold files instead of deleting
  anything** (`6bc9fde`). Opt-in with `[compress] enabled = true`, a list
  of `roots` and `allow_zstd_feature = true`. When a root's Btrfs mount
  reaches `start_level` (default yellow), the daemon runs the same
  discover-then-apply pass as `sbh compress --discover --apply`, at most
  one at a time and at most every `interval_minutes` (default 30), bounded
  by `[compress.policy]` (files idle 24 hours and at least 16 MiB, 128
  files and 8 GiB per pass by default). Each file is rewritten losslessly:
  open, mapped, leased, young and shared files are skipped, the file is
  held through a read-only descriptor (running it stays possible), and the
  result is checked against a SHA-256 read back from disk after its cached
  pages are dropped. A started file is finished on its own allowance, not
  the pass deadline, and one an earlier pass stopped inside is finished
  later rather than skipped as compressed. When part of a file does not
  compress, btrfs marks it no-compress (`m` in lsattr); the rest of that
  file is still compressed in the same pass, and the mark stays so later
  passes skip the file instead of rewriting the incompressible part again.
  The tier does not run in observe or fallback-safe mode, under the kill
  switch or in dry-run, and a pass running when the daemon enters one of
  them stops before its next file or chunk. Outcomes go to the
  activity log; an `[SBH-COMPRESS]` line summarizes each pass. Enabling it
  stands in for the CLI's `--quiescent`: a snapshot or reflink made during
  a pass keeps the old extents, so those bytes are freed only when it
  goes. On one host the same method, run by hand, freed several hundred
  GB in two days while deletion freed megabytes an hour.
- **Idle cargo targets inside protected agent scratch are reclaimed**
  (bd-232u). Operators protect a coding agent's session scratch as a
  whole, since it holds temp clones and evidence, but agents also build
  there with `CARGO_TARGET_DIR`. On one 3.6 TB Mac about 151 GB of such
  targets sat untouched for over a day while the volume reached 99% and
  sbh released nothing. Under each `scanner.target_only_roots` root
  (macOS default `/private/tmp/claude-*`; none elsewhere), while its mount
  is at Yellow or above, the daemon now looks every 10 minutes for
  directories with `CACHEDIR.TAG` or `.rustc_info.json` whose top level
  holds only cargo's own entries, with no `.sbh-protect` or `.git` in,
  inside or above them below the root, nothing created or changed within
  `scanner.target_only_idle_hours` (24), and no process with a file open
  or its working directory in them. Those go to the executor as a
  target-only batch pinned to the directories surveyed: the policy mode,
  the decision ledger, the planner and every executor check still apply,
  the executor drops anything outside the root, and only the
  `protected_paths` patterns that protect the root as a whole are lifted
  (one naming something inside it still applies). Everything else under
  the root stays untouchable. A user-scoped macOS daemon cannot see other
  users' processes and so keeps every candidate; the tier needs the
  system-scope service there.
- **macOS: browsers' leftover app copies are reclaimed** (`0bd2dbb`).
  Chrome, Canary, Edge, Brave and Opera copy their app bundle into
  `/var/folders/<xx>/<hash>/X` at every launch and remove the copy only
  when they exit normally. Killed headless browsers left 1,027 of them on
  one Mac. With the v2 engine, a configured user temp dir root
  (`/var/folders/<xx>/<hash>/T`) now brings the `X` directory beside it,
  where only these copies are candidates. A copy is kept while a running
  instance of its browser may own it: one that started up to 10 minutes
  before the copy was made, or any instance for the browser's newest
  copy. Open files can't tell which copy is live: some browsers hold
  nothing open in theirs, and copies made from one binary all link that
  binary. Freed space is smaller than the sizes listed, because the copies
  share blocks with the installed app and with each other.

### Fixed

- **Generated systemd units cap memory at 4096M, not 768M.** The cgroup
  is charged for the dentry and inode cache the walker fills, not only the
  daemon's RSS. On one large host at Critical the cgroup sat at the 768M
  cap with about 400 MiB of that cache. The daemon spent 73-79% of its
  time stalled on memory, and its monitor tick stretched to minutes, so
  its CPU self-report read 220-1093% of a core against a real 100%.
  Raised to 4G at runtime, the next pass ran with no memory stall at
  about 1.1 GiB, and ticks were regular again; when a `daemon-reload`
  restored the 768M drop-in 14 minutes later, the stall was back within a
  minute and the ticks stretched again. The daemon's own RSS limit
  still bounds its allocations; the rest of the cap only bounds
  reclaimable cache. Existing installs keep their unit until `sudo sbh
  service --systemd reinstall-unit` rewrites it; a drop-in that sets
  `MemoryMax=768M` overrides the new unit and must be changed too.
- **The daemon no longer restarts itself on a large host's normal working
  set.** Its RSS limits default to 512 MiB (warning) and 1 GiB (exit),
  from 256 MiB and 500 MiB. Under the 768M cap the kernel had pushed part
  of the daemon's memory into swap, which kept RSS under 500 MiB. Under
  4096M the same host, whose passes stop at the 500k-entry budget, settled
  at 460-490 MiB and passed 545 MiB at the end of a pass. It exited on the
  hard limit under Critical pressure after 52 hours, and the new process
  climbed back to 490 MiB within two hours. Installs that set the limits in
  `[telemetry]` keep their values.
- **The end of a timed-out pass no longer copies every barren directory.**
  The incremental scan cursor cloned each visited directory that had no
  candidates, about 450k paths per pass on that host, and then kept
  50,000. It now clones at most 50,000. Which directories it keeps is
  unchanged: fresh ones first, then the newest cached ones.
- **The RAM-scratch report names the largest tmpfs trees again.** `sbh
  check --ram-scratch` and the daemon's `SBH-RAM-SCRATCH` warning split
  a 20,000-entry budget (8192 in the daemon) evenly across the occupied
  mounts, largest first. On one host with swap 100% full, `/tmp` held
  45 GiB in 128k entries; the report saw a few percent of it, listed
  trees of about 1 GiB, and missed the three of 16.8, 12.3 and 3.9 GiB
  that filled most of it. Mounts are now probed smallest first, so what a runtime
  mount leaves unused passes to the fullest one, and the budgets are
  2,000,000 entries (hard limit 5,000,000) and 1,000,000 in the daemon;
  the existing deadlines still bound the work. A budget hit by many
  directories is reported once.
- **A deferred behavior-mode change now takes effect when its window
  ends.** A memory transition that came within
  `pressure.behavior_hysteresis_secs` of the previous one in the same
  direction was held back and then lost: the memory subscription reports
  a level only when it changes, and the next disk tick evaluated the old
  level, which cancelled the held transition. The daemon then ran in the
  wrong mode until memory changed level again. On one host none of 12
  deferrals in three days was applied, and the next logged change came up
  to four minutes later. The held level now counts as the latest
  reading, survives a config reload, and is retried every 500 ms while
  the daemon sleeps and on every tick; it applies once the window has
  passed.
- **Btrfs compression no longer leaves large files part-compressed**
  (`3110b29`). On Linux 6.17 one defrag call over a large uncompressed
  extent compresses only its first 256 KiB, so `sbh compress --apply`
  left most fresh files partial. A part-compressed file uses more space
  than before, because btrfs keeps the whole original extent while any
  of it is still in use, and later passes refused to touch it again. Each
  256 KiB is now compressed and written to disk before the next, and
  anything still uncompressed in the original extents is retried until
  none is left. A remainder is reported, never counted as compressed. On
  one host's test files, a pass that left both files partial now
  compresses them fully, 20 to 1.2 MiB each.
- **Compression discovery resumes where any budget stopped it**
  (`4a9ed94`). Only the file limit left a continuation, so a walk stopped
  by its directory, entry or time budget started over from the top next
  time: on a temp root with tens of thousands of entries, the daemon tier
  would have compressed the first part and then found nothing new on every
  later pass. Every stop now continues after the last path it fully
  examined, and a directory past the depth limit is skipped instead of
  ending the walk.
- **Empty candidates no longer fill the decision log** (`7d41487`). The
  planner never deletes a candidate that frees nothing, but the scanner
  still sent every one to it, and each became a decision record on every
  pass. On one host at Critical that was 3,479 empty directories every 20
  minutes, about 250,000 records a day kept for 30 days: the activity
  database grew from 1.1 to 1.5 GB in a day while nothing was deleted.
  They are no longer sent.
- **Linux: a Cargo build without HOME keeps its home config's protection**
  (`f0e17ac`). A build run from a systemd unit or under `env -i` has no
  HOME, so Cargo reads the config in its account's home instead. sbh read
  no home config at all and still treated the build as fully inspected,
  so a `build.target-dir` set there wasn't protected. sbh now reads the
  same home config, finding the account from the process's user ID. When
  it can't find the account, it treats the build as not fully inspected
  and deletions wait.
- **Installed Python packages in uv's cache are no longer nominated one
  directory at a time** (`4bdd857`). With `~/.cache` as a scan root, sbh
  nominated `__pycache__` directories inside packages uv had unpacked,
  300–600 times an hour on one host. Running interpreters had them open,
  so every attempt was refused. sbh now leaves the inside of each uv
  cache entry alone; the uv cache as a whole can still be reclaimed.
- **Space freed on ext4 and btrfs is reported, and marked as an estimate**
  (`7eee639`). These filesystems release a deleted file's blocks only when
  they next commit, so the gain measured right after each deletion was
  close to zero. One host reported "0.0 GB freed" while freeing 4–6 GiB
  an hour. There, summaries, status, the dashboard and notifications now
  use the deleted trees' allocated size and say so: "~4.2 GB freed,
  estimated". On btrfs a snapshot or reflink can keep shared blocks, so
  the figure reads "up to 4.2 GB". The new `freed_basis` field in the
  status JSON and state file, and the new `sbh_bytes_freed_basis` metric,
  say how the figure was obtained, and the measured figure is kept
  alongside. sbh's cleanup decisions don't use these figures.
- **"Largest directories" names the real space users on large disks**
  (`59944ea`). When reclaim can't keep up, sbh lists the biggest
  directories on the disk. On multi-terabyte disks it had time to look at
  only a sliver of each, so it named whatever was quick to measure: a
  5 GiB placeholder on one host, "/Applications" on a Mac whose space was
  in temporary agent work. Directories too large to measure fully are now
  estimated by sampling and shown as "~X GiB est.". On a Mac with 1.7 TiB
  used, the home directory ranked first in every trial; before, it wasn't
  listed at all. Estimates of very large trees tend to run low.
- **The log's RAM copy no longer switches on and off near a limit**
  (`12c910f`). When the disk holding sbh's log fills, sbh also writes the
  log to RAM, but stops when RAM or swap runs short. Starting and
  stopping used the same limit, so on one host the copy started 19 times
  and stopped 14 times a day, and each stop lost the lines it was holding.
  Starting now needs more headroom than keeping it running (15% instead
  of 10% of RAM and swap, 25% instead of 20% of the destination), and
  sbh checks that headroom about once a second instead of on every log
  line.
- **Linux: the log's RAM copy also needs headroom in sbh's own cgroup**
  (`9da9e8d`, `4662995`). The host can have plenty of free RAM while the
  service's cgroup, or one above it, sits near its `memory.high`,
  `memory.max` or swap limit; writing the log to RAM there pushes sbh
  toward the cgroup's reclaim or OOM killer. After the host and mount
  checks pass, the same 10% keep and 15% start margins now apply to every
  visible cgroup-v2 scope, each against its own usage. When that evidence
  can't be read (a legacy hierarchy, a hidden ancestor, a limit changing
  mid-read), sbh refuses the RAM copy and stays on disk.
- **Linux: memory pressure inside sbh's own cgroup counts** (`772d43b`,
  `863784f`). The daemon read only the host's memory stall (PSI), so a
  service cgroup stalling on its own limit looked healthy. It now also
  reads its cgroup's `memory.pressure` and uses the larger of the two
  stall figures, never their sum; host page and swap counts are unchanged.
  The memory subscription survives its event source breaking (it falls
  back to sampling once a second) and a failed sample reports the level
  as unknown instead of repeating the last one.
- **macOS: the live-process checks report what they could not see**
  (`16feafc`, `61a303e`, `4c0119a`, `0aaaeef`, `9c7e282`, `9585207`,
  `0741675`, `3684721`, `a588eaf`). Before a deletion, sbh asks which
  processes use the candidate: running builds' outputs, open files,
  executables and memory mappings. On macOS those queries dropped
  processes they could not read and returned what was left as the whole
  answer. They now say when coverage is incomplete (access errors,
  budgets, a process list that would not fit), and the deletion waits;
  what they did see still protects. One query covers all roots under
  shared limits, a stalled native call no longer blocks its caller, and
  the process list grows its buffer instead of retrying at the same size.
- **macOS: deletion no longer waits forever on processes that cannot use a
  candidate** (`00d8b23`). On a busy Mac the new checks above never
  reported complete coverage, even as root, so nothing would have been
  deleted:
  - About 20 zombie processes, children their parents never reaped, read
    as unreadable instead of exited. The errno libproc leaves behind is
    now read.
  - Agent CLIs still running a version their updater had deleted (10 of
    1,670 processes) had no executable path. An unlinked executable or
    open file lies under no candidate root.
  - Apple daemons' guarded descriptors refuse even root. As root, those no
    longer count as missing coverage. Without root, missing privileges
    still hold deletions, as on Linux.

  Also fixed: the macOS build (`mappings.rs` did not compile), two clippy
  lints, and three tests that never passed on a Mac. Measured on the
  3.6 TB Mac these checks were written for, whose daemon runs as root.
- **The dashboard leaves the terminal usable after a panic or a kill**
  (`ca17048`). `sbh dashboard` now opens the terminal through one guard.
  A SIGTERM, SIGHUP, SIGQUIT or SIGINT from another process used to make
  the terminal library restore the screen and then wait 2 s for the
  dashboard, which went on drawing frames over the shell and was then
  killed. The dashboard now notices the signal within 0.2 s, stops
  drawing, restores the terminal and exits with 128 + the signal. In
  builds where a panic unwinds (debug and test builds; release builds
  abort, and the library covers them), the terminal is restored before
  the panic message is printed. The message now stays readable instead of
  being printed on the alternate screen and wiped.
- **`sbh config validate` reports a config that does not parse as
  INVALID again.** Since v0.7.9 the source-root assessment that runs
  first printed "Source-root configuration: FAIL" for a syntax error and
  stopped there, so the real check never ran and its "Configuration is
  INVALID" message was never printed. A load failure is now left to the
  command: `config validate` and a targeted `doctor` report it themselves.
  A plain `sbh doctor`, which the assessment answers alone, still reports
  it there.
- **Release binaries include the dashboard cockpit.** dsr built the
  release binaries without the `tui` feature that Cargo.toml lists for
  them, so `sbh dashboard --new-dashboard` on v0.7.9 said "TUI feature not
  enabled". dsr's build now passes `--features cli,daemon,sqlite,tui`.

## v0.7.9 **[release]**

Compare: [`v0.7.8...v0.7.9`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.8...v0.7.9)

The first published release since v0.7.6: v0.7.7 and v0.7.8 were tagged
but not published, and this release carries everything listed under both.
From those: on a host under memory pressure, a build stuck in `mmap` froze
the daemon's monitor for 19 minutes, and neither the monitor nor scans and
deletions now wait on another process's memory. On Linux, a live build's
command-line output directories, its Cargo config's target and build
directories, and its default `target/` count as in use (also for `sbh
clean` and `sbh emergency`), and a build that can't be fully inspected
holds the batch. Directories with more than 65,536 entries are covered over
successive passes, the root daemon no longer reads kernel pseudo-files
named as Cargo configuration, memory pressure no longer flaps between
levels, scans use 16–21% less CPU, protection refusals are reported as
refusals, and maintenance passes no longer flood the journal.

New in this release, a safety and availability fix set: sbh deleted source
directories named `build` or `dist` inside repo copies under temp roots,
and the shipped code of packages in install caches, on the name alone; such
a directory now counts as output only beside the manifest of a tool that
writes it. One process with tens of thousands of open files (a `bfs`
search) stopped every deletion on its host; the limit is higher and the
log names the process. Under the
hardened systemd unit `sbh install` generates, ballast was never released
for `/`; it now is, and ballast the service can't release is named
instead of counted. Also: `sbh compress --discover --apply` compresses a
directory's cold files in one pass.

### Added

- **`sbh compress --discover --apply` compresses a directory's cold files
  in one pass** (`74e1f93`). Discovery could only list candidates, so
  compressing a tree meant pasting its output into an explicit-file apply.
  With `--apply` and both consents, the same pass now runs every apply check
  on exactly the selected files, and refuses a file that changed since
  discovery or whose root was replaced. Automatic compression under pressure
  is still not enabled.

### Fixed

- **Source directories named `build` or `dist` inside repo copies under a
  temp root are no longer deleted** (`41bce34`). Any `build` or `dist`
  directory under `/tmp` or `/data/tmp` counted as build output on its
  location alone. On one host sbh chose 1,743 of them and deleted 863 from
  agents' verify checkouts and exports, for about 12 KiB each: 711 tracked
  scripts/build source directories and 152 golden-test fixture directories
  (a Rust src/cmd/build module was spared only by the executor's source
  check). Inside a project tree such a directory now needs a project
  manifest beside it to count as output.
- **Packages' shipped code and partial repo copies are kept too**
  (`183fd53`). A `dist/` beside `package.json` counted as output anywhere,
  so sbh deleted the code of three packages in a bun install cache, and a
  partial export with no manifest at all still lost its build directories.
  A `build/` or `dist/` now counts as output only beside the manifest of a
  tool that writes it (JS and Python packaging for `dist/`; CMake, Make,
  Meson, Gradle, Python and JS builds for `build/`), and never inside
  `node_modules` or a package cache. The executor's last-line source check
  now also recognises `.mjs`, `.cjs`, `.mts` and `.cts` files.
- **One process with many open files no longer stops every deletion**
  (`48c1414`, `726c9a2`). sbh reads each process's open files before
  deleting, up to 16,384 per process; past that it couldn't vouch for any
  candidate and held them all, logging only that inspection was
  "incomplete". On one host a long-running `bfs` search with 65,536
  directories open stopped all deletions for hours. The per-process limit
  is now 131,072, and when a limit is hit the log, the scanner's
  "incomplete" line and `sbh explain` name the process.
- **Ballast is released for `/` under a sandboxed systemd unit**
  (`151b50f`). With `ProtectSystem=strict` (what `sbh install` generates for
  a system service), `/` is a read-only mount inside the service and the
  ballast directory a writable bind mount of the same disk. sbh keyed the
  pool to the bind mount and found no pool when `/` itself came under
  pressure: one host logged "released 0 ballast file(s)" at Critical eight
  times in three days. Every mount entry of a pooled disk now reaches its
  pool.
- **The daemon says when it can't release a ballast reserve** (`f1284a9`).
  sbh ballast left in a former pool directory that is read-only to the
  service (outside `ReadWritePaths=`) was skipped silently, and a root `sbh
  ballast status`, run outside the sandbox, counted it as releasable. On
  one host that was the entire root reserve, 10 GiB. The daemon now names
  such directories at startup, with the remedy, and `sbh --json ballast
  status` lists them under `unreachable_reserve`.
- **A root `sbh ballast status` no longer counts that reserve as
  releasable** (`54bfabb`). Outside the service's sandbox `/` is writable,
  so the CLI still adopted the read-only reserve and reported it as
  releasable (10.7 GB on that host, which the daemon could never release).
  The CLI now reads the installed unit and its drop-ins, and a reserve
  directory that no `ReadWritePaths=` entry grants under
  `ProtectSystem=strict` is listed as unreachable instead. Human output
  names it per volume, with the remedy.

## v0.7.8

Compare: [`v0.7.7...v0.7.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.7...v0.7.8)

Tagged (`5bc148d`) but not published: v0.7.9 followed the same day with
fixes found during its canary. Its changes ship in v0.7.9.

v0.7.7 was tagged but held back, because its build-inspection rework left
Linux `sbh clean` and `sbh emergency` without a live build's declared
directories. This version fixed that and carried everything listed under
v0.7.7. On a host under memory
pressure, a build stuck in `mmap` froze the daemon's monitor for 19
minutes: no pressure response and no ballast release on a Critical host.
Neither the monitor nor scans and deletions now wait on another process's
memory. On Linux, a live build's command-line output directories, its
Cargo config's target and build directories, and its default `target/`
count as in use, and a build that can't be fully inspected holds the
batch. Also: directories with more than 65,536 entries are covered over
successive passes, a local user can no longer make the root daemon read
kernel pseudo-files as Cargo configuration, memory pressure no longer flaps
between levels, scan workers hand over results in batches (16–21% less
user CPU), protection refusals are reported as refusals, and maintenance
passes no longer flood the journal with repeated "keep" lines.

### Fixed

- **Linux `sbh clean` and `sbh emergency` keep a live build's declared
  directories** (`5b7faf8`). v0.7.7's build-inspection rework (`e089850`)
  moved declared build directories (`CARGO_TARGET_DIR`, `--target-dir`,
  Cargo config) into the checked collector the daemon uses, but left the
  collector behind interactive `clean` and `emergency` with open-file
  evidence only. A running build's target directory with nothing open
  beneath it, such as the local side of an `rch` build, lost its veto and
  could be deleted by a manual clean. That collector now uses the same
  checked composition, and its coverage is complete only when both the
  open-file and build observations are. v0.7.6 was not affected.
- **`cargo d` holds its default target like `cargo doc`** (`d5dafbf`). On
  Linux a running cargo's default `target/` counts as in use before its
  first artifact exists, but only for known build subcommands; Cargo's
  built-in alias `d` was missing (`b`, `c`, `t` and `r` were covered).

### Changed

- **Maintenance passes stop repeating the same "keep" lines** (`94a2e3d`).
  A maintenance pass logs why each classified entry was kept, and the same
  entries recur on every pass: on one host that was 100,000 identical lines
  a day, 95% of sbh's journal, on a disk at 95%. Each path is now logged
  when first seen, when its verdict changes, and otherwise hourly.

## v0.7.7

Compare: [`v0.7.6...v0.7.7`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.6...v0.7.7)

Tagged (`adc802a`) but not published: it carried the Linux `sbh clean` /
`sbh emergency` regression fixed in v0.7.8. Its other changes ship in
v0.7.8.

An availability and safety release. On a host under memory pressure, a
build stuck in `mmap` froze the daemon's monitor for 19 minutes: no pressure
response and no ballast release on a Critical host. Neither the monitor nor
scans and deletions now wait on another process's memory. On Linux, a live
build's command-line output directories, its Cargo config's target and
build directories, and its default `target/` now count as in use, and a
build that can't be fully inspected holds the batch. Also: directories with
more than 65,536 entries are covered over successive passes, a local user
can no longer make the root daemon read kernel pseudo-files as Cargo
configuration, memory pressure no longer flaps between levels, scan workers
hand over results in batches (16–21% less user CPU), and protection
refusals are reported as refusals.

### Fixed

- **A directory with more than 65,536 entries is covered over successive
  passes** (`d1f154d`). The walker stopped at that many entries and
  started at the top again every pass, so the rest was never visited. On
  btrfs, which lists entries in creation order, that is the newest ones:
  a 68,519-entry `/data/tmp` hid its newest 2,984 entries (40 GiB) from
  every pass. Each pass now processes the next 65,536 entries, and every
  name is still read, so a `.sbh-protect` marker anywhere in a large
  directory protects it.
- **On Linux, build output directories named on a live build's command
  line count as in use** (`0c64ff6`, `a7838ef`). sbh read a build
  process's environment but not its arguments, so it could delete a
  running build's `cargo --target-dir` directory (also via `cargo-clippy`
  and rch's `cargo-rch-real`), or rustc's `-C incremental=` cache outside
  the target directory. It now also tracks `CARGO_BUILD_TARGET_DIR`,
  `CARGO_BUILD_BUILD_DIR` and an inherited `OUT_DIR` separately from the
  final artifacts. If a known build tool's process details can't be read
  in full, the deletion waits; a build process caught while exiting gets
  a few milliseconds to finish first (`8a89b93`), or busy build hosts
  held most batches.
- **On Linux, a running cargo's configured and default target directories
  count as in use** (`e688393`, `5441d1a`, `8177792`). A `build.target-dir`
  or `build-dir` set in a Cargo config file (the hierarchy above the build,
  the cargo home's config, `--config` files and inline values, and their
  includes) was not seen at all. Nor was a build's default `target/`
  before its first artifact existed. sbh now reads those config files, bounded and without running
  Cargo, and derives the default target from the package or workspace
  manifest (`--manifest-path`, virtual and nested workspaces). A config
  file that disappears or changes while sbh reads it counts as unreadable,
  not absent, so the deletion waits.
- **Build inspection that can't finish holds the batch** (`e089850`,
  `900c47a`). The executor re-checks live builds' declared directories for
  each batch but ignored whether that check finished. Within 20 seconds of
  a complete open-file sweep, a build whose workspace manifest couldn't be
  read could lose its target's protection. An incomplete check now holds
  the batch, as an incomplete open-file sweep already did, in scoring, the
  executor and compression.
- **The root daemon no longer reads kernel pseudo-files a user names as
  Cargo configuration** (`c9c971e`). Any local user could start a process
  named `cargo` with `--config /proc/kmsg`, and every sweep then read it
  as root, draining the kernel log; a directory swapped for a symlink
  mid-check could even make root open a device. On Linux, configuration
  paths are now opened without following any symlink, and files on procfs,
  sysfs, debugfs, tracefs and similar filesystems are refused unread.
- **A wedged process can no longer freeze the daemon's monitor**
  (`c1d8f23`). Reading another process's command line waits for that
  process's memory-map lock. Under memory pressure a build stuck in `mmap`
  held it for 19 minutes, and the daemon's monitor thread, which read every
  process's command line for its I/O history and regret checks, waited
  with it: no logging, no pressure response, no ballast release on a
  Critical host. Those checks never used the command line and no longer
  read it.
- **A wedged process can no longer stall scans or deletions either**
  (`3b45c3d`, `bbf3867`). Two more readers waited on that lock. The
  scanner's index of what live processes use read every process's command
  line, for names and working directories it gets elsewhere; it no longer
  does. The build inspection before each deletion batch must read build
  tools' environments and arguments, so on Linux each read now runs on a
  helper thread and is abandoned at the inspection's 30-second deadline.
  A process whose read is stuck counts as not inspected, so the batch
  waits as for any incomplete check. It costs one blocked thread until it
  recovers, not one per sweep.
- **An unexpandable `CARGO_BUILD_BUILD_DIR` holds the batch** (`3b45c3d`).
  A build-dir template (`{workspace-root}`, `{cargo-cache-home}`, ...) in
  a build's environment was skipped silently, though the same template in
  a Cargo config file already held the batch. Both now do; the build's
  other declared directories stay protected either way.
- **Protection refusals are reported as refusals** (bd-drua; `30f55e1`).
  A candidate the daemon's executor refused because it is protected (an
  `.sbh-protect` marker, a sacred path, or a protection check that failed
  and is treated as protected) was counted under `target_free_reached`,
  documented as "not a refusal — a success". It is now `sacred_stowaway`.
  A batch cut short by shutdown reports the new `shutting_down` reason and
  no longer puts the rest of the batch on per-path backoff.
- **Naming what fills an unreclaimable mount stays bounded and can't stall
  the monitor** (`5b4bc8e`, `4e8036b`). When a mount under pressure has
  nothing sbh can delete, the daemon reports its largest directories. That
  probe restarted its budget for each directory and ran on the monitor
  thread. One entry and time budget now covers the whole mount, the
  monitor waits a bounded time and never on a stalled probe, symlinks are
  not followed, and a cut-short inventory reports its sizes as lower
  bounds.

### Changed

- **Scan workers hand their results over in batches** (bd-vf9z;
  `7eac2c7`). Each walker thread sent one message per directory, so the
  collector waited on the channel, spinning and then yielding, once per
  directory; on a loaded Mac the daemon's scanner thread spent about a
  third of its time in those yields. Workers now send up to 64 entries at
  a time, and whatever they hold before they wait for more work. Scanning
  a 200,000-directory tree took 82–95% fewer voluntary context switches
  and 16–21% less user CPU, in the same wall time.
- **Memory pressure no longer flaps between levels** (`14530fe`). On
  Linux, memory pressure is the kernel's 10-second stall average against
  fixed thresholds (Warn 5%, Critical 20%). With the average hovering near
  5%, the daemon switched between Normal and Warn every few seconds (up to
  31 behavior changes an hour on one host), changing how aggressively it
  scans each time. A level is now left only once the average falls a
  fifth below its threshold. And a host that goes quiet after pressure is
  now seen to recover: the daemon checked again only when a new stall
  occurred, so it could stay at Warn or Critical indefinitely.
- **The RSS warning no longer repeats every minute** (`13e8d5c`). While RSS
  stayed over the warning level (256 MiB), the daemon logged the same
  warning on every state write, about 1,440 lines a day on a host whose
  tree needs ~300 MiB. It is now logged when RSS crosses the level, then
  hourly or after another 64 MiB of growth.

## v0.7.6 **[release]**

Compare: [`v0.7.5...v0.7.6`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.5...v0.7.6)

A safety release. sbh v0.7.5 could delete the target directory of a build
offloaded with `rch exec`, because it didn't count `rch` as a build process,
and under Critical pressure it could choose to delete an empty directory,
which frees nothing. A user-scoped macOS sbh could delete a small candidate
that another user's process held open. Generated systemd units now give the
daemon room above its own memory limit and cap glibc's malloc arenas. Also:
`sbh check` honours the absolute free-space floors, the root `install.sh`
honours `--dest`, a `kill -USR1` scan is no longer dropped, the activity
log's RAM fallback keeps clear of a full RAM filesystem, and sbh's HTTP
User-Agent names sbh.

### Fixed

- **An offloaded `rch` build's target directory counts as in use**
  (`eb43d58`). `rch exec -- cargo build` compiles on a worker, so the only
  local process is `rch`, which sbh did not treat as a build process, and
  nothing holds the `CARGO_TARGET_DIR` open until the artifacts sync back.
  On a dispatcher, v0.7.5 deleted a live build's fresh, empty target
  directory eight minutes into the build, and the sync-back recreated it.
  `rch` now counts as a Rust build process, so the `CARGO_TARGET_DIR` and
  cargo home named in its environment are in use while it runs.
- **The planner never deletes an empty candidate** (`eb43d58`). At
  Critical pressure with no risk budget, it could choose a 0-byte candidate,
  which frees nothing and still risks a live directory. That empty target
  above was such a choice.
- **A `kill -USR1` scan is no longer dropped while the scanner is busy**
  (`911c776`). With the scan queue full, the forced scan was discarded
  after 100 ms while the log said "forced scan triggered". It is now
  retried every monitor tick until queued, and the log says when it was
  deferred and when it was queued.
- **`sbh check` honours the absolute free-space floors** (`bca8ba4`). It
  compared free space with the Yellow percentage alone and ignored the
  `*_min_free_bytes` floors that the daemon's levels use, so a large disk
  with hundreds of gigabytes free could still fail the check: `sbh check
  --need 20G` exited 1 on a 3.6 TiB volume with 453 GB free. `check` now
  uses the daemon's Yellow line for that volume; `--target-free` still
  overrides it.
- **The root `install.sh` honours `--dest` and refuses unknown arguments**
  (bd-fgxo; `651445a`). It never parsed its arguments, so `--dest /opt/x`
  installed to `$SBH_INSTALL_DIR` or `/usr/local/bin` and, run as root,
  silently replaced the system daemon's binary. It now takes `--dest`,
  `--version` and `--help`; anything else exits 2 before downloading.
- **A user-scoped macOS sbh no longer deletes what it cannot check**
  (bd-1ouz; `645e0d2`). Run without root, macOS hides other users' open
  files. The v1 scanner refused every candidate for that reason, but the v2
  scanner, its index replay, and the CLI's `clean`, `emergency` and `scan`
  checked open files only for large candidates outside cache categories, so
  a small candidate could be deleted while another user's process held it.
  Every path now refuses such candidates, and `clean`/`emergency` print a
  hint to run `sudo sbh <command>` or the system-scope daemon. Root sbh and
  every Linux sbh are unchanged.
- **The activity log's fallback and mirror stay off a RAM filesystem that
  is short of room** (`c0fa218`, `01b8cc1`, `1165983`). A fallback or
  mirror log on tmpfs is used only while the host has at least 10% of its
  RAM available, its filesystem 20% free and, if it has swap, 10% of the
  swap free; counters that can't be read or don't add up count as a
  refusal. The check runs on open, recovery, writes, flushes, idle ticks
  and shutdown. A refused mirror stops while the primary log carries on; a
  refused fallback sends later records to stderr and drops its pending
  buffer instead of flushing it into RAM. sbh prints `[SBH-JSONL]
  fallback/mirror refused` at most every 30 seconds. The 16 MiB cap on the
  fallback and mirror now holds for a single oversized record and after a
  failed rotation, and a handover no longer opens the same file with two
  writers. Details in `docs/ram-scratch.md`.

### Changed

- **Generated systemd units cap memory at 768M, above the daemon's own
  limit** (`cb6e62c`). `MemoryMax=256M` sat below the daemon's 500 MiB RSS
  hard limit, so on a tree that needed more than 256 MiB the kernel
  killed the daemon, possibly mid-deletion, before it could exit cleanly
  and be restarted. A host scanning 500k entries per pass needs about
  290 MiB. Existing installs keep their unit until `sudo sbh service
  --systemd reinstall-unit` rewrites it (or a drop-in sets the two
  `[Service]` lines `MemoryMax=768M` and `Environment=MALLOC_ARENA_MAX=2`).
- **Generated systemd units cap glibc malloc arenas at two** (`8da899d`).
  glibc keeps a malloc arena per scanner thread along with its freed pages,
  so on a large tree the daemon's RSS settled at about twice its live set:
  on a host scanning 500k entries per pass it reached 480–499 MiB and once
  exited on the 500 MiB hard limit. With `MALLOC_ARENA_MAX=2` it held at
  about 290 MiB for an hour at the same scan CPU. Units written by other
  installers can add the line in a drop-in.
- **sbh identifies itself honestly in HTTP requests** (`2eb0210`). The
  updater, release-asset downloads and webhook notifications sent a
  User-Agent borrowed from other companies' clients. They now send
  `sbh (+https://github.com/Dicklesworthstone/storage_ballast_helper)`.

## v0.7.5 **[release]**

Compare: [`v0.7.4...v0.7.5`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.4...v0.7.5)

A safety release. sbh v0.7.4 and earlier could delete a Python virtual
environment that a long-running job was still using, because uv marks every
venv with a cache tag, and could delete a freshly copied or moved temp tree
two minutes after it arrived when the disk was under pressure. This release
also adds `sbh relocate`, and `sbh compress` no longer rewrites files inside
Git repositories.

### Fixed

- **A Python venv is not a cache because uv tagged it** (bd-tx4l). uv writes
  a `CACHEDIR.TAG` into every venv it creates so that backup tools skip it.
  sbh read the tag as "regenerable cache", so an idle venv whose name matched
  no pattern was reclaimable at any pressure, including Green. On one host
  sbh quarantined three venvs of a running job between uses, and the job's
  next step failed with `ModuleNotFoundError`. A tag beside a `pyvenv.cfg`
  is no longer cache evidence (`24be113`).
- **A tree that has just arrived keeps its real age under pressure**
  (bd-macg; JE's policy decision). At Orange or above, a classified artifact
  in a temp root seen for two minutes was treated as old enough to delete.
  That shortened the wait for trees that had just been copied, moved or
  extracted, not only for old trees with fresh contents: a fresh copy of
  relocated scratch was deleted five minutes after it was made. A
  candidate whose root was born or moved into place less than the minimum
  age ago now keeps its real age; an old build tree with fresh writes inside
  is still fast-tracked (`1426666`). This does not make a temp root a safe
  place to keep a copy: once older than the minimum age, it is reclaimable.
  Protect such a copy with `sbh protect`, or keep it outside the scan roots.
- `sbh compress` skips files inside Git work trees and repository internals
  (bd-1p9j; `9d9a1bf`, `b9cafb1`).
- `sbh explain --why-not <dir>` walks only the directory it explains. It
  walked every sibling as well, so in a crowded `$TMPDIR` on macOS it did not
  finish in three minutes (bd-g3g3; `898d309`).
- **The socket evidence fails closed** (`9916f43`, `a828c3c`). A
  `/proc/net/unix` table that cannot be read, is too large, or is malformed
  or truncated no longer counts as "no socket here": the sweep is incomplete
  and the batch is held, as for any other unreadable process evidence. A
  socket bound to a relative path names no file and holds nothing; Postfix
  binds its sockets that way, and holding on them would have stopped all
  reclaim on any host running it.
- **A stop requested while the first start is still writing ballast is not
  held off** (`7d96b0b`). The start-timeout extension added in v0.7.4 also
  extended systemd's stop timeout, and provisioning ignored the request
  until every pool was full; `systemctl stop` waited minutes. Provisioning
  now stops before its next file, and the extension ends with the stop
  request.
- `sbh install --ballast-count` and `--ballast-size` reach the config it
  writes, so the daemon keeps the ballast the install was told to provision
  instead of the default 10 x 1 GiB per pool (bd-ncxh; `c77b89f`).
- **Writeback tuning is never applied from inside a container** (bd-pivw;
  `59bda6e`). `vm.dirty_*` is shared with the host, so `sbh install` or
  `sbh tune --apply` in a privileged container set the host's limits, sized
  for the container's view. Under Docker, Podman, systemd-nspawn or LXC sbh
  now writes no sysctl snippet, applies nothing, and says to tune on the
  host.
- **The log is not mirrored into RAM that is already short** (bd-ffjj;
  `0ab5535`, `b36e956`). When the log's own disk is pressured the daemon
  copies its log lines to `/dev/shm`; it did so even with `/dev/shm` nearly
  full and swap exhausted. It now copies only while `/dev/shm` has a fifth
  of its space free and swap is not nearly full, re-checks every 30 seconds,
  and logs why when it stops or skips the copy.
- **Locks are released when sbh lets go of them, even while it is starting
  another process** (`b9e925f`, `ddc6a16`). A lock stayed held for as long
  as a child process being started still had a copy of its descriptor.
  So the daemon's next ballast replenish could find the pool "busy" right
  after a release. And `sbh compress --recover-journal`, run just after a
  pass, could report that pass as still running. Both locks are now
  released explicitly, and recovery also waits up to two seconds for a lock
  before calling a pass live.
- `install.sh` reads the latest release tag from GitHub API responses
  served as one-line JSON, where it took part of the release notes as the
  version (`8023aa9`).

### Added

- **`sbh relocate`** (`0991337`, `91f0464`): moves a protected scratch tree that
  has been dormant for weeks to another disk or host and leaves a stub in its
  place. **It does nothing after install:** it moves nothing unless
  `/etc/sbh/relocation.toml` sets `enabled = true` and a `target`, and turning
  it on is a per-host decision. Without that, `sbh relocate` only reports.
  - Linux only for moves; macOS can report.
  - Only `/tmp`, `/var/tmp`, `/dev/shm` and `/data/tmp` are considered, never
    home or project trees. Cargo, rch, cass and agent-mail paths are never
    moved, and a marker can opt a tree out (`relocatable = false`).
  - A tree qualifies only if nothing in it has changed or been read for 14
    days (on a `noatime` mount, 14 days of observation first), no process
    holds it, it is at least 256 MiB, and it crosses no mount.
  - A move copies, verifies the copy by checksum, re-checks the tree, writes
    the stub, and only then removes the original, without crossing into any
    other mount. `sbh relocate --restore <stub>` brings a tree back; a stub
    something else has written into is kept aside and reported.

### Documentation

- The README explains how to verify a release: the minisign public key
  (key id `1BBD79B28BF718D0`) and the commands that check the signed
  manifest and an archive against it (`ca1b62a`).

## v0.7.4 **[release]**

Compare: [`v0.7.3...v0.7.4`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.3...v0.7.4)

A safety release. sbh v0.7.3 and earlier could delete the directory of a
server that was still serving a Unix-domain socket from it, because socket
descriptors were invisible to the in-use check. This release also lets a
fresh system install start on its first attempt, stops a refused candidate
from being planned again on every pass, and adds a read-only check of tmpfs
scratch against RAM and swap and an opt-in Btrfs compression command.

### Fixed

- **A process serving a Unix socket now holds the socket's directory**
  (bd-zx8b). The in-use check read only descriptors that carry a file path.
  On macOS a socket descriptor is not a file, and on Linux it shows only as
  `socket:[inode]`, so a directory holding nothing but a served socket looked
  unused at any age: tmux's `/tmp/tmux-<uid>`, an ssh-agent directory, a
  launchd listener. On two Macs sbh deleted the `/private/tmp/com.apple.launchd.*`
  directories of a running iOS Simulator (`launchd_sim`, `testmanagerd`),
  after which XCTest and the Web Inspector could no longer reach it. sbh now
  resolves socket descriptors to the path they are bound to:
  `PROC_PIDFDSOCKETINFO` on macOS, `/proc/net/unix` on Linux. This covers
  scoring and the deletion preflight's last check (`8eff34e`).
- **A fresh system install starts on the first try.**
  - `sbh install --systemd --scope system` creates every directory it lists
    in `ReadWritePaths=` before it enables the unit. A missing one made
    systemd fail the unit with `226/NAMESPACE` (bd-2dzx; `10dd6ce`,
    `c60b38a`).
  - The daemon writes its ballast before it reports ready. On a fresh host
    that can be gigabytes per pool, written as random data on Btrfs, ZFS and
    bcachefs, and it outlasted the unit's 30-second start timeout: 20 GiB took
    45 s. systemd killed the first start. Repeated timeouts can reach
    systemd's start limit and leave the service failed. The daemon now asks
    systemd for more time (`EXTEND_TIMEOUT_USEC`) every 10 s while it
    provisions, for up to 15 minutes (bd-yqg0; `1416b93`).
- **A candidate that is always refused is not planned on every pass**
  (bd-pb40). A uv cache, which the deletion preflight refuses because it
  holds Git checkouts, was planned 72 times in a few hours on one host and
  over a hundred on another, and every pass counted as dispatched but freed
  nothing. The per-path backoff meant to stop this never held. The scanner
  index was keyed on each pass's roots and was rebuilt on about half the
  passes, and the pre-scan and the walk each reset the other's backoff.
  The index is now kept across passes over different roots, and the backoff
  stays with the directory until the directory itself changes (`d71e452`).
- The `[SBH-SAFETY] open-file sweep incomplete` line names a refused build
  tool first, with the number of other refused processes. Before, it named
  the first refusal, usually pid 1 (bd-3maz; `af41970`).

### Added

- **`sbh check --ram-scratch`** (Linux, read-only; bd-ffjj). It compares what
  the tmpfs mounts (`/tmp`, `/dev/shm`, `/run`, `/run/user/<uid>`) hold
  with host RAM and swap. It warns when they hold more than half of RAM, or
  when swap is nearly full and they hold more than all processes have
  swapped out. On a warning it names the largest top-level entries with
  owner and idle hours. On one host idle agent scratch had filled all 64 GiB
  of swap while sbh reported only "/dev/shm 20% free". The daemon samples the
  same check every five minutes and logs a risk at most every 15 minutes. It
  adds no deletion roots (`22ec3b4`, `ddbfa04`, `ad0d3f9`).
- **`sbh compress`** (Linux x86-64 and AArch64 on Btrfs; bd-rxq5): lossless
  zstd compression of cold, unshared files named explicitly. Preview is the
  default. Applying needs `--apply` with both `--allow-zstd-feature` and
  `--quiescent`. Each change is recorded in a journal before and after it
  happens.
  - `--discover` lists cold candidates under directory roots without changing
    anything.
  - `--recover-journal` inspects an interrupted run.
  - `sbh explain --id compress:RUN:SEQ` explains one operation.
  - Outcomes go to the activity log.

  Nothing is compressed automatically. See `docs/btrfs-compression.md`
  (`f021401`, `ed3be77`, `4a80038`, `9a25898`, `e6cbc44`, `47d4be5`,
  `f569683`, `9bf82e2`, `f1c1adb`, `42d74fa`, `e4c3478`).

### Changed

- Linux: one `/proc/<pid>/maps` pass now serves all scan roots, instead of
  one per root (`5bb8269`).

### Known limitations

- Socket evidence covers sockets in sbh's own network namespace and sockets
  bound to absolute paths. A server inside a container with its own network
  namespace, or one that bound a relative path, is not seen.
- `sbh compress --discover` does not check live processes or physical extents.
  Preview and apply of the selected files do.

## v0.7.3 **[release]**

Compare: [`v0.7.2...v0.7.3`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.2...v0.7.3)

A safety release. sbh v0.5.0 through v0.7.2 could delete the `registry/`
and `git/` caches of a cargo home that a running build was using: rch
renames cargo `cargo-rch-real`, and neither that name nor build scripts
counted as a build tool, so a live build's default `~/.cargo` was
unprotected (bd-d1kt). v0.7.3 holds such caches on Linux and macOS, and an
idle daemon no longer spends a large share of a core rescanning a busy temp
root (bd-os02).

### Upgrade note: `sbh update` from v0.7.2

- The update from v0.7.2 is performed by v0.7.2's updater. Where sbh runs
  from outside `/usr/local/bin` and `/usr/bin` (for example `~/.local/bin`),
  that updater installs v0.7.3 and then exits 2 with "could not locate sbh
  binary", leaving the service on the old binary (#35). Restart the service
  once (`systemctl restart sbh`, or `systemctl --user restart sbh` for a
  user install). `install.sh` is not affected, and updates from v0.7.3 on
  restart the service themselves.

### Upgrade note: rollback snapshots

- `sbh update --rollback` now refuses a snapshot without a recorded SHA-256.
  Snapshots taken by v0.7.2 and earlier have none, so they cannot be rolled
  back to; the first update made by this release takes a verifiable one.

### Known limitations

- macOS withholds the environment of Apple platform binaries (Xcode's
  `clang` and `swift`, `/usr/bin/python3`) from every other process, root
  included. For a build run by one of those, sbh sees its working directory
  and open files but not the caches its environment names. Builds run by
  rustup's cargo and rustc or by Homebrew's tools are seen in full (bd-j7ho).
- A daemon that cannot inspect every process (a user-scope install, or a
  daemon without `cap_sys_ptrace`) holds every batch while such a process is
  running instead of guessing. On such hosts it reclaims little (#27).
  The `[SBH-SAFETY] open-file sweep incomplete` line such a daemon logs
  names the first process it was refused, usually pid 1, rather than the
  build that matters (bd-3maz, fixed after this release).
- On a fresh host, `sbh install --systemd --scope system` can list
  `ReadWritePaths=` entries that do not exist yet, and the unit then fails
  with `226/NAMESPACE`. v0.7.2 does the same; create the listed directories
  and restart the unit (bd-2dzx).

### Changed

- **Caches are checked for in-use evidence at any size.** Scoring used to
  probe live processes only for candidates of at least
  `active_reference_min_size_bytes` (100 MiB). A small cache under a running
  build was nominated with no evidence at all; in a real-build test a fresh
  62 MB default `~/.cargo` was approved and only the deletion preflight
  stopped it. Cache candidates (`cachedir-tagged-cache`, cargo stores, catalog
  caches, Go caches) are now always probed. When the probe cannot complete,
  the candidate is vetoed with the reason, never approved. `sbh explain
  --why-not` now always probes, as its documentation said (`e9b5c55`).
- **Empty-pass backoff survives a threshold that flaps.** A rise in pressure
  since the last pass clears the backoff. A host whose free space hovers at
  the Red line crossed it every minute or two and never reached the
  terminal-idle pacing: one host reset its backoff 365 times in 6 hours and
  ran 816 passes, 723 of them finding nothing. A return to a level that came
  back empty within the last five minutes now keeps the backoff; a rise above
  it still resets it (`cdbdb75`).
- Default npm, pip and uv caches count as in use while a package manager
  runs: `~/.npm` for npm and npx, `~/.cache/pip` (macOS:
  `~/Library/Caches/pip`) for pip, and uv's cache under `XDG_CACHE_HOME` or
  `~/.cache/uv`, unless an explicit override names another place. A plain
  node or python process implies none of them (`d5392cf`).

- #33 source-root detection is report-only in this release; enforcement is
  pending a narrower definition. `sbh doctor` lists each scanner root with
  any Git work tree found beneath it, or `unverified` when the bounded
  inspection could not finish, and `sbh doctor <target>` and
  `sbh config validate` print the same findings as warnings. They do not
  change `valid` or the exit code, and nothing is refused: on real hosts every
  temp root holds a checkout or exceeds the inspection budget.

### Fixed

- sbh no longer deletes the cargo home of a running build (bd-d1kt). Under
  Orange or higher pressure, the `registry/` and `git/` of a live cargo home
  were reclaimed minutes after creation: on the rch workers the shared cargo
  cache was deleted under running builds again and again (eleven times on
  one host in a day), and the builds failed with their dependency sources
  gone. Three causes are fixed:
  - under pressure, a cache seen for two minutes was given the minimum age
    at once. No cache of any kind, and no cargo home by name, is shortened
    that way now: it has to be its real age. In a real-build test on macOS a
    default `~/.cargo/registry/src` extracted 174 s earlier was deleted at
    "age 300 s" under the running build;
  - sbh 0.7.2 and earlier did not recognise cargo when rch has renamed it
    `cargo-rch-real` (the usual name on hosts with rch), nor build scripts,
    as build tools. A live build's default-home cache was therefore
    unprotected whenever only those were running, even though the evidence
    was there to read. Both are recognised now, and both run with cargo's
    environment;
  - a process whose working directory is inside a tree now counts as using
    it;
  - on Linux, the cargo home and target directory of a running cargo or
    rustc count as in use for as long as it runs: `CARGO_HOME` and
    `CARGO_TARGET_DIR` from its environment, or `$HOME/.cargo` when it sets
    no `CARGO_HOME`. Builds from the default home were hit almost as often:
    in one 12-hour window of fleet logs, 15 of 35 deletions of
    `~/.cargo/registry` and `~/.cargo/git/db` stores were recreated under a
    live process.
  `sbh explain` names the process and the reason. Affected: v0.5.0 through
  v0.7.2 (`53942a3`, `5a6f04a`, `11a609c`).
- macOS: live builds are now held. A build holds its caches as it does on Linux: sbh reads a
  process's working directory (`PROC_PIDVNODEPATHINFO`) and the environment
  and arguments of recognised build tools (`KERN_PROCARGS2`), including
  `python -m pip` and Node-hosted npm, through bounded read-only calls in
  `sbh_mach` (`538f362`, `22491fa`, `4efa6a6`).
- A cache or output directory a live build names protects everything below
  it, also when the candidate is reached by another spelling (a symlinked or
  bind-mounted parent), in both unlink and quarantine mode (`3b821ff`,
  `c17cb96`).
- Linux: a refused read of a process's working directory, or of a build
  tool's environment, makes the deletion preflight's process sweep
  incomplete, and the batch is held (`open_scan_incomplete`). Before, the
  refusal was ignored and that process counted as using nothing. The journal
  names the pid and the file (`e9b5c55`).
- On Linux, live builds of other toolchains hold their caches the same way
  (bd-j7ho): Go's build and module caches (`GOCACHE`, `GOMODCACHE`,
  `GOTMPDIR`, or their defaults under `XDG_CACHE_HOME`, the first `GOPATH`
  element and `$HOME`), npm's (`npm_config_cache`), uv's and pip's
  (`UV_CACHE_DIR`, `PIP_CACHE_DIR`), and sccache's and ccache's
  (`SCCACHE_DIR`, `CCACHE_DIR`). sbh reads these only from the environment of
  a process with a recognised build-tool name; a cache no live build names
  stays reclaimable (`40f15f3`, `11a609c`).
- A candidate directory the scan recognises by its contents (a
  `CACHEDIR.TAG`, for one) is measured before it is planned (bd-3rlm). It
  carried only the size of its immediate files: two candidates planned at
  4 KiB each freed 2.5 GB, so the pass met its byte target only on paper,
  kept choosing, and reported the paper size as freed (`122d355`).
- `sbh update --rollback` verifies a snapshot before it replaces the
  installed binary (#35). Each snapshot records its size and SHA-256 when it
  is taken, and rollback checks the private copy it is about to publish, so
  a missing, symlinked, resized or corrupted snapshot is refused and the
  installed binary is left as it is (`972f8f8`, `b021028`, `d560b32`,
  `bed564e`).
- sbh no longer treats a candidate as "open" because its own scanner was
  still walking it. The open-file sweep and the active-reference index
  counted sbh's own directory handles, so a candidate examined or dispatched
  while the scan was still in progress was vetoed or skipped, backed off, and
  its mount could sit idle for a whole rescan interval (90 s by default) with
  space to reclaim. sbh's own regular files and every other process's
  handles still count. In a Linux container the reclaim end-to-end test that
  hit this passed 6 of 6 runs with the fix against 4 of 6 and 5 of 6 without,
  and the quarantine-drain test, which had failed in every container run,
  passed 6 of 6 (`add621c`, `6725772`).
- Linux: a watch-coverage rebuild whose worker is stuck in a kernel call (a
  hung network mount under a scan root) no longer leaves earlier coverage
  trusted indefinitely (#30). After 30 s the rebuild is treated as failed,
  every root is marked dirty and the index generation is bumped, and that
  repeats every 30 s while the worker stays stuck (`d90bb12`).
- The predictive rescue no longer releases ballast and cleans up on a mostly
  empty disk (#29). Its second, "corroborating" runway was the first forecast
  rescaled after the conformal correction had already shortened it. It is now
  the measured free bytes at the median rate of the intervals that consumed
  space; intervals that freed space no longer count as consumption
  (`f970594`).
- Linux: a damaged ballast slot is repaired where a seccomp filter blocks
  `openat2`, as systemd's `RestrictSUIDSGID=` does (#28). Repair now falls
  back the way confined deletion has since v0.7.2: `openat` plus a mount-ID
  check, which still refuses a file bind-mounted onto the slot (`864adf2`).
- A host whose deletions reclaim nothing (dry-run, observe mode, or every
  candidate failing, as under `RestrictSUIDSGID=` with 0.7.1) now backs off
  its rescans (#36). The empty-pass streak never grew past one, so such a
  host rescanned at the base interval for as long as it lasted (`fa3837e`).
- A confident prediction that a mount is about to turn red gets its scan
  (bd-lihi). The prediction escalates the mount while it is still Green, so
  a Green maintenance walk already in flight could finish empty at the same
  level, park the mount and consume the prediction's wake. A maintenance walk
  or event-scoped pass that comes back empty no longer parks a mount that is
  reclaiming (`f0dd99c`).
- `sbh lease run` no longer stops a live build when part of its target cannot
  be measured (bd-am3p). A directory replaced by a file mid-walk (ENOTDIR) or
  a directory the watchdog cannot read (EACCES/EPERM, such as the mode-000
  directories permission tests leave under `target/tmp`) made the lease
  "invalid" and killed the build's process group. Those parts now go
  uncounted for that round. A replaced or symlinked target still stops the
  build, as does any other error (`49f8ea0`).
- Deletion now refuses a candidate that holds a Git repository or a
  `.sbh-protect` marker at any depth (bd-jydu). Every containment check
  stopped three levels below the candidate, so a clone deeper inside an
  agent's temp tree could be deleted. Below that depth the executor counts
  real repositories (a `.git` directory, or a `gitdir:` file such as a linked
  worktree), not uv's empty `.git` marker or a cargo git checkout. The walk
  is bounded at 250k directories and refuses the candidate when that runs
  out; the largest real caches measured opened 54k (`7f229fd`).

- An idle daemon no longer spends 10-46% of a core rescanning a busy temp
  root with nothing to reclaim (bd-os02). A pass cut short inside the priority
  pre-scan skipped the pass accounting, so the empty-pass cooldown never armed
  and a large `$TMPDIR` was rescanned every ~20 s at the CPU-budget ceiling;
  such passes are now paced like any other. Ancestor `.sbh-protect` probes are
  remembered within a pass, the quarantine sweep reads its records once
  instead of three or four times, and macOS caches the firmlink table
  (`9e0119e`, `4c4788e`).

- macOS: the launchd daemon runs at `ProcessType=Standard`, `Nice=5` instead
  of `Background`, `Nice=19`. macOS schedules by priority rather than by
  share, so under a saturated CPU a background or Nice 19 daemon got no time
  at all: on a Mac at load ~700 sbh wrote no state for 40 minutes and a
  four-entry scan took over half an hour. sbh's CPU budget and scan duty
  cycle still bound what it takes. Reinstall the service
  (`sudo sbh install --launchd --scope system`) to pick it up.
- A mount that is idle at Yellow with nothing left to reclaim now rebuilds
  its emptied ballast reserve (bd-7spb). Replenishing had waited for Green,
  which a large volume running hot may not see for days; provisioning still
  keeps free space above the Orange floor, so a refill cannot itself
  trigger a release.
- Linux: `sbh update` restarts the service with the new binary when sbh runs
  from outside `/usr/local/bin` and `/usr/bin` (for example `~/.local/bin`).
  It had applied the update, then exited 2 with "could not locate sbh
  binary" and left the service on the old binary (#35).

## v0.7.2 **[release]**

Compare: [`v0.7.1...v0.7.2`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.1...v0.7.2)

A fix release. Under a systemd unit with `RestrictSUIDSGID=`, sbh 0.7.0 and
0.7.1 could not delete anything; v0.7.2 can. It also stops treating a
directory as build output on a `*-target` name alone (#34).

### Upgrade note: hosts with an `openat2` workaround

- If a host runs sbh with a drop-in that sets `RestrictSUIDSGID=false` to work
  around the failure below, remove the drop-in after upgrading to v0.7.2.

### Known limitations

- The `openat2()` fallback below needs `statx` mount IDs (Linux 5.8 and
  later). On an older kernel, deletion and quarantine purge still fail closed
  (issue #28).
- In-place repair of a ballast file with a damaged header has no fallback.
  Under `RestrictSUIDSGID=`, or on a kernel without `openat2()` (before 5.6),
  that repair fails and leaves the file as it is; the file can still be
  released by the ordinary pressure path.

### Fixed — safety and reclaim under a hardened systemd unit

- Every deletion failed with "Function not implemented (os error 38)" when the
  sbh unit sets `RestrictSUIDSGID=`: systemd's seccomp filter for it returns
  `ENOSYS` for `openat2()`, which sbh 0.7.x used, failing closed, to open each
  directory without crossing a mount. The open now falls back to
  `openat(O_NOFOLLOW)` and keeps the directory only when `statx` reports the
  parent's own mount ID, so a bind mount is still refused; a kernel without
  mount IDs still fails closed (`329e75f`). On trj and vmi1227854 no deletion
  had succeeded since 0.7.1.

### Added

- Optional absolute free-space floors per pressure level:
  `pressure.green_min_free_bytes`, `yellow_min_free_bytes`,
  `orange_min_free_bytes` and `red_min_free_bytes`. A level's threshold becomes
  the smaller of its percentage and its floor, so a large volume is not called
  pressured at a low percentage that still leaves plenty of space. Off by
  default (all zero); when set, all four must be given in descending order
  (`eba87f2`).

### Fixed

- Safety: a directory named `<prefix>-target` or `<prefix>_target` is treated
  as build output only when it carries cargo's own root markers (a validated
  `CACHEDIR.TAG`, `.rustc_info.json`, or a `debug/`, `release/`,
  `.fingerprint/`, `deps/` or `incremental/` directory). On the name alone,
  the classifier nominated such directories, and the source-tree floor let
  them through, so fixtures deliberately named `invalid_target` and
  `ambient-target` inside non-git release-evidence trees were deleted
  (`0d9a52f`; issue #34). Exact names (`target`, `node_modules`, ...) and the
  `.rch-target-*` / `target-*` forms are unchanged; a real stranded
  `CARGO_TARGET_DIR` keeps its markers and stays reclaimable.
- A mount on the same filesystem as another (folded onto it, sharing its
  ballast pool) kept its own ballast release state when it was the pressured
  mount. That state was never saved, so a restart released the same shortfall
  again, and every state write reset it. With both mounts pressured the pool
  could drain completely where three of five files were enough. Release
  history, cooldowns and the floor flag are now kept under the pool's own
  mount (`2c2f99f`).
- `sbh status`, `sbh doctor`, `sbh ballast` and the TUI read a configured
  `paths.ballast_dir` that is a symlink through to its target, as the daemon
  already did. With an alias configured, `sbh status` had reported a
  provisioned reserve as indeterminate, with every file unreadable
  (`8818aa4`).
- When the active-lease watchdog stops a build, its log line and error name
  the reason, including the I/O error from inspecting the target, instead of
  only "invalid" (`dd11f40`).

## v0.7.1 **[release]**

Compare: [`v0.7.0...v0.7.1`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.7.0...v0.7.1)

### Upgrade note: source trees under `scanner.root_paths`

- This applies to v0.7.0 as well. If a scan root contains Git repositories,
  sbh reclaims untracked build output inside them, as the v0.6.24 release
  did. Since v0.7.0 it also asks Git what is tracked and keeps that; a root
  daemon asks as the repository's owner.
- Builds of `main` made between 2026-10-05 and 2026-10-08 also report
  `0.6.24`, and under a root daemon they kept every in-repo candidate,
  because that query failed with "dubious ownership". A host running one of
  those will see reclaiming inside repositories resume when it upgrades.
- If source trees must never be cleaned, remove them from `root_paths`, or
  mark them with `.sbh-protect`, before upgrading.

### Fixed — safety: tracked Git content on case-insensitive filesystems

- Tracked Git content is matched without regard to case. On a
  case-insensitive filesystem (the macOS default) a tracked directory whose
  on-disk case differs from the Git index, such as a tracked `Build/` renamed
  to `build/`, read as untracked, so the tracked-content veto did not protect
  it. On a case-sensitive filesystem this can keep an untracked `build/`
  beside a tracked `Build/`, which errs toward keeping (`1100bad`).

### Changed

- macOS: `sbh status` warns, and `sbh doctor --system` fails a
  `reclaim.privilege` check, when the sbh that reclaims is not root. A
  user-scope sbh there refuses every candidate it must walk and every
  candidate of 100 MB or more, so almost nothing is reclaimed; that has been
  so since before v0.7.0 and was not reported. The remedy is a system
  LaunchDaemon: `sudo sbh install --launchd --scope system` (`01d8780`).
- A deletion batch aborted because the open-file or process scan was
  incomplete is logged as `SBH-3005` and names its cause: no root, or a scan
  that could not read every process within its limits. It had been logged as
  `SBH-3003`, which the catalog gives to a closed daemon channel (`c82411e`;
  issue #27).
- `[profile.release]` says `opt-level = 3`. v0.7.0's binaries were already
  built that way through an environment override; the profile had still said
  `"z"` (`1d2b3da`).

## v0.7.0 **[release]**

Compare: [`v0.6.24...v0.7.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.24...v0.7.0)

**Scope.** Everything on `main` since v0.6.24. A v0.6.25 was prepared on
2026-10-08 and never tagged or published (issue #26 held it); its entries are
included here. The minor version changes because two behaviours change for
existing Linux installs; read the upgrade notes first.

### Upgrade notes

- **Linux: sbh must run as root to reclaim by scanning.** The open-file,
  executable and memory-map sweeps now fail closed: if any process cannot be
  inspected, the scan is incomplete and every candidate is refused. A normal
  user cannot read root-owned processes, so a user-scope daemon, `sbh clean`
  and `sbh emergency` run without root free nothing. Ballast release still
  works. `sbh status` prints a warning and `sbh doctor --system` fails a
  `reclaim.privilege` check in that case. Install the daemon in system scope:
  `sudo sbh install --systemd --scope system` (`cb0125e`, `460661d`,
  `c49b533`, `a0b99c7`, `a795b8a`; issue #27).
- **Linux: deleting a directory tree needs `openat2(2)`.** Permanent deletion,
  quarantine purge and in-place ballast repair walk through verified directory
  handles and have no fallback on kernels older than 5.6 or where seccomp
  filters the call; there they refuse and keep the data (`57a8f79`, `405d585`,
  `d40d4bf`; issue #28).
- Saved scan evidence is revoked at every start, so expect reconciliation
  scans after the upgrade (`b50984c`).
- The default `scanner.root_paths` no longer lists `/data/tmp` outside Linux
  (`6545e88`).

### Security — a root daemon queries Git as the repository's owner

- **Security-relevant behaviour change.** The tracked-content check below
  ran `git ls-files` as root under the Linux system-scope daemon, and Git
  refuses a repository another user owns ("dubious ownership"), so every
  candidate in users' repositories was kept and none of their build output
  was reclaimed. A root daemon now runs that one query as the owner of the
  repository's Git directory, with that user's primary group and no
  supplementary groups, instead of trusting the repository's configuration as
  root. `git` is looked up only in root-owned directories and runs with a
  scrubbed environment, a 10 s deadline, bounded stderr and discovery pinned
  to the repository, and "untracked" requires Git's own unmatched-pathspec
  message. A symlinked `.git`, a malformed or swapped gitfile, mixed owners or
  a failed user lookup keeps the candidate (`c0281be`, `f494404`, `8ff4fc1`).

### Fixed — safety: what may be deleted

- Tracked Git content is kept. A deep repository or worktree subtree has no
  `.git` of its own, so one host deleted thirty tracked Lean `Lake/Build`
  source files. A candidate under a repository now passes only if
  `git ls-files --error-unmatch` finds nothing tracked in it; missing Git or
  a failed query keeps it. `.lean` counts as source (`2c54bfe`).
- Permanent deletion goes through verified directory handles and refuses a
  replaced root or parent and any nested mount. Only directory modes of Go
  and Cargo caches are widened, and an unreadable directory is refused rather
  than chmodded open. A refusal can leave a tree partly removed (`57a8f79`).
- The planner no longer picks a parent whose vetoed or suspended child is in
  the same batch, nor a child or alias of a vetoed entry. One directory seen
  under two spellings counts once toward the target and inherits a veto placed
  on either (`3cf1a01`, `8450490`).
- The executor rechecks a category's regret suspension just before each
  delete or quarantine, so candidates queued before an alarm are skipped
  (`category_suspended`) instead of deleted (`08cd42f`).
- Regret evidence: a recreation first seen after its window expired, and a
  path that could not be inspected, are "unknown" instead of a regret or a
  clean result; each window starts when that item's unlink completes and is
  timed at the observation, not the tick start (`2cea9f6`, `5577f70`,
  `c034e7e`, `f3194fd`).
- A filesystem event inside or above an indexed candidate clears its saved
  score, so it is rescanned before a pressure pass can replay it; evidence
  from before a restart is revoked (`9e3c42e`, `7146953`, `b50984c`).
- Cache evidence needs an exact `CACHEDIR.TAG` regular file with the valid
  signature. Any-case names, symlinks and special files no longer count, and a
  FIFO of that name can no longer block a scanner worker (`6404e2e`).
- Quarantine moves and restores use opened directory handles and recheck the
  source and parent; a swapped source or parent, or a candidate whose parent
  lies inside the store, is refused. Purge removes records through the locked
  store handle, and a drain skips an entry whose record changed between
  selection and locking (`1f17acf`, `e906896`, `e9775e6`).

### Fixed — Linux process and mount inspection

- The open-file sweep skipped processes whose descriptors it could not read
  and still reported a complete scan; a running program with an unreadable or
  non-UTF-8 name was dropped from the executable query; unreadable maps files
  were skipped. All three now mark the scan incomplete, within caps of 262,144
  descriptors and 64 MiB of maps (`cb0125e`, `460661d`, `c49b533`,
  `a0b99c7`). See the upgrade notes for what this means without root.
- `anon_inode:` and `socket:[N]` rows in `/proc/<pid>/maps` are mappings of no
  file. They were rejected as malformed, so on Ubuntu, where systemd-networkd
  maps BPF maps, a root daemon's coverage was incomplete and it reclaimed
  nothing (`179c0e7`; issue #25).
- A live directory literally named `... (deleted)` is no longer mistaken for
  an unlinked file (`c49b533`).
- One non-UTF-8 mount name made reading the mount table fail and disabled all
  pressure readings; the table is parsed as bytes. A malformed row is now an
  error for the whole table rather than a skipped line (`c3dc95a`).
- Capacity followed symlinks while the mount, type and RAM-backed lookups used
  the unresolved path, so a link into tmpfs mixed tmpfs capacity with the
  parent disk's identity. Paths are canonicalized first (`0f17092`,
  `6ae1a97`).

### Fixed — pressure readings and the daemon

- A cached reading is bound to its mount's device, type and resolved path,
  and a slow older probe cannot replace a newer one (`5217550`).
- macOS: name, counters and read-only flag come from one `statfs`; startup
  memory pressure is the kernel's level, not a Critical guess that blocked the
  first scan (`a62d895`, `f457e62`).
- macOS: a path on an external volume is measured on that volume. `a62d895`
  had attributed every `/Volumes/*` path to the Data volume, so Data pressure
  could delete on an external disk. Firmlinks and `synthetic.conf` links now
  resolve to a fixed point and mount points are compared in the same spelling
  (`8c6bde5`, `18992f7`, `a50eb77`; issue #26).
- Under Red or Critical with nothing reclaimable, passes that always timed
  out never counted as empty and rescanned about every 20 s; runs of them now
  reach terminal idle (`6545e88`).
- After a write failure a mount resumes reclaiming once a probe write
  succeeds, not once free space recovers (`e450990`); a late empty result no
  longer idles a mount that has since escalated (`c3f32d1`).
- A build lease is no longer judged invalid, killing its build (exit 143),
  when a file vanishes during the size walk (`4280e87`).
- Control socket: excess clients are refused without stalling the listener,
  each read or write has one overall deadline, malformed arguments are
  rejected (a bad ballast `mount` had meant every pool), and a restart no
  longer unlinks a live daemon's socket (`6259b9d`, `26bbf82`, `e92a9e6`).
- Forecast calibration: a full pending window now defers new forecasts
  instead of evicting unscored ones, and with too few samples the lower bound
  is 0 rather than derived from the worst past miss (`2759874`, `cb67d7d`).
- Logger: shutdown and the JSONL mirror toggle no longer block on a full
  queue, and shutdown waits at most 5 s for a writer stuck in I/O (`ac88f2c`,
  `6d12d55`).

### Fixed — scanning and event coverage

- Pressure scans rotate which root goes first; a bounded pass that always
  began with the dirtiest root never reached the rest (`218ecec`).
- The index drops a rebuilt path's old inode (stale identities piled up as
  high-scoring candidates); checkpoints use an exclusive temp file, fsync
  and a 64 MiB / 100,000-record cap (`000c854`, `a777d4a`).
- Linux inotify coverage decayed silently: moved-in trees got only a
  top-level watch, removed directories kept using the watch budget, and a
  failed startup never retried. Topology changes now trigger a bounded,
  background watch rebuild that keeps the old watches until it succeeds, and
  draining and watch retirement share a 50 ms budget per tick (`254f386`,
  `0870b65`, `6516db4`, `d601c4a`, `32e5cae`, `175c131`, `fc2d456`).
- A configured root that does not exist was a permanent coverage gap that
  caused repeated repair planning. Absent roots are tracked separately and
  rechecked every 30 s (`9d0c040`). macOS: a symlinked root such as `/tmp`
  gets FSEvents coverage (`6545e88`).
- Prescan reads each root in resumable slices and keeps unfinished reads
  across passes, with at most four roots in progress; its checkpoint is
  versioned, checksummed and holds non-UTF-8 paths (`ef580f0`, `3d389a5`,
  `97970d5`, `73eecab`).

### Fixed — quarantine and ballast

- Quarantine uses the deepest configured root on the candidate's own
  filesystem; purge walks the recorded payload by descriptor instead of
  `remove_dir_all`, entering no symlinked directory, other filesystem or
  bind mount, and keeps the record if refused (`cf4d1fc`, `405d585`).
- Batch drains share a step budget per call, so a large entry is purged over
  several sweeps and stays recorded meanwhile; a restore after a partial purge
  returns what remains (`d0181ae`).
- Ballast on ZFS: a new file was written, then unlinked, on every pass,
  because ZFS reports a file's blocks only after its transaction group syncs
  and the block count was checked straight after `fsync`. A payload written in
  full is now accepted on the completed write; block coverage is still checked
  on every later pass. An under-allocated creation ends the batch instead of
  repeating the write for each remaining file (`ce6b871`; issue #26).
- Ballast status counts only allocated, releasable reserve and finds pools
  configured through a symlink; surplus left by a lowered or disabled target
  stays releasable (`d8f3f2b`, `60b5624`, `9f0cd3f`, `3c89dfe`, `2b6e438`).
- Release counts observed depletion, not never-filled slots, so a partial
  pool helps at Orange/Red, not only at Critical; the credit survives
  restarts in `state.json` (`a6639f1`, `b7891ea`).
- Maintenance checks pools by bytes, not file count; repair works in place
  and keeps the file on failure; new files are created `O_EXCL` through a
  descriptor (`5503121`, `d40d4bf`, `5df350b`, `0644d3a`).
- A child holding an inherited lock descriptor no longer keeps the
  quarantine store or an adopted pool busy (`6b8cc2e`, `99746d9`).

### Changed

- With a byte target, the planner also tries lower-loss sets that still cover
  the target and drops redundant items, instead of one large risky item that
  overshoots (`221e1c5`).
- Imminent exhaustion is acted on even with over half the disk free when
  the calibrated historical rate agrees (`99cb919`).
- A config reload applies regret settings without a restart; pending watches
  keep their window and active suspensions are never shortened (`114515d`).
- Dependencies: the TUI crates come from crates.io (`ftui` 0.6.0) instead of
  a git tag; semver-compatible lockfile refreshes; `sbh_mach`'s Apple-only
  dependencies are macOS-only (`5d77619`, `115b199`, `7dbb3c4`).

### Known limitations

- Linux without root, and Linux without `openat2`: see the upgrade notes
  (issues #27, #28).
- macOS: a user-scope sbh (the default LaunchAgent install) refuses every
  walked candidate and every candidate of 100 MB or more, because it cannot
  see other users' processes. This predates this release (bead `bd-0nx9`).
- Ballast on a filesystem whose settled block count stays below the file
  size: such files fail verification on every pass and are rewritten in
  place each time. Not observed; inferred for some raidz geometries.
- The predictive rescue's two runways are derived from the same corrected
  forecast, so under steady writes it can release ballast and run a
  Green-level cleanup on a mostly empty disk. Scoring vetoes still apply
  (issue #29).
- The tracked-content query finds `git` only in fixed system directories
  (`/usr/local/bin`, `/usr/bin`, `/bin`, `/run/current-system/sw/bin`, plus
  the Homebrew and Linuxbrew prefixes for a non-root daemon); where `git`
  lives only elsewhere, such as a per-user Nix profile, candidates inside
  repositories are kept.

## v0.6.24 **[release]**

Compare: [`v0.6.23...v0.6.24`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.23...v0.6.24)

### Fixed — no more dispatching candidates the executor always refuses

- The scorer approved directories that the executor's source-tree floor and
  source-file check refuse every time: one host logged 902 refused plans in
  an hour, another backed off 58 times at Critical pressure because those
  passes "reclaimed nothing", and the scan index re-dispatched them on every
  pass. Both checks now also run at the end of the scorer's veto chain (the
  source-file check bounded to 4096 entries there); the executor keeps its
  own unbounded checks, so nothing becomes deletable that was not before
  (`75ad60a`).

## v0.6.23 **[release]**

Compare: [`v0.6.22...v0.6.23`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.22...v0.6.23)

### Reverted — the rch job TMPDIR rule (v0.6.21, v0.6.22)

- Neither release reclaimed a single `.rch-tmp`. With the scorer and the
  sacred layer past, the executor still refused every one: its source-tree
  floor, nested-`.git`, Cargo-manifest and source-file checks all match the
  test fixtures that live in a job TMPDIR, and those fail-closed layers
  exist because sbh once destroyed real working trees. Meanwhile each pass
  spent large idle probes and containment walks on candidates that could
  never be deleted. The code is back to v0.6.20's (`d1db715`). rch, which
  owns that directory and already prunes children idle >24 h, is the right
  place to sweep projects that stop receiving jobs.

## v0.6.22 **[release]**

Compare: [`v0.6.21...v0.6.22`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.21...v0.6.22)

### Fixed — idle rch job TMPDIRs are no longer protected by test fixtures

- v0.6.21's `.rch-tmp` rule reclaimed nothing: tests leave `git init`
  repos and SQLite files in their TMPDIR, which matched the built-in
  sacred markers, and the largest dirs exceeded the containment walk's
  directory bound. For a `.rch-tmp` (which rch itself prunes after 24 h,
  and which sbh only nominates once its whole tree is that idle) the
  built-in test-fixture markers (`.git/`, `.beads/`, `beads.db*`, `*.db*`,
  `*.sqlite*`) are no longer consulted. `.sbh-protect` markers, user
  `protected_paths` / `sacred.toml` and the built-in secret stores
  (`.ssh/`, `.gnupg/`, `.config/age/`) still protect it, and a walk that
  cannot finish still fails closed (`95724d8`).
- **Did not reclaim anything either:** the executor's source-tree and
  nested-`.git` checks refused every `.rch-tmp`; reverted in v0.6.23.

## v0.6.21 **[release]**

Compare: [`v0.6.20...v0.6.21`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.20...v0.6.21)

### Added — idle rch job TMPDIRs are reclaimed

- rch points every job's TMPDIR at `<project>/.rch-tmp` and prunes it only
  when the next job for that project arrives, so projects that stop getting
  jobs keep every leaked test tempdir: one host held ~13 GB in idle
  `.rch-tmp` dirs, one with 315k entries idle for five days. sbh kept each
  tiny child and re-scored all of them on every pre-scan cycle (a full CPU
  slice per project). The whole `.rch-tmp` is now the reclaim unit (rch
  recreates it per job), vetoed until nothing in it has been written for
  rch's own 24 h prune floor (`d8d5e42`).
- **Not effective yet:** after rollout no host reclaimed a `.rch-tmp`. The
  sacred-path layer still protects every one observed, because leaked test
  fixtures inside match the built-in `*.db`, `*.sqlite` and `.git/` markers,
  and the largest exceed the containment scan's 50k-directory bound (which
  fails closed). Whether idle rch job TMPDIRs may override those built-in
  markers is an open policy decision.

## v0.6.20 **[release]**

Compare: [`v0.6.19...v0.6.20`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.19...v0.6.20)

### Changed — the behavior matrix's scan posture sets the scanner's CPU pace

- The matrix's scan posture was only a label (just `skip` was honoured), so
  at Yellow through Red with healthy memory the "aggressive" scanner ran
  exactly like a Green one; at Orange one host's priority pre-scan stopped
  on the CPU budget ~150 times an hour. `aggressive` now paces at twice
  `telemetry.cpu_budget_pct` (at most one core), `light` and
  `definite_only` (memory pressure) at half. Critical disk pressure stays
  unpaced; `definite_only` does not yet restrict which paths are walked
  (`6ebd3a3`).

## v0.6.19 **[release]**

Compare: [`v0.6.18...v0.6.19`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.18...v0.6.19)

### Added — abandoned `mktemp` scratch in temp trees is reclaimable

- Directories made by `mktemp -d -t <prefix>.XXXXXXXX` matched no name
  pattern, so sbh never nominated them: one host at Critical pressure
  reported "nothing to reclaim" while 14 idle `fsfs-quickstart.*` test
  dirs held 53 GB. A directory under a temp tree named
  `<prefix>.<6-16 random alphanumerics mixing upper and lower case>` is
  now temp scratch, unless a directory between it and the temp root is a
  project (`.git`, `Cargo.toml`, `package.json`, `pyproject.toml`,
  `go.mod`). Digit-free suffixes with a run of four or more lowercase
  letters are words (`com.apple.WindowManager` in a macOS `$TMPDIR`) and
  do not count. The whole-tree idle age and open-file checks still apply
  (`4cb4c54`, `8136b30`).

## v0.6.18 **[release]**

Compare: [`v0.6.17...v0.6.18`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.17...v0.6.18)

### Fixed — reported and planned sizes are measured, not a 100 MiB placeholder

- The priority pre-scan recorded candidates in its index at the 100 MiB
  nomination placeholder, so every later replay dispatched and reported
  that size: in 12 hours one host logged 361 deletions and 17.9 GB "freed",
  all of it the placeholder (171 deletions at exactly 100 MiB) for a few
  megabytes of tiny `node_modules`, and the reclaim byte target counted it
  as progress. (The release commit's "73 GB in 12 hours" came from a query
  whose time filter matched a much longer window.)
  The index now records the measured size, and records written by earlier
  versions are re-measured when replayed (`e4c33d4`).

## v0.6.17 **[release]**

Compare: [`v0.6.16...v0.6.17`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.16...v0.6.17)

### Fixed — Linux: the memory-map check no longer burns a core on big hosts

- Every process's `/proc/<pid>/maps` is read once per 30 seconds and shared
  by all scan roots, instead of once per root on almost every pass. On a
  host with ~2,400 processes one sweep costs ~6 CPU-seconds, and the
  scanner was running at a full core (`b5587bf`).

## v0.6.16 **[release]**

Compare: [`v0.6.15...v0.6.16`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.15...v0.6.16)

### Fixed — a scan pass can no longer run away inside one directory

- Sacred-pattern regexes are compiled once and reused. Every protection
  check recompiled the whole catalog's patterns, for every candidate.
- The priority pre-scan checks its CPU and time limits before each
  candidate. One directory with dozens of candidates, each taking seconds
  to prove protected, held a pass at most of a core for 16+ minutes past
  its budget (`d55310b`).

## v0.6.15 **[release]**

Compare: [`v0.6.14...v0.6.15`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.14...v0.6.15)

### Changed — the daemon gets enough CPU to finish a scan

- The generated systemd unit caps sbh at one core (`CPUQuota=100%`) with the
  lowest CPU weight (`CPUWeight=1`) instead of 10% of one core. The 10% cap
  throttled the fleet in nearly every scheduling period, so on a full host
  every scan timed out; builds still win whenever cores are busy
  (`0ce785a`).
- A routine scan waits until the daemon's CPU budget is nearly full before
  starting, so each pass gets a real slice instead of stopping after a
  handful of entries. Average CPU use is unchanged (`9987a36`).

## v0.6.14 **[release]**

Compare: [`v0.6.13...v0.6.14`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.13...v0.6.14)

### Fixed — macOS ballast

- Ballast files on macOS really reserve their space. APFS does not reliably
  turn a preallocation into allocated blocks (it fails outright on some
  volumes and leaves the file mostly sparse on others), so a Mac's ballast
  pool could never be provisioned. The file is now filled with zeros when
  preallocation falls short (`d295843`). No change on Linux.

## v0.6.13 **[release]**

Compare: [`v0.6.12...v0.6.13`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.12...v0.6.13)

### Fixed — safety

- Name rules for agent scratch directories (`cass_*`, `frankenterm-*`,
  `frankentui-*`, `pi_agent_*`, `claude-*`, ...) apply only to a directory
  created directly in a temp root. Matching a name anywhere had removed a
  backup folder, checked-in fuzz corpora inside git clones and rch run
  mirrors. Build-artifact rules (targets, `node_modules`, caches) are
  unchanged (`8b1b728`).

## v0.6.12 **[release]**

Compare: [`v0.6.11...v0.6.12`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.11...v0.6.12)

### Fixed — safety

- Claude Code's own directories are never reclaimed whole: the per-user
  session root `claude-<uid>` (every live session's scratchpads and task
  output) and `claude-mcp-browser-bridge-*`. The broad `claude-` rule
  nominated them; a Mac deleted the bridge directory and tried the session
  root three times, stopped only by the open-file check. Agent scratch dirs
  and artifacts inside a scratchpad stay reclaimable (`f04a9b0`).
- A walked directory about to be deleted is always checked for running
  executables, memory maps and open files. Its recorded size was only its
  immediate files, so a large build directory looked tiny and skipped those
  checks, the only guard for a binary a process is running (`f04a9b0`).
- `state.json` is written world-readable whatever the daemon's umask, so
  non-root `sbh status` can always read it (`00b858a`).

## v0.6.11 **[release]**

Compare: [`v0.6.10...v0.6.11`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.10...v0.6.11)

### Fixed

- `~/.cargo/registry` and `~/.cargo/git` are never reclaimed as a whole;
  the stores inside them (`registry/{cache,src,index}`, `git/{checkouts,db}`)
  are. rch's per-job cargo home symlinks those roots, so removing one broke
  every crates.io download on that worker (hz4: a release lost 33 minutes)
  (`6417f0b`).
- The executor's open-file refusal now matches candidates spelled through a
  symlink. It compared the spelled path against resolved open-file paths, so
  on macOS nothing under `/var/tmp` or `$TMPDIR` could ever be refused as
  open (`94e2fb3`).
- A configured root that is itself a symlink is walked. On macOS the default
  `/tmp` (a link to `/private/tmp`) was skipped silently, so the daemon never
  saw stale build output there (`94e2fb3`).

## v0.6.10 **[release]**

Compare: [`v0.6.9...v0.6.10`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.9...v0.6.10)

### Fixed — macOS scans no longer stall in the memory-map probe

- The active-reference memory-map check walks only file-backed regions
  (`PROC_PIDREGIONPATHINFO2`) instead of every region of every process. On
  a Mac with ~900 processes the old walk took 9-12 s per scan root, often
  timed out (reporting "incomplete" anyway), and ran once per root, so a
  pass could spend its whole CPU budget before scanning anything ("scan
  budget reached (1 entries, 0 candidates, 54.2s)"). Now 0.2-0.4 s per root
  with identical results (`ebf65ee`). No change on Linux.

## v0.6.9 **[release]**

Compare: [`v0.6.8...v0.6.9`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.8...v0.6.9)

### Added — macOS scans the per-user temp dir

- The daemon also scans `$TMPDIR` (`/var/folders/<x>/<y>/T`), where cargo
  test tempdirs and most tools write. The default roots `/tmp` and
  `/var/tmp` resolve to `/private/...` on macOS and never reached it, so a
  full Mac reported nothing to reclaim while that directory went unvisited.
  It is added at load unless a configured root already is, contains, or lies
  inside it; `scanner.include_user_temp_dir = false` opts out. No effect on
  other platforms (`95cc829`).

### Changed

- `clippy -D warnings` passes on macOS; macOS-only code had never been
  linted. No behavior change (`1312548`).

## v0.6.8 **[release]**

Compare: [`v0.6.7...v0.6.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.7...v0.6.8)

### Fixed — service repairs keep the unit's config and never run a dev build

- `sbh service reinstall-unit`, `sbh bootstrap` and the install-time repair
  keep the unit's `--config` (and other `ExecStart` arguments). They reset
  the command to plain `daemon`, so a fleet unit running with
  `--config /root/.config/sbh/config.toml` fell back to a stale
  `/etc/sbh/config.toml` after a repair (`84ea6f2`).
- A service repair refuses to point the unit at a binary outside an install
  location (`/usr/local/bin`, `/usr/bin`, Homebrew, `~/.local/bin`,
  `~/.cargo/bin`). A test run as root on a build worker had rewritten that
  host's production unit to run the worker's debug build (`84ea6f2`).
- `sbh bootstrap` honors the `SBH_TEST_MODE` + `SBH_SYSTEMD_UNIT_DIR` fixture
  override when it scans for units, as `doctor --service` already did
  (`84ea6f2`).

### Tests

- Two load-sensitive tests no longer fail on busy build workers: the pre-scan
  resume test asserts on the cursor (an index replay batch legitimately
  precedes the pre-scan's), and the `proof_harness` micro-benchmarks bound
  the median rather than the single slowest sample (`ad390fd`, `5bb5416`).

## v0.6.7 **[release]**

Compare: [`v0.6.6...v0.6.7`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.6...v0.6.7)

### Fixed

- Within one scan pass, no candidate *containing* an already dispatched tree
  is dispatched either. Only candidates inside a dispatched tree were dropped,
  so a pre-scan batch for `proj/target/debug` followed by a walk batch for
  `proj/target` could delete a `debug/` rebuilt in between; the containing
  tree now waits for the next pass (`405a15f`).
- The macOS temp-root check requires an absolute path of plain names; it
  accepted relative paths and skipped `..` components (`405a15f`).
- `scripts/dsr_release.sh` verifies a release with the binary for the release
  Mac's own architecture (`405a15f`).

## v0.6.6 **[release]**

Compare: [`v0.6.5...v0.6.6`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.5...v0.6.6)

### Changed — the executor spends its time deleting, not re-listing open files

- A complete open-file sweep is reused by the next batch while it started
  less than 20 s ago; a batch whose candidate root changed after the sweep
  began gets a fresh one. On css the sweep over thousands of agent
  processes took most of each 12-25 s batch, and 74% of batches start the
  moment the previous one ends (`4c834f2`).
- A plan the executor refuses entirely now backs its candidates off and names
  the reasons, instead of being re-proposed every pass (css: 10 of 27 batches)
  (`b3747eb`).

### Fixed — macOS

- The per-user temp dir `$TMPDIR` (`/var/folders/<xx>/<hash>/T`) is a temp
  root: build artifacts there are scored like those in `/tmp` instead of
  being held for review (`d74ed6d`).
- The library suite now passes natively on macOS (3028/3028, plus `sbh_mach`
  19/19); it had never run there. Host-dependent tests were made hermetic and
  README now describes the FSEvents backend that shipped in `864066f`.

### Changed — process I/O attribution

- Bounded sampling sweeps finish despite continuous PID churn (`f9a5d5e`), and
  I/O history snapshots persist across daemon restarts (`c5b5dd5`).

## v0.6.5 **[release]**

Compare: [`v0.6.4...v0.6.5`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.4...v0.6.5)

### Fixed — pressured hosts spent their scan budget re-proving the same trees

- A protected verdict proved by a real find (a `.db`, `.beads/`, WAL sidecar
  inside the tree) is kept while that find still exists, instead of being
  dropped whenever the busy tree's mtime changes. On css every pass re-walked
  ~8 active agent temp trees, hit the daemon CPU budget, and never reached the
  main walk (`245fc18`).
- The priority pre-scan plans and reports a directory at its measured size;
  it used a flat 100 MiB, so a 2 MiB cache was logged as 100 MiB freed
  (`245fc18`).
- The installed service's own ballast pool is never adopted as a "stranded"
  reserve by a process running with another config (a CLI or a test daemon).
  A test daemon running as root on a build worker had counted,
  and could release from, the production daemon's live 10 GiB pool (`56f6271`).
- **A tree is dispatched for deletion at most once per scan pass.** The
  pre-scan and the walk could both nominate it; the second batch arrived right
  after the first deletion, and a build that recreated the tree in between got
  the freed inode back, so the identity check passed and the rebuilt target was
  deleted too (`a219521`).
- Process I/O attribution history is bounded, persisted atomically and
  survives counter and clock resets; busy hosts are sampled fairly
  (`dec4a3e`, `e0741fc`).

### Changed — releases no longer involve GitHub Actions

- The GitHub workflows (`ci.yml`, `release.yml`, `cert-expiration.yml`) are
  deleted. Releases are `dsr build` from a clean tag worktree followed by
  `scripts/dsr_release.sh all X.Y.Z`: Developer ID signing with hardened
  runtime, notarization (must be `Accepted`), packaging and audit, manifest
  minisign, GitHub release upload and verification, and the Homebrew tap. The
  sign step refuses an expired certificate and warns 30 days ahead.
- **The Homebrew tap had been stuck at v0.6.0**: only the disabled Release
  workflow updated it, so v0.6.1–v0.6.3 never reached `brew`. It now serves
  v0.6.4, and the v0.6.4 darwin binaries are notarized
  (`spctl`: `accepted, source=Notarized Developer ID`).
- `sbh doctor --release` no longer checks GitHub secrets, workflow state or the
  cert-expiration workflow, and its setup plan no longer stores credentials as
  GitHub secrets; the JSON report drops `required_github_secrets`. The tap
  version check reads the version from the formula URL (the rendered formula
  has no `version` line, which made the check fail).

### Fixed

- A candidate whose protection check errors (for example a dead FUSE mount
  inside it) is remembered as protected until its verdict expires, instead of
  being re-probed and logged on every pass.

## v0.6.4 **[release]**

Compare: [`v0.6.3...v0.6.4`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.3...v0.6.4)

### Fixed

- **Agent session histories and cass data are built-in sacred** (`a446e2a`):
  `~/.claude`, `~/.codex`, `~/.gemini`, `~/.cass-memory`,
  `~/.local/share/coding-agent-search*` and the macOS cass Application Support /
  `Library/Caches/cass-*` trees are protected under any home, not only when an
  operator remembers to add them.
- **Executor reports the space deletions actually free** (`2df3347`): each
  unlink is measured with `statvfs` before and after; `bytes_freed` stays the
  estimate and `bytes_freed_observed` feeds the controller and the
  `observed_freed=` summary. Quarantine renames count as zero freed.
- **Emergency ballast release no longer blocks on pool locks** (`d556cc4`):
  release uses a nonblocking flock, refreshes slots under it and unlinks by
  directory handle after an identity check; gradual refill defers on
  contention instead of stalling the daemon.
- **Ballast provisioning fails closed on unknown headroom** (`c30a376`):
  every new file needs a fresh capacity reading; unknown, nonfinite or
  read-only readings stop allocation, and damaged reserves are kept when the
  replacement would cross the floor.
- FIFO release regressions are portable to macOS (`6d884a5`); emergency
  manager lint cleanup (`2c490aa`).
- An explicit `SBH_BUILD_GIT_SHA` wins over the enclosing checkout, so
  worktree/dsr builds embed the right sha (`a23f07a`).
- Real-daemon e2e scenarios run serially to stop timing flakes (`a32294f`).
- `sbh update` retries its staged-binary self-test while exec reports
  `Text file busy` (a descriptor briefly inherited by another thread's
  child) instead of aborting a good update (`003cd43`).
- Ballast tests no longer depend on how full the build host is; the rch
  pressure floors and the canary re-prove window are documented constants
  checked against the code (`53dca2e`, `ecab55c`).

## v0.6.3 **[release]**

Compare: [`v0.6.2...v0.6.3`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.2...v0.6.3)

### Fixed — the fleet kept filling while sbh held itself back (fleet audit 2026-09-24)

An audit of all 20 deployed hosts (sbh 0.6.2) found disks at 84–100% with the
daemon running but throttled or blind. Fixes, each with tests:

- **Policy ratchet** (`c825b75`): the drift alarm ignored
  `calibration_breach_action` and demoted Enforce fleets at every bursty Orange;
  recovery landed in Canary and a later fallback remembered Canary, so hosts sat
  at 10 deletions/hour for days (15/20 hosts). Drift now follows the breach
  action, the engine tracks the operator's intended mode, an automatic Canary
  re-proves itself back to it after 30 minutes, the canary budget counts executed
  deletions, and a failed state write at Red+ no longer demotes.
- **Ballast never helped** (`a1190e4`, `b5de9ce`): macOS pools resolved to the
  sealed read-only `/` and were always skipped; `ReadWritePaths=` bind mounts of
  one disk became separate pools that released nothing when the pressured entry
  was not the one holding files; ~126 GB of sbh's own ballast sat stranded in
  unmanaged `.sbh/ballast` dirs. Pools now follow `statfs`, fold per device, and
  adopt header-validated stranded files as reserve.
- **rch pools** (`c8af305`): active pools were vetoed until idle 168 h (never);
  from urgency 0.7 the idle floor is 60 min (pooled) / 30 min (per-job).
- **Reclaim to Green** (`09eccc2`), **symlink candidates vetoed at scoring**
  (`3ecc3e0`), **plan-time refusals attributed and backed off** (`2097add`),
  **opaque sizes floored only when truncated** (`90fc109`, no more fictional
  100 MiB deletions), **protected verdicts carried across passes** (`21dbe9a`,
  pre-scans no longer burn their CPU budget re-proving the same trees), and the
  **CLI reads the config the installed service runs** (`f2d3eeb`).
- **Open-file safety sweep** (`b2895d7`, `f8c8d53`): its 5 s wall-clock budget
  could not fit under the unit's `CPUQuota=10%` on a busy host, so every batch
  failed closed (css at 100%, SBH-3003 on every batch). The budget is 30 s, and
  an aborted batch now counts as skips, not deletion failures (no false
  SBH-2005 alarm, no index backoff for the host's load).
- **Growth attribution** (`03a401a`, `28e0865`): a mount at Red or worse for
  10 minutes gets an `SBH-2007` warning naming its largest directories, at
  most hourly.
- **Former user-scope reserves** (`ccf445e`, `aa75d80`): ballast left by an
  earlier user-scope install is adopted and credited before the active pool
  grows.
- `sbh config set` accepts arrays and inline tables (`95730d2`).

### Fixed — one stuck entry wedged the whole quarantine, permanently (`bd-quarantine-drain-fail-closed-7tun`)

`drain_expired` and `drain_oldest` propagated the first per-entry failure out of
their loop with `?`:

```rust
bytes = bytes.saturating_add(self.purge(&record.decision_id)?);
```

So a single entry that would not unlink — `EACCES`, `EBUSY`, `ENOTEMPTY`, an
immutable bit, a mountpoint underneath — aborted the entire batch and left every
remaining expired entry in place. That is not self-healing but self-perpetuating:
`records()` is sorted oldest-first and `sweep_quarantines` re-enters from the top
of that same list every 60 s, so the poison entry is always hit first and the
store never drains again, growing without bound while `sbh status` reads green.
The same shape made `drain_all`, `enforce_cap` and the Orange+ pressure drain
brittle — the paths that matter most on a filling disk.

- Drains are **best-effort per entry**. They return a `DrainOutcome`
  (`entries`, `bytes`, `failures`, `skipped_stuck`) instead of `(usize, u64)`,
  and `Err` now means only that the store itself is unreadable.
- A failed purge writes a `<decision-id>.stuck` sidecar next to the record
  (deliberately not `.json`, so `records()` cannot mistake it for one) carrying
  the failure count, first/last failure time and the error. The entry is then
  skipped for `STUCK_RETRY_SECS` (1 h) rather than retried every sweep, and is
  reported **once** per transition instead of once a minute. `purge` clears the
  sidecar whenever the entry finally goes, and `stuck_entries()` drops orphans.
- Pressure and `sbh emergency` use `drain_all`, which **ignores the cooldown**:
  when the disk is filling, one more `EBUSY` costs less than the space does.
- Stuck entries are now visible outside the journal: `sbh doctor --system` FAILs
  the new `quarantine.stuck` check naming the worst offender and its errno, and
  `sbh status` prints a `Quarantine:` warning block. It stays silent when there
  is nothing stuck, so normal output is unchanged. A version check is not a
  liveness check, and neither is a green status.

### Fixed — `config set` wrote a file the daemon never reads (`bd-config-set-wrong-path-3gp1`)

`sbh config set`, `sbh config reset` and `sbh tune --apply` resolved their target
with the raw per-user default (`Config::default_path`) while every reader —
`sbh config show`, `sbh config path`, `Config::load` — went through
`Config::resolve_config_path`, which prefers the system config for root. As root
on a host carrying `/etc/sbh/config.toml`, a `config set` therefore wrote
`~root/.config/sbh/config.toml`, reported success, exited 0, and changed nothing;
`config show` immediately afterwards still returned the old value. `config reset`
was worse still: it reported resetting a config it had never touched.

Writes now resolve through `Config::resolve_config_write_path`, which *is* the
read resolver rather than a copy that can drift from it again. `--config` and
`SBH_CONFIG` continue to win, non-root behaviour is unchanged, and both commands
now report the chosen file **and why** (`path_source` and `reason` in JSON),
warning when a shadowed per-user config will keep overriding for non-root runs.

### Fixed — the crate's test target did not build on macOS

`system_temp_base()` was `#[cfg(target_os = "linux")]` but
`clean_quarantines_at_green_and_undo_restores_the_target` is not gated to Linux
and calls it, so `cargo check --all-targets` failed on the Mac. Added the
non-Linux arm (`/private/tmp`, already the canonical form these tests compare
against) rather than gating the test away.

## v0.6.2 **[release]**

Compare: [`v0.6.1...HEAD`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.1...HEAD)

### Fixed — the scan pass budget: sbh reclaimed nothing on any host with a large tree

Measured on hz1, vmi1167313 and vmi1156319, every pass of an "active, healthy"
0.6.x daemon ended:

```
[SBH-SCANNER] priority pre-scan budget reached (0.7s) — cancelling scan pass
[SBH-SCANNER] scan complete: 0 entries, 0 candidates, 0.7s (timed out)
```

Four defects compounded into a scanner that burned its CPU quota and reclaimed
nothing while the disks filled.

- **The CPU budget was converted into a wall deadline with a worst-case model
  (`src/daemon/cpu_budget.rs`, `src/daemon/loop_main.rs`).**
  `CpuBudget::pass_allowance` returned `available_cpu_secs / scanner.parallelism`
  *as wall time*, i.e. assuming every walker thread pegs a core for the whole
  pass, and the scanner then took `min(scan_time_budget_secs, that)`. Because
  the token bucket is clamped to its burst (5 CPU-seconds), that gave every
  discretionary pass a **hard wall ceiling of `burst / parallelism`** — 0.62 s
  at the default `parallelism = cores / 2` on a 16-core host, 0.71 s on 14
  cores — which no amount of idling could raise, and which silently overrode
  the configured `scan_time_budget_secs = 900`. The model was wrong twice over:
  a directory walk is I/O- and syscall-bound, and the priority pre-scan that
  the deadline actually killed is single-threaded. It is now
  `CpuBudget::pass_cpu_allowance`, a CPU-second allowance charged against the
  pass's **measured** rusage delta by the new `PassCpuGuard`. The documented
  bound (`pct/100 * w + burst` over any window `w`) is unchanged and now exact
  rather than pessimistic; an I/O-bound pass runs to its wall budget.
- **The priority pre-scan restarted from the first root on every pass
  (`src/scanner/prescan_cursor.rs`, new).** Truncated at 0.7 s it re-examined
  the same leading directories forever. The new `PrescanCursor` remembers the
  root and depth-1 entry the last pass finished, sorts each root's entries so
  the resume point is stable, resumes strictly after it, wraps to the next root
  when one is exhausted, and is persisted to `prescan-cursor.json` beside the
  scanner index so progress survives a restart. A tree needing twenty passes to
  cover is now covered in twenty passes rather than never.
- **A pre-scan timeout aborted the whole pass, so the general walker never ran
  (`src/daemon/loop_main.rs`).** The pre-scan phase now has its own wall budget,
  `scanner.prescan_time_budget_secs` (default 60 s, `0` = no separate limit);
  exhausting it hands the pass over to the walker — which has its own
  incremental cursor and computes real recursive sizes — instead of ending it.
  Only the pass wall budget and the CPU allowance mark a pass as timed out.
- **Pressure *shortened* the scan budget (`effective_scan_budget`).** The
  Orange/Red/Critical extension was `base * 2` clamped with `.min(600)`, so with
  the shipped default of 900 s the hosts under pressure got 600 s — less than
  Green. It is now clamped to `[base, 3600]`.

### Fixed — test robustness

- `tests/integration_tests.rs` picked its fixture base with
  `Path::new("/private/tmp").is_dir()`, meant to resolve macOS's `/tmp`
  symlink. A Linux build worker can carry a root-owned `/private/tmp` left
  behind by a synced macOS path, and the two `clean` tests then failed with
  `PermissionDenied`. The new `system_temp_base()` probes for writability
  instead of existence.

### Added

- `telemetry.cpu_budget_burst_secs` (default `5.0`, clamped to `[1, 600]`,
  `SBH_TELEMETRY_CPU_BUDGET_BURST_SECS`): the depth of the CPU token bucket,
  i.e. the most CPU a single discretionary pass may spend.
- `scanner.prescan_time_budget_secs` (default `60`,
  `SBH_SCANNER_PRESCAN_TIME_BUDGET_SECS`): the priority pre-scan phase's own
  wall budget.
- **Operator-visible budget reporting.** A truncated pre-scan and a truncated
  pass now both emit an `ActivityEvent::Warning` with code `SBH-2007`
  naming which limit stopped it, how many entries it reached, the wall and CPU
  time spent, and where the next pass resumes — so a budget-starved daemon
  shows up in `sbh status` and the activity log, not only on stderr. The
  `scan complete` line now reports the pre-scan's real entry count instead of a
  hardcoded `0 entries`, and carries the pass's measured CPU.

---

## v0.6.1 **[release]**

Compare: [`v0.6.0...HEAD`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.6.0...HEAD)

### Fixed — Build artifact recognition, special location monitoring, and test isolation

- **Cargo build-profile artifact recognition (bd-8t1l):** `is_obvious_build_artifact_basename` now recognizes `debug` and `release` subdirectories when nested under an obvious build artifact directory (e.g. `target/debug`, `target/release`, `.cargo-target/debug`, `build/release`), ensuring operator-configured source trees under `/data/projects/` and `/home/*/projects/` have their build profile artifacts safely reclaimed instead of being vetoed as source code.
- **Special location filling_fast rate check:** `HorizonRule::assess` now checks write rate > 0 before computing seconds-to-exhaustion, preventing quiet small RAM mounts (< 1.8 GiB, e.g. `/dev/shm`) from falsely triggering `SpecialAlert::Critical` and premature emergency ballast releases.
- **Offline update-check test isolation:** Pinned `SBH_CONFIG` to an isolated configuration inside the temporary fixture and populated metadata cache on both XDG and macOS Application Support paths so host configs and system caches cannot interfere with offline checks.
- **systemd user-scope path isolation:** Scoped default read-write paths for `HOME` to user service scope, avoiding permission warnings.
- **Bootstrap drift repair:** Avoid emitting empty drift summary when only foreign drop-ins exist.

### Fixed — macOS installer and Homebrew tap fixes (#22, #23, #24)

- **bash 3.2 heredoc parse bug (#23, bd-fc94):** `scripts/install.sh` failed to parse under macOS stock bash 3.2.57 due to command-substituted heredocs containing single quotes (`$(cat <<'SKILL_EOF' ... Don't ...)`). Fixed by writing the inline agent skill directly to a temporary file before copying.
- **Homebrew tap formula audit (#22, bd-xt1e):** Added `depends_on :macos` to `packaging/homebrew/Formula/sbh.rb` so Homebrew's Linux syntax verification during `brew tap Dicklesworthstone/sbh` does not reject the formula for missing Linux URLs.
- **macOS unsigned/adhoc binary installation escape hatch (#24, bd-58fs):** `scripts/install.sh` now supports `--allow-unsigned` and `SBH_ALLOW_UNSIGNED_MACOS=1`, allowing users to install adhoc-signed macOS binaries with a prominent security notice while preserving strict SHA-256 checksum verification. `scripts/release-manual.sh` also warns when darwin targets are packaged without Developer ID signatures.

---

## v0.6.0 **[release]**

Compare: [`v0.5.1...HEAD`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.5.1...HEAD)

### Added — `sbh doctor --release --assets <dir|tag>`: post-publish release asset audit (bd-rc-master-ajg1.5.3)

- `src/cli/release_audit.rs` audits a release asset directory (or a tag, downloaded first with `gh release download`) the way the workflow guards itself: for every CI target the versioned archive, its `.sha256` sidecar, its `SHA256SUMS.txt` entry, the byte-identical legacy unversioned mirror with its sidecar, and the architecture of the `sbh` inside the tarball (ELF `e_machine` / Mach-O `cputype` against the labelled triple, the v0.4.23 incident shape); plus `release-provenance.json` with non-empty `tag`, `sha`, `run_id`, `timestamp`, `rustc_version` and the right tag. macOS codesign/notarization is reported as a warning, not checked. Exit 1 on any failure; `--json` carries the findings. Fixture tests build a workflow-shaped set with real `tar -cJf` archives and fail it four ways (mislabeled tarball, wrong sidecar, missing mirror, provenance tag mismatch). The release doctor's drift check reuses `release_audit::ci_target_host`.
- The Release workflow gains a `asset-audit` job after publish: it extracts the just-built Linux x86_64 `sbh`, runs `sbh --json doctor --release --assets <tag>` against the published release, uploads the JSON, and the Homebrew tap update now depends on it. docs/macos.md's manual fallback tells operators to run the same audit before uploading.

### Added — real-pressure scenario: a loop-mounted ext4 written to ENOSPC (bd-rc-master-ajg1.11.3)

- `tests/daemon_e2e.rs` gains `zero_free_volume_releases_the_pool_and_keeps_writing_state` (sudo-gated like the other loop-mount scenarios, run with `--ignored`): a 512 MiB ext4 image with a provisioned four-file 16 MiB pool and a stale Definite target is written until the filesystem refuses (`ENOSPC`), repeatedly, because the daemon releases ballast while the fill is still running. The daemon, on real statvfs and without injection, must record Orange→Critical, release all four files, delete the stale target, keep rewriting `state.json` (on the root filesystem) through the incident, and leave the filler untouched. On this host: 491 MB to ENOSPC over two fills, the whole incident in 96 s. The CI `daemon-e2e` job's loop-mount step already runs the ignored scenarios on ubuntu.

### Added — `sbh doctor --release` drift checks (bd-rc-master-ajg1.5.6)

- Four checks join the release doctor, all through GitHub CLI: `release.latest_assets` (the latest release's asset list satisfies the updater contract for every CI target and carries `release-provenance.json`; missing names are listed per target), `release.tap_version` (the tap's `Formula/sbh.rb` version equals the latest tag), `release.workflows_enabled` (`ci.yml`, `release.yml`, `cert-expiration.yml` are registered and active), `release.cert_expiration_run` (the last cert-expiration run concluded successfully). Without GitHub access they warn instead of failing, so `doctor --release` stays usable offline. Fixture tests cover a complete v0.5.1 asset set, a release missing one target and the provenance document, a lagging formula, a disabled workflow, a failed run, and the offline case.

### Changed — `crates/sbh_mach` is a workspace member and its tests run in the macOS lanes (bd-rc-master-ajg1.1.4)

- The root manifest declares `[workspace] members = [".", "crates/sbh_mach"]`, so `cargo metadata` sees the FFI crate and the `macos-platform` CI job runs `cargo test -p sbh_mach` on both the arm64 and the Intel runner; its eight tests (including the `HOST_VM_INFO64` count regression) had never executed in CI. The root crate still forbids unsafe code; the manifest and AGENTS.md say why the Mach crate cannot.

### Added — claims registry: numbers in README prose are checked against the code (bd-rc-master-ajg1.12.4)

- Prose can carry `<!-- claim:<id> -->value<!-- /claim -->` markers; `sbh docs --check` verifies each value against the generated document (ids `constants.<area>.<name>[.raw]`, `pressure.<level>.<column>`, `scoring.<factor>`, `exit.<code>`) and `sbh docs --render` rewrites only the value between the markers. Findings name the claim, its line, the expected and the found value; unknown ids fail. 49 numbers in README "How It Works" carry claims now (controller gains, thresholds, breaker, channel bounds, logger rotation, guardrail bounds, scoring losses and weights, regret rates, ballast layout, RSS limits, VOI budget, inotify budget, control-socket limits).
- Corrections the claims exposed: the e-process upper bound is 3.5 (prose said 5.0); the circuit breaker trips after 5 failures (prose said 3); the walker's work queue is unbounded and its result channel holds 10000 entries (prose said a 4096-entry work queue); ballast provisioning stops at the provisioning floor `max(orange, red + 2)` = 10% with the defaults (prose said 20%); the daemon warns at 256 MiB of RSS and exits at 500 MiB while the systemd unit caps the cgroup at `MemoryMax=256M` (prose said one 256 MB hard limit).
- Coverage guard: the bin test `readme_how_it_works_unmarked_numbers_do_not_grow` lists every bare number in "How It Works" prose that no claim, generated region, table, code block, backtick span, link or comment covers and fails when the count exceeds a budget (103 after this pass). New constants: `logger::dual::SQLITE_FAILURE_TRIP`, `daemon::service::SYSTEMD_MEMORY_MAX`; the constants table gains the JSONL rotation, control-socket, VOI and inotify-budget rows (129 rows).

### Added — README v0.6.0 sections generated from the code: behavior matrix, exit codes, state.json fields (bd-rc-master-ajg1.12.5)

- `sbh docs` sections `behavior-matrix` (both presets, `v0.6` default and `v0.5`, from `daemon::policy::BehaviorPreset::base_cells`: 3 memory rows × 5 disk columns, cell = scan / cleanup / ballast / notify), `exit-codes` (the C-EXIT contract, `cli::docs::EXIT_CODES`, checked by the bin test against `CliError::exit_code` and the help epilog) and `state-fields` (every top-level `state.json` field with its JSON type from a default `DaemonState` and a meaning; the test fails when a field is added without a row). README gains "Behavior Matrix" under the policy engine, "Exit Codes" before "Error Codes" and "state.json Fields (schema 2)" under the state file protocol; AGENTS.md gains "Exit Codes". The `label()` accessors of the behavior enums and `BehaviorPreset::base_cells` are public.

### Added — doc-contract tests: documented flags and file references must exist (bd-rc-master-ajg1.12.3)

- The bin test `documented_commands_flags_and_file_references_resolve` checks the README "Command Reference" and the AGENTS.md "CLI Command Reference" against clap: every `sbh …` row names a real command and every `--flag` in the row exists on that command, an ancestor, or the global flags (a flag may sit between path words, `sbh service --systemd reinstall-unit`); every backticked `src/`, `docs/`, `scripts/`, `tests/`, `.github/` path in README, AGENTS.md, CHANGELOG and docs/*.md exists. Findings name the file, the row and the flag or path. `cli::docs::{undocumented_flags, missing_file_references}` carry fixture tests including the negative case (a typo'd flag is reported). It found `--purge-dropins` documented on the wrong command (resolver fixed) and a naming example in docs/testing-and-logging.md pointing at a file that never existed (corrected).
- `scripts/ci_docs_update_check.sh` also runs `quality-gate.sh --check-stages` in its drift phase.

### Changed — the pressure, scoring, error-code and constants tables are generated from the code (bd-rc-master-ajg1.12.2)

- `sbh docs` gains the sections `constants` (117 named defaults and limits: pressure thresholds, controller gains, prediction, EWMA, guardrails, deletion breaker, scanner and walker budgets, scoring and risk budgets, ballast, quarantine, daemon channels and self-monitor, logger), `pressure-levels` (the default thresholds crossed with the controller's response table), `scoring-weights` and `error-codes`; `sbh docs --json` carries them. The README pressure and error-code tables and the AGENTS.md pressure, scoring, error-code tables plus a new Runtime Constants section are rendered regions; `sbh docs --check README.md AGENTS.md` runs in the bin tests, `scripts/ci_docs_update_check.sh`, the quality-gate `docs-drift` stage and CI.
- The controller's per-level response is a named table (`monitor::pid::RESPONSE_TABLE`) instead of literals in `response_policy`; a test pins the previous behavior at eleven points. Other literals became named constants at their point of use: the guardrail e-process clamp (`E_PROCESS_LOG_MIN/MAX`), the walker's result channel bound and channel timeouts.
- Corrections the generator exposed: AGENTS.md listed a 35/20/10/5 threshold generation (the code is 20/14/10/6 with Critical below Red) and a 3-failure circuit breaker (the default is 5); the README said Critical starts at half the Red threshold (the code treats anything below `red_min_free_pct` as Critical). `src/core/errors.rs` now has an `ERROR_CODES` catalog checked against every variant.
- docs/adr-tui-integration-strategy.md records what shipped (ftui git dependencies pinned at `v0.6.0` behind the default `tui` feature) as an amendment to the original "no FrankentUI crate" decision.

### Added — incident replay: `sbh dashboard --replay <activity.jsonl>` (bd-rc-master-ajg1.4.13)

- The cockpit can be driven from a captured activity log instead of a daemon: every screen shows the log's events up to a moving cursor, the Overview shows a state reconstructed from them (counters, per-mount pressure, ballast counts, last scan), and the header carries `REPLAY <file> t=<ts> i/n <speed>`. `--speed 1x|10x|max` sets how fast log time runs, `--from <RFC 3339>` starts later; `Space` pauses/resumes, `,`/`.` step one event, `Home`/`End` seek (the keys the bead named, `[`/`]`, stay screen navigation). Lines that do not parse are skipped and counted; ballast actions are refused with a hint. No daemon, socket, or database is touched.

### Added — Diagnostics thread health and a live VOI overlay (bd-rc-master-ajg1.4.11)

- The Diagnostics screen's Runtime pane lists the daemon's four threads from `state.json` (`running`/`stalled`/`dead` with the heartbeat age), or says the daemon did not report thread health.
- `state.json` carries a `voi` block (enabled, budget and its use by the last plan, exploration split, fallback state, calibration windows and recent MAPE, paths tracked, when the last maintenance plan was made and its top paths). The VOI overlay (`v`) renders it instead of the literal "5 paths/cycle, 80/20" it used to print, flags a stale state file, and explains when a daemon predates the block or no state is loaded.

### Added — the dashboard's Log Search screen searches (bd-rc-master-ajg1.4.10)

- Screen 6 was a read-only mirror of the Timeline with a `<not-yet-editable>` query line. It now has one: `/` edits the query inline (Enter runs it, Esc cancels, and the editor owns every key meanwhile), `n`/`p` page through results, `c` clears, `Enter` opens the selected entry on the Timeline. The grammar is free words (every word must appear in the entry's path, event type, severity, message, error code, pressure level or details, case-insensitively) plus `type:<event>`, `level:<info|warning|critical>` (a minimum), `path:<prefix>`, `id:<decision-id>` and `since:<15m|1h|24h|7d>`; the header shows the active filters, the page, and the backend that answered.
- Data: the telemetry adapters gained `search_events`. SQLite answers with `WHERE` clauses (`LIKE` with escaped wildcards for words and the path prefix, `timestamp >=` for `since:`) and `LIMIT/OFFSET` paging; JSONL filters a bounded tail in memory; the composite prefers SQLite and falls back to JSONL, and says which one answered.

### Changed — test counts in the docs are generated (bd-rc-master-ajg1.1.5)

- `scripts/test-census.sh` counts every cargo test target with `cargo test <target> -- --list` (library with the default features and with the lean set, the binary, every integration file) plus the e2e shell cases the suite defines, and prints a Markdown table; `docs/testing-and-logging.md` embeds it between `sbh-census` markers, `--check` fails on drift, `--write` rewrites it, `--self-test` checks the counting. The hand-typed summary it replaces was stale by 35–270 % per row. The quality gate runs `--check` as the SOFT `test-census` stage.
- `scripts/quality-gate.sh --write-stages` rewrites the stage table embedded in `docs/quality-gate-runbook.md` and `docs/testing-and-logging.md` (the "N stages: H HARD, S SOFT." line included), `--check-stages` fails on drift, and the SOFT `stage-docs` stage runs that check; with `docs-drift` and `test-census` the gate has 30 stages (21 HARD, 9 SOFT).

### Added — `sbh docs`: README tables generated from the code (bd-rc-master-ajg1.12.2, first slice)

- `sbh docs` prints a versioned JSON document built from the binary's own tables: every `SBH_*` environment variable (a registry a test keeps equal to the names the code reads, each config override naming its `config.toml` key), every command and flag from clap, the dashboard's screens, keymap, palette actions and playbook, and the default configuration as TOML. `--section <name>` prints one section's Markdown.
- `sbh docs --render <file>` rewrites the regions a file marks with `<!-- sbh-docs:begin <section> -->` … `<!-- sbh-docs:end -->`; `--check <file>` exits 1 naming the drifted regions. README's environment-variable table, dashboard keybinding tables, palette list and triage playbook are such regions now; `scripts/ci_docs_update_check.sh` runs the check and the quality gate has a `docs-drift` stage.
- Contract tests: the keymap resolves every global and overlay binding in its context and no global key shadows a documented screen key; every `sbh <command>` in README's Command Reference exists in clap; README's generated regions match the build.

### Changed — the quality gate cannot pass vacuously (bd-rc-master-ajg1.1.3)

- `scripts/quality-gate.sh` counts the tests each stage executed (the sum of its `test result:` lines; the e2e suite's `summary pass=N fail=M` line) and records a test stage that exits 0 having selected no test as `vacuous`, a failure of that gate; `summary.json` carries `executed_tests` per stage and in total, and the console shows the count next to each PASS.
- The stages are one table in the script; `--print-stages [--markdown]` prints it and `docs/quality-gate-runbook.md` and `docs/testing-and-logging.md` embed the Markdown output between `sbh-qg:stages` markers. `--self-test` checks the accounting and the vacuous path against fixtures without cargo.
- The TUI and fallback stages pass `--features tui` explicitly (it is a default feature since 4.7, so the nine TUI stages and `fallback` that used to select zero tests now execute 900+ and 42). New stages: `cli-exit-codes`, `decision-e2e` (split from `decision-plane`), `explain-ledger`, `dashboard-pty`, and `daemon-e2e` (SOFT: its idle-CPU case is load-sensitive). 27 stages: 21 HARD, 6 SOFT.

### Added — dashboard ballast actions execute (bd-rc-master-ajg1.4.15)

- On the Ballast screen `Shift-X` releases every available file on the selected volume and `p` replenishes it, each behind the confirmation modal; `x` stays the global one-file quick-release. Enter performs the action: through the running daemon's control socket (scoped to the selected mount), or directly on the pool when no daemon holds it, the way `sbh ballast release`/`replenish` do; a daemon without a control socket is a refusal, not a race. The outcome (files released or recreated, bytes, a free-space floor holding files back, an already-full pool) or the daemon's refusal is the notification, and the dashboard refetches state.
- Operator-driven releases and replenishes through the control socket are now logged like the daemon's own (`ballast_release` with `pressure = "control"`, `ballast_replenish`), so they appear on the Timeline and in `sbh stats`, and the release controller is told so an operator's release is not refilled at once.
- `state.json` carries `ballast_pools`, one record per mount (mount, pool directory, filesystem, strategy, available/total files, releasable bytes, skipped and why), sorted by mount. The Ballast screen lists those instead of a single volume synthesized on whichever monitored mount came first, so a release is scoped to a mount that has a pool; quick-release lands on a volume with files to give. A state file from an older daemon still parses (the list is empty and the aggregate volume is synthesized as before).
- `tests/dashboard_pty.rs` drives the shipped binary under a pseudo-terminal against a sandbox daemon: screens 1–7 draw their headers, `x` then Enter releases one ballast file (the daemon's event and pool count prove it), and `q` exits cleanly.

### Changed — the cockpit ships in the default build (bd-rc-master-ajg1.4.7)

- `tui` is a default feature: `cargo install`, the release workflow, and CI all build the same feature set (`cli,daemon,sqlite,tui`), so `sbh dashboard` is the frankentui cockpit on every shipped binary. A lean build still exists with `--no-default-features --features cli,daemon,sqlite`.
- The pre-cockpit crossterm dashboard (`src/cli/dashboard.rs`) moved behind the off-by-default `legacy-crossterm-dashboard` feature; `sbh dashboard --legacy-dashboard` remains the plain live status view.
- `sbh dashboard --start-screen <overview|timeline|explainability|candidates|ballast|log_search|diagnostics|remember>` opens the cockpit on that screen for the session without touching the saved preference; an unknown name is a usage error listing the choices.
- `REDUCE_MOTION` (any value but `0`/`false`/`no`/`off`) selects reduced motion the same way `NO_COLOR` disables color; the README's preferences path is the real `~/.config/sbh/preferences.json`.
- Enter on the ballast release confirmation (quick-release `x`, or the Ballast screen's release keys) now performs the release through the daemon's control socket, scoped to the selected mount (one file, or every available file for release-all), and refetches state; the result, or the daemon's refusal, is the notification.
- Without an interactive terminal the cockpit route degrades to the live status view with one stderr line; an explicit `--new-dashboard`/`--start-screen` on a pipe is refused with a "stdout is not a TTY" error. The e2e dashboard cases run the cockpit under a PTY (`script`) and quit it with `q`.

### Added — build metadata in every build path (bd-rc-master-ajg1.5.4)

- A `build.rs` records the git sha (with `-dirty` when the tree has uncommitted changes, or the packager's `SBH_BUILD_GIT_SHA` outside a checkout), the target triple, the profile and a reproducible RFC 3339 timestamp (`SOURCE_DATE_EPOCH`, else the commit time, else the build time). `sbh version --verbose` and the `sbh_info` metrics line read them; a build with none of the sources still says `unknown` instead of failing.

### Changed — the dashboard reads the decision ledger (bd-rc-master-ajg1.3.3)

- The TUI's SQLite telemetry adapter reads `decision_log` for the Explainability screen (real decision ids, factors, veto reasons, policy mode, and the full record for the detail pane) instead of projecting `artifact_delete` rows; a database without the ledger, or with an empty one, falls back to the activity-log projection and is marked partial with the reason. Timeline `artifact_delete` rows carry the id of the decision that approved them (joined from the ledger for SQLite rows, from the line for JSONL) and `Enter` on such a row opens that decision on the Explainability screen. The `tui` feature also compiles again: its `LogEntry` fixtures had missed the `quarantined` field.

### Added — the daemon's own files against the volumes it reclaims (bd-rc-master-ajg1.7.4)

- At startup the daemon checks whether the activity database, the JSONL log and `state.json` share a mount with a scan root, a special location or a ballast pool. It logs one `logging.on_monitored_fs=... device=... paths=[...]` line, carries the result in `state.json` under `logging`, and `sbh status` warns; `sbh doctor --system` gains `logging.on_monitored_fs` (WARN, FAIL while that mount is at Orange or worse). While the mount is pressured, every JSONL line is mirrored to the RAM fallback (capped like the fallback) and the daemon says so once per level change.
- `state.json` is padded to a fixed 64 KiB; when the atomic temp-file write cannot allocate on a full volume, the file is rewritten in place, so status keeps updating exactly when the disk is full.

### Changed — one logging degradation chain (bd-rc-master-ajg1.7.2)

- The daemon's JSONL settings are now a single definition (`JsonlConfig::for_daemon`): rotation at 50 MiB keeping 5 files, fsync every 30 seconds, and the RAM-backed fallback enabled (`/dev/shm/sbh-<uid>.jsonl` on Linux, `$TMPDIR/sbh.jsonl` elsewhere), never rotated and truncated at 16 MiB. An idle timer in the logger thread fsyncs lines written before a quiet spell once the interval passes. SQLite trips after 3 consecutive write failures and is retried every 50 events, which is what the code always did; the README said 50 failures. At open, a database whose `auto_vacuum` is not FULL is converted only when it is larger than 64 MiB.

### Added — reserve sizing from observed write bursts (bd-rc-master-ajg1.2.18)

- The daemon measures, per mount, the peak used-bytes growth inside each reaction window (an EWMA of poll + scan + reclaim latency, five-minute prior) and keeps the samples in a t-digest persisted as `burst_stats.bin` beside `state.json`. The reserve target is the 0.99 quantile of those windows: the digest's own quantile after 50 windows, a generalized Pareto tail fit above the 0.9 quantile from 10 windows, and never below two ballast files. `state.json` carries it per mount as `reserve_state.burst` (`recommended_bytes`, `q99_bytes`, `windows`, `reaction_window_secs`, `method`, `horizon_minutes` at the burst rate); `metrics.prom` exports `sbh_reserve_recommended_bytes` and `sbh_burst_q99_bytes`.
- `sbh tune` recommends `file_count = ceil(reserve / file_size)` per pool (`ballast.file_count` for a single un-overridden pool, `ballast.overrides.<mount>.file_count` otherwise) and `sbh doctor --system` gains `ballast.reserve_coverage`, which FAILs when a pool's releasable bytes fall short of that reserve. `sbh status` shows the required bytes, the estimate method and the window count in the reserve column.

### Changed — event-scoped Green passes (bd-rc-master-ajg1.8.8)

- A filesystem event no longer dirties the whole configured root: it resolves to the project directory below the root that contains the change (the root itself when the change is at the root, when that directory is an artifact tree, or when more than 64 projects are dirty at once). The scanner polls the event source every 2 seconds while idle and runs the scoped pass itself at Green or Yellow, reported as `reason=event` in `scan_complete` and paced by the base `min_rescan_interval_secs` only. Before, Green passes only happened on the maintenance interval and walked everything.

### Changed — inotify watch budget allocation (bd-rc-master-ajg1.8.4)

- The scanner's recursive inotify plan always watches every root and depth-1 directory and spends the rest of `scanner.event_watch_budget` on the most active directories (per-directory event-rate EWMA, directory-mtime prior for never-watched subtrees). Directories left unwatched under a watched parent are reconciled as their own scan paths instead of dirtying the whole root, and an incomplete plan is re-allocated every 15 minutes from observed rates without losing events.
- inotify queue overflows reconcile everything once and then back off (30 s, doubling per consecutive overflow, capped at 30 min); overflows inside the window are coalesced into one deferred reconciliation. `scan_complete` details gained `event_overflows` and `event_watch_replans`; the `scanner_events:` log lines gained `frontier_dirs`, `overflows`, `backoff_secs` and `replans`.

### Added — daemon control socket

- The daemon serves `control.sock` beside `state.json` (mode 0600, per-boot token in `daemon.lock`, JSON line in / JSON line out). `sbh daemon ping|scan-now|reload|shutdown` and `sbh policy status|promote|demote` talk to it; `sbh status --json` asks a running daemon to rewrite `state.json` first and reports `"source": "socket"`. Promotions persist `[policy] initial_mode` after a config backup. `[core] control_socket_enabled = false` turns the socket off.

### Added — Prometheus textfile export

- The daemon writes `metrics.prom` beside `state.json` with every state write (atomic, world-readable) for node_exporter's textfile collector: daemon identity/uptime/CPU/RSS/budget, per-mount free ratio, pressure level, fill rate, forecast, reclaim capability, controller state and ballast bytes, plus scan/deletion/byte counters, policy mode and thread liveness. `sbh metrics` prints it; `[telemetry] metrics_enabled = false` turns it off and removes a stale file.

### Fixed — daemon scanner hot loops at Orange (bd-8aeq)

- A definite cargo `target/` replayed from the scanner index was re-classified from the root directory's own entries and downgraded to `unclear`, so the Orange cell held it back forever while the replay re-dispatched it twice a second. Index records now persist the walk's structural signals (checkpoint version 2; an old index is walked once more) and replays score with them.
- The scanner applies the behavior cell's certainty gate itself: held-back candidates are neither dispatched nor counted toward the pressure byte target, and a pass whose dispatches reclaimed nothing (dry-run, observe mode, dampened or failed batches) is paced like an empty pass. Measured on the operator workstation at injected Orange: 575 passes / 92.8 CPU-s per five minutes before, 4 passes / 8.6 CPU-s after.

### Changed — status and check JSON schema 2

- `status --json` and `check --json` carry `"schema_version": 2`; each mount's `platform` block is keyed by filesystem family (`darwin.apfs` on APFS, `linux { fs_type, is_ram_backed, is_readonly, device_id }` on Linux, `{}` elsewhere) and the APFS-only mount keys, including `free_excludes_purgeable`, appear only on APFS.

### Added — diagnostics and recovery

- `sbh doctor --service [--user]` diffs the installed systemd unit or launchd plist against the generator (hardening directives, `Type=`, binary, drop-ins, condition gates); `sbh service --systemd reinstall-unit [--purge-dropins]` rewrites the unit with a backup beside it.
- `sbh explain --why-not DIR [--counterfactual]` scores a directory now and names the first rail that stops it; `sbh explain --replay ID` re-scores a recorded decision with the current code.
- `sbh emergency --min-age MINUTES` (default 5) is emergency mode's only age floor; emergency prints a decision id per candidate.

---

## v0.5.1 **[release]**

### Fixed — rch target dirs are reclaimed on idle time, not birth time (regression from v0.5.0)

v0.5.0 widened reclaim to key on `CACHEDIR.TAG` rather than directory name.
Cargo writes `CACHEDIR.TAG` into every target dir, so rch's remote
`CARGO_TARGET_DIR` trees — previously invisible to the name matcher — became
first-class candidates. Being the largest directories on a build host, they
scored highest.

They were also removed **while builds were writing to them**, because
`EntryMetadata::effective_age_timestamp` ages directories by *birth* time. That
is deliberate and correct for ordinary caches (a directory's `mtime` bumps on
every child add/remove, so an active `target/` looks perpetually young), but it
inverts for an rch pool dir: a warm cache created days ago and rebuilt into ever
since still reports an age of days, so it scores as maximally abandoned exactly
when it is busiest. On one host this removed an 18.9 GB and a 12.3 GB pool dir
in a single sweep.

Removing a pool dir does not reclaim reusable space. It forces every subsequent
dispatch sharing those build dimensions to rebuild the whole crate graph from
cold.

Reclaim of rch-managed dirs now mirrors rch's own contract
(`rch-common/src/stale_target_reap.rs`):

- scope is exactly rch's `REAP_GLOBS` — the `-job-`, `-pid-` and `-pool-`
  marker shapes under `.rch-target-`. Bare `rch_target_*` and `target` trees
  keep their existing scoring.
- eligibility is **recursive tree idleness**, tested with an early exit on the
  first fresh file, not the directory's own timestamp.
- idle floors match rch: 12 h for per-job and per-pid dirs, 168 h (7 days) for
  pooled ones, which rch treats as warm caches rather than short-TTL targets.
- an indeterminate result (unreadable subtree, or a tree past the traversal
  guard) vetoes rather than removes, deferring to rch's own reaper.

Vetoed candidates are never plannable in any mode, including emergency
escalation.

### Fixed — `sbh stats` no longer looks broken when the daemon runs as root

The activity database lives under the invoking user's data dir. With the usual
root-owned daemon, an unprivileged `sbh stats` correctly found nothing and
reported a bare `no_database`, which reads as a malfunction. It now detects the
root-owned database and points at `sudo sbh stats` (JSON output gains `hint` and
`root_db_path`).

---

## v0.5.0 **[release]**

### Changed — build-cache reclaim is now keyed on `CACHEDIR.TAG`, not directory name (bd-k0t3r)

**This widens what the reclaim daemon will delete. Read before rolling out.**

Previously a regenerable build cache was recognised only by directory *name*
(`rch_target_*` plus a fixed set of `target`-like patterns) together with
structural markers (`deps/`, `incremental/`, `.fingerprint`) that live one level
down under `debug/` and `release/`. Cargo target dirs under arbitrary names —
`srw`, `p4-verify`, `*bld`, the shared `cargo-target` — matched no name pattern
and exposed no markers at their own root, so they were never reclaimed. They
were also the largest consumers, and drove `/` to ~98%, at which point the host
starts killing in-flight builds.

Reclaim now detects cargo's canonical `CACHEDIR.TAG` marker, **with signature
validation**, so a file merely *named* `CACHEDIR.TAG` cannot mark a directory
reclaimable.

Operationally: directories that were previously invisible to the sweeper are now
eligible. That includes isolated `RCH_TARGET_BASE` target dirs. Verify on a
canary host before fleet rollout.

### Fixed

- Scanner duty cycle is bounded so a productive pass cannot pin a core.
- Scanner/walker error mapping, symlink handling, and diagnostics refined.
- Five exhaustive struct literals that `cargo test --lib` never compiled.
- `clippy -D warnings` clean, including the two deletion fail-safes, which keep
  their deliberate negative-first form (`if !complete { skip } else { delete }`)
  under an annotated `#[allow(clippy::if_not_else)]` rather than being inverted.

### Notes

- Lib tests: 1404 passed, 0 failed. Run them as a **non-root** user — as root,
  `fallback_when_primary_dir_unwritable` cannot exercise its fallback because
  root can create the "unwritable" path, producing ~20 environmental failures
  that are not defects (see #19).

## v0.4.40 **[release]**

Tag: [`v0.4.40`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.40) | Compare: [`v0.4.39...v0.4.40`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.39...v0.4.40) | 2026-08-16

### Fixed — interactive clean/emergency deletions use the full preflight veto stack

- Adversarial review of the v0.4.39 emergency escalation found that the interactive `clean` and `emergency` paths (no `--yes`) removed accepted candidates through a bare `remove_dir_all`, bypassing the source-tree floor, active-lease, open-file, and marker vetoes the `--yes` batch path enforces. Both now go through the same preflight stack ([`0dde89a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0dde89ae3356570d5e08bd08057c362f784a7373)).

## v0.4.39 **[release]**

Tag: [`v0.4.39`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.39) | Compare: [`v0.4.38...v0.4.39`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.38...v0.4.39) | 2026-08-15

### Added — process-scoped active-target leases

- A live cargo/build target is neither marker-protected nor an open file, so it could be reclaimed mid-build. A build can now hold a process-scoped lease on its target that survives `exec`; leases are probed on canonical paths so symlink ancestors cannot fail open, and a watchdog keyed on the process group releases them when the process dies ([`8ed845b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8ed845b4daa24e8d75b8ee682cfb0e9151ff28f0), [`37111db`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/37111dba9bd2c38d1286f33b2fbfaf27d8d88e85), [`430b7dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/430b7dd4ef6552d7407a4f591d8ff30855324368), [`fd9298f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fd9298f2cac6d92888ddc430db6e54dbb129f6f1)).

### Changed — emergency mode acts on `Review` candidates

- `sbh emergency` only admitted `Delete` decisions, so a corpus that scored entirely as `Review` made the last line of defence a no-op on a full disk. Review candidates are now eligible in emergency mode, with every hard safety rail unchanged ([`1923bc8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/1923bc898da3b9b0afe000dc7fac2f372b097f8b)).

### Fixed — every skip is attributed

- A run reporting 221 candidates, 221 skipped, and 0 bytes freed with no reason was indistinguishable from a malfunction. `clean` and `emergency` reports now attribute each skip (`skipped_by_reason`) and flag a stalled run, on the no-candidates path too ([`8e10858`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8e10858b5ca794a489e255b22a95103fcb0539f5), [`b00ca43`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b00ca43bac83b6f6779f5fc128ae1a878b83df6b), [`c47ce06`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c47ce06289281da1957b22ec6b5882accf7a1789)).
- Local builds use the parallel rustc front-end (`-Z threads=4`) ([`94fa77a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/94fa77a85355b50f0092c899be6e02a91966a994)).

## v0.4.38 **[release]**

Tag: [`v0.4.38`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.38) | Compare: [`v0.4.37...v0.4.38`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.37...v0.4.38) | 2026-08-11

### Performance — protected sacred verdicts are memoized across daemon passes

- Re-proving sacred overlaps every pass recursively walked known-protected `/data/tmp` candidates and pegged a core. Only *protected* verdicts are cached (never "clean", which would fail open if a marker appeared later): TTL 600 s, capacity 4096, invalidated when the root's mtime changes ([`12fd99e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/12fd99e355cb6aea3f874a399ca4a3a15843a870)).

## v0.4.37 **[release]**

### Fixed — sparse files are sized by allocated blocks (#17)

The walker sized every entry with `meta.len()` (`st_size`, the *apparent*
logical length) in `entry_metadata`, and accumulated directory content size the
same way via `child_meta.len()`. A sparse file therefore contributed its full
logical size rather than the space it actually occupies: a 20 GiB `set_len`
image with zero allocated blocks was reported as 21474836481 bytes, and a
real-world store directory holding one sparse disk image reported 927 GiB of
usage that did not exist on the device.

Entries are now sized by allocated blocks (`st_blocks * 512`) on Unix, which is
what a ballast/reclaim tool has to reason about — reclaiming a sparse file
returns only its allocated extents, not its logical length. Apparent length is
still available where the logical size is the meaningful quantity.

### Also in this release

- Ballast health reporting: `Unconfigured` now outranks `Indeterminate`, an
  unreadable reserve is never reported as empty, and the unreadable tally is
  surfaced instead of being silently folded into the healthy count.

---

## v0.4.36 **[release]**

Tag: [`v0.4.36`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.36) | Compare: [`v0.4.35...v0.4.36`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.35...v0.4.36) | 2026-08-02

### Performance — ancestor canonicalization is memoized

- `resolve_absolute_path` called `canonicalize` once per path, one `readlink` per component, re-resolving the same ancestor chain for every descendant. Ancestors are now memoized, which ends the scanner's readlink storm on wide trees ([`74e52a9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/74e52a95b32c2daae49ba4ab4b8bd3b9f4c4a991)).

### Fixed — macOS zombie processes

- `command_output_with_timeout` dropped a timed-out child before reaping it, leaking one zombie per timed-out command for the life of the process ([`3508685`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/35086853bc69b87250d2fcdf25c2b37abd7068be)).

## v0.4.33 **[release]**

Tag: [`v0.4.33`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.33) | Compare: [`v0.4.32...v0.4.33`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.32...v0.4.33) | 2026-07-02

### Added — safe `/root` build-artifact backstop

- A stale 241 GB `/root/cass-ft-target` filled a worker because `/root` is a hard system-path veto and the artifact-basename rule had no `*-target`/`*_target` suffix. A narrow, safety-gated backstop now reclaims regenerable build targets under `/root` ([`1389645`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/13896455a4c3c8ef7a29e6cd6240f32234325da0)).
- `Cargo.lock` completed with ftui's transitive `fsqlite-*` dependencies so `--locked` source builds resolve ([`7298046`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7298046e627d1cc4f07f23b0a663a173782df1c2)).

## v0.4.32 **[release]**

Tag: [`v0.4.32`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.32) | Compare: [`v0.4.30...v0.4.32`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.30...v0.4.32) | 2026-06-30. The v0.4.31 version bump below was never tagged; this release carries it.

### Added — Go caches are reclaimable; scanner v2 is the default engine

- `GOCACHE`/`GOMODCACHE` trees (tens of GB under arbitrary names; module dirs ship a `go.mod` and are mode `0555`) are now recognized, pass the source-code veto, and can be removed. The v2 scanner engine is the default ([`7e50e27`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7e50e2787b077d1a2447a27b3818d8ee2559105c)).

### Fixed

- The daemon's multi-volume ballast coordinator ignored `[paths] ballast_dir` and always used `<mount>/.sbh/ballast` ([`0e8f703`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0e8f703b42deb6b50ec6ed70091296f5dba6a08c)).
- `ftui` is sourced from git instead of a local `/dp` path so `cargo install --git` works off the build host (#12) ([`0f534d8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0f534d8c9c4a20e90eb626b946e74a9bda0248b9)); the empty-pass no-progress fix landed via #13 ([`8591776`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8591776757b425f24dcd03dfbb71f62c505527cd)).

## v0.4.31

Never tagged; shipped in v0.4.32 above.

### Added — kernel writeback (dirty-page) tuning

sbh already runs its daemon at `Nice=19` + `IOSchedulingClass=idle`, but the worst
interactive-latency stalls on busy build hosts come from *kernel* writeback behavior that no
per-process nice/ionice can fix. On a high-RAM box the default percentage-based
`vm.dirty_ratio`/`vm.dirty_background_ratio` knobs let many GB of dirty pages accumulate before
writeback throttles (e.g. ~24 GB at `dirty_ratio=10` on a 247 GB host); they then flush in bursts
through kernel writeback threads (`btrfs-endio-write` and friends) that ignore the producing
process's ionice class, so the interactive terminal stalls behind each multi-GB flush. The fix is
to replace the ratio knobs with absolute byte limits (`vm.dirty_bytes`/`vm.dirty_background_bytes`)
sized for continuous, gentle writeback.

sbh now models this cross-platform and applies it on Linux:

- **`sbh tune`** gained a `KernelWriteback` recommendation category. It sizes the byte limits from
  the backing device's **measured write bandwidth** (a short, bounded, non-destructive on-volume
  micro-benchmark with random data; `--no-benchmark` falls back to an NVMe/SSD/HDD device-class
  heuristic). At a typical ~512 MiB/s SSD with the default 1 s background-drain target and 4:1 hard
  ratio this lands on `vm.dirty_background_bytes=512 MiB` / `vm.dirty_bytes=2 GiB`. `--apply`
  (root) writes the live `/proc/sys/vm` knobs **and** persists a backup-first, self-documenting
  `/etc/sysctl.d/99-sbh-writeback.conf`, validates it with `sysctl -p`, and warns about any
  later-loading `sysctl.d` file that would override the byte limits with a ratio.
- **`sbh tune --revert-writeback`** (root) restores the most recent backup of the sbh snippet (or
  removes it) and reloads sysctl.
- **`sbh doctor --system`** adds a `system.writeback_tuning` check that WARNs when the RAM-derived
  dirty pool exceeds `system_tuning.writeback_pool_warn_bytes` (default 4 GiB), escalated for
  copy-on-write filesystems (btrfs/zfs). It is read-only (heuristic only, never benchmarks) and
  returns PASS/not-applicable on platforms without tunable writeback limits (macOS).
- **`sbh install`** applies + persists the tuning automatically when run as root
  (`system_tuning.writeback_auto_apply_on_install`, default on); non-root installs print the
  `sudo sbh tune --apply --yes` hint.

This is **never applied by the daemon at runtime** — the hardened system-scope unit sets
`ProtectKernelTunables=true` (so the daemon cannot write `/proc/sys`), and silently mutating global
kernel state from a background daemon would violate sbh's explainability/least-surprise principles.
All mutation is operator-invoked, root-gated, backup-first, and reversible.

New `[system_tuning]` config section (with `SBH_SYSTEM_TUNING_WRITEBACK_*` env overrides):
`writeback_enabled`, `writeback_auto_apply_on_install`, `writeback_target_drain_secs`,
`writeback_hard_ratio`, `writeback_min_background_bytes`, `writeback_max_background_bytes`,
`writeback_benchmark_enabled`, `writeback_benchmark_bytes`, `writeback_pool_warn_bytes`,
`writeback_sysctl_path`.

New PAL surface: `writeback_state()`, `block_device_for()`, `apply_writeback_runtime()`
(Linux reads `/proc/sys/vm` + `/sys/block`; other platforms return not-applicable). New
platform-agnostic `tuning` module (`tuning::writeback`, `tuning::bandwidth`) holds the sizing,
assessment, `sysctl.d` rendering, conflict detection, and bandwidth estimation, fully unit-tested.

---

## v0.4.30 **[release]**

Compare: [`v0.4.29...v0.4.30`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.29...v0.4.30)

### Fixed — empty-pass cooldown now keys on reclaim *progress*, not candidates *surfaced* (+ exponential backoff)

v0.4.29's B6 empty-pass cooldown only armed when a scan surfaced **zero** candidates
(`candidates_found == 0`). On a disk parked below the green free-space threshold whose
candidates are *all protected* — e.g. `/data/tmp` test fixtures full of `*.sqlite-wal`,
`.git/`, `.beads/` sacred markers — every ~50s scan surfaces hundreds of candidates that
are then all skipped, so `deleted == 0 / freed == 0` yet `candidates_found > 0`. The
cooldown was therefore cleared on every pass and never engaged: the scanner re-walked the
same tree back-to-back and pinned a core 24/7 (observed on ts2 — ~100 CPU ticks/s for
~2 days, contained only by the `CPUQuota` cap).

- **Cooldown now keys on reclaim progress.** `dispatch_top_candidates` reports how many
  candidates it handed to the deletion executor; a pass arms the cooldown when it
  dispatched **nothing** (`dispatched_this_pass == 0`) — covering both "found nothing" and
  the hot-loop case "found candidates but all protected/dampened".
- **Exponential backoff for sustained no-progress.** Each consecutive no-progress pass
  doubles the rescan interval, capped at 32× `min_rescan_interval_secs` (90s → … → 2880s),
  resetting to the base interval on the first productive pass. A perpetually-pressured-but-
  nothing-to-reclaim disk decays from one scan per base interval to one per ~32× instead of
  re-walking continuously.

Red/Critical pressure still bypasses the cooldown (disk-safety floor unchanged); the
deletion path and all protection logic are untouched. Verified live on ts2: daemon CPU
~100 → ~1.5 ticks/s, with backoff log lines firing (`… 427 candidates, 0 dispatched;
backing off rescans (consecutive=2, … ≥180s)`).

---

## v0.4.29 **[release]**

Compare: [`v0.4.28...v0.4.29`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.28...v0.4.29)

### Fixed — scanner hot-loop: bounded marker sub-walk, device-affinity gate, empty-pass cooldown

Ships the scanner fixes from PR #11 (`sbh-scan-affinity-and-bounded-marker-walk`, merged to
`main` as `13c5005` / `34957b6`). These landed **after** the published v0.4.28 release, so the
0.4.28 binary running fleet-wide never contained them — and on 2026-06-12 the scanner was found
hot-looping at ~100% of a core 24/7 on every orchestrator (one host's pass walked 218,186
entries / 7,160 top-level `/data/tmp` dirs in 356s, then immediately rescanned on a 5s poll).
Three independent fixes, **none of which touch the deletion path or weaken any safety floor**:

- **Bounded sacred-marker sub-walk.** The "protected candidate skipped" containment check that
  walks a candidate looking for sacred markers (`.beads/`, `.git/`, `*.sqlite3`, `*.db-wal`, …)
  previously ignored `scanner.max_depth` and full-walked million-file trees every pass. It now
  caps at `max_entries` (20k) with early-exit and **fails closed to PROTECTED on truncation** — a
  truncated walk can only strengthen protection, never weaken it.
- **Device-affinity gate.** Aggressive scanning triggered by pressure on a device is suppressed
  when no configured `root_path` actually lives on that device (e.g. `/` is full but every
  `root_path` is on `/data`), a situation the scanner can never relieve and would otherwise spin
  on forever.
- **Empty-pass cooldown.** New `scanner.min_rescan_interval_secs` (default 90s) enforces a
  cooldown after a pass that produced no deletions, so a steady state of all-protected candidates
  no longer triggers back-to-back rescans.

Verified on the trj canary (2026-06-02): CPU settles to 0–3% (was pinned ~100%), the
device-affinity backoff fires in production logs, `sbh clean --dry-run` enumerates 38,922 dirs in
10s with 0 candidates, and zero `auditd` DELETE events occur under `/data/projects`. 2,275 library
tests pass.

> Operational note: hosts that accumulate *thousands* of marker-bearing ephemeral test dirs under
> `/data/tmp` should still keep that directory pruned — the bounded walk caps cost per candidate,
> but a very large top-level dir *count* is still real work per pass. A periodic `/data/tmp`
> janitor and a longer `poll_interval_ms` are complementary operational mitigations.

---

## v0.4.28 **[release]**

### Added — `rch-cargo-home-*` cleanup matcher

rch (the remote compilation helper) stages an isolated `CARGO_HOME` per build in a
`rch-cargo-home-<host>-<pid>-<uuid>` directory; as of rch 1.0.38 these land under
`$TMPDIR`/`/data/tmp` and are left behind when a build dies. sbh had no matcher for
this prefix (`cargo-home-` and `.tmp_cargo_home_` did not cover `rch-cargo-home-`),
so these abandoned dirs were never reclaimed. Added a basename `Prefix("rch-cargo-home-")`
matcher (`ArtifactCategory::TempDir`, confidence 0.92), mirroring the existing
`cargo-home-prefix` rule. Matching is by basename, so it fires regardless of the
parent (`/tmp` vs `/data/tmp`). The narrow source-tree carve-out
(`is_obvious_build_artifact_basename`) was deliberately **not** extended, so the
hard `is_hardcoded_source_tree()` refusal still gates these dirs under any protected
source root — the matcher only affects scoring/age in tmp-like roots. Reviewed
adversarially: cannot match a source/repo/`.git` dir (trailing-hyphen prefix); no
change to deletion-scope floors.

---

## v0.4.27 **[release]**

Tag: [`v0.4.27`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.27) | Compare: [`v0.4.26...v0.4.27`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.26...v0.4.27) | 2026-05-27

- One commit over the unpublished v0.4.26 tag: the macOS active-reference mock paths are normalized so the platform test lane passes; no runtime change ([`53a7475`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/53a747501846319c24de314f97882fdc8a48d235)). For what v0.4.26 itself changed over v0.4.25, see the compare link.

## v0.4.25 **[release]**

Compare: [`v0.4.24...v0.4.25`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.24...v0.4.25)

### Safety floor — source-code deletion is now impossible regardless of config

**Background.** The 2026-05-16 fleet carnage wiped ~87 working trees under `/data/projects` on trj when the scanner's name-heuristic gave source-crate directories high artifact-like scores. The carnage repeated on a smaller scale on 2026-05-22 when sbh was re-enabled on the vmi worker fleet: synced source-crate stubs (1–10 KB, no `Cargo.toml` yet) were classified as deletable artifacts and `frankenterm/crates/frankenterm-core`, `frankenterm/crates/frankenterm-alloc`, `frankenterm/crates/frankenterm-topo`, and ~25 other crate dirs were deleted across vmi1149989/vmi1153651/vmi1156319/vmi1167313 before the operator caught it. No primary source was lost (vmis hold synced ephemeral copies and re-sync from trj on next rch job), but the bug means an operator who points sbh at `/data/projects` on a primary dev machine can lose actual source.

**Fix.** Two hardcoded safety layers were added to `scanner::deletion::preflight_check` that cannot be disabled via operator configuration:

- **`SkipReason::HardcodedSourceTree`** (preflight step 0, runs BEFORE the existence check) refuses paths inside well-known source-tree locations — `/data/projects/`, `/home/<user>/projects/`, `/Users/<user>/projects/` — UNLESS the candidate's basename clearly identifies it as a disposable build/cache artifact (see the carve-out list below). It also refuses, unconditionally with no carve-out, any path with an ancestor directory literally named `.git` (including the candidate itself being named `.git`). The match list is hardcoded and cannot be disabled by config.
- **`SkipReason::LooksLikeSourceCode`** (preflight step 5b, runs after the existing cargo-manifest veto) refuses any directory that directly contains a source manifest (`Cargo.toml`, `package.json`, `pyproject.toml`, `setup.py`, `go.mod`, `pom.xml`, `build.gradle`, `tsconfig.json`, `Gemfile`, `Pipfile`, `mix.exs`, `Project.toml`, etc.) OR direct-child source files (`*.rs`, `*.py`, `*.ts`, `*.go`, `*.cpp`, `*.swift`, `*.rb`, `*.java`, `*.kt`, `*.ex`, `*.exs`, `*.ml`, `*.hs`, `*.c`, `*.h`, `*.hpp`, `*.scala`, `*.clj`, `*.cljs`, `*.lua`, `*.jl`, etc.). Catches synced stubs that lack `Cargo.toml` and so slip past the existing `ContainsCargoManifest` veto. Direct-child only (no recursion). The check applies everywhere — even outside the hardcoded source-tree paths — so a stray `package.json` in an unexpected location still triggers a veto.

Both new skip reasons are routed through the existing "normal safety veto" log-noise filter so they don't flood the activity log with expected refusals.

### Artifact-basename carve-out — keeps sbh useful inside source trees

The broad source-tree refusal would otherwise block sbh from doing its main job inside operator-configured source roots (the setup wizard adds `/data/projects` to `root_paths` precisely so target/ etc. can be cleaned). The carve-out is a narrow allow-list of basenames that are unambiguously disposable:

**Exact match** (alphabetized): `.cargo-target`, `.next`, `.nuxt`, `.parcel-cache`, `.pytest_cache`, `.rch-target`, `.rch_target`, `.target`, `.tox`, `.turbo`, `.venv`, `__pycache__`, `build`, `dist`, `node_modules`, `rch-target`, `rch_target`, `target`, `venv`.

**Prefix match (each requires the trailing separator):** `target-*`, `target_*`, `.rch-target-*`, `.rch_target_*`, `rch-target-*`, `rch_target_*`, `.cargo-target-*`.

The separator requirement matters — an earlier draft used `.rch-target` as a prefix (no trailing `-`), which would have falsely matched names like `.rch-targetfoo` and exempted them from the protection. Each prefix matcher in the implementation requires its separator; bare basenames without suffixes are in the exact-match list instead.

A path under a protected root whose basename matches one of these IS deletable; any other basename is vetoed. This means `/data/projects/franken_node/target` gets cleaned, but `/data/projects/franken_node/src` (or `/data/projects/frankenterm/crates/frankenterm-core`, the actual 2026-05-22 incident) stays protected.

The `.git`-ancestor refusal is NOT subject to the carve-out — `/srv/code/.git/target` is still vetoed because the `.git` ancestor wins. The whole purpose of refusing under-.git paths is to protect git metadata; allowing artifact-named children would defeat that.

### Default scan roots are now safe out of the box

`ScannerConfig::default()` shipped with `["/data/projects", "/tmp", "/data/tmp", "/var/tmp", "/home", "/root"]` — three of those six entries hold source code or personal files. A fresh install that inherited defaults was unsafe. New default:

- `root_paths = ["/tmp", "/data/tmp", "/var/tmp"]` — only ephemeral temp paths.

`excluded_paths` is unchanged. `/data/projects` is intentionally NOT added to default `excluded_paths`: the setup wizard (`cli/wizard.rs`) actively adds `/data/projects` to `root_paths` when run, so excluding it would silently break wizard-generated configs (the walker would refuse to descend into the configured root). The hardcoded preflight refusal at deletion time — combined with the artifact-basename carve-out — is the real defense.

### Operator implications

Once v0.4.25 is deployed and sbh is re-enabled:

- The setup wizard's auto-added `/data/projects` root continues to be useful: `target/`, `node_modules/`, `.rch-target-*/`, etc. under it ARE cleaned up.
- Arbitrary basenames under `/data/projects/`, `/home/*/projects/`, or `/Users/*/projects/` (e.g., `src/`, `docs/`, `crates/`, `frankenterm-core/`) are refused at preflight even if the scorer marks them as candidates. This is the carnage-prevention guarantee.
- `LooksLikeSourceCode` (step 5b) provides a second-layer defense even outside the protected paths: any dir containing source manifests or top-level source files is refused regardless of where it sits.

If the carve-out list misses a basename you'd like sbh to clean (or includes one you'd like protected), it's an additive edit to the constant list inside `is_obvious_build_artifact_basename` in `src/scanner/deletion.rs` — no API change.

### Tests

Hardcoded source-tree refusal:

- `hardcoded_source_tree_matches_data_projects` / `_home_projects` / `_users_projects` — non-artifact basenames under each protected root are refused.
- `hardcoded_source_tree_skips_unrelated_paths` — `/tmp/junk`, `/home/ubuntu/.cache`, `/home/ubuntu/project` (singular), etc. pass through unchanged.
- `hardcoded_source_tree_matches_git_ancestor` — paths with `.git` ancestor (including the leaf case `/srv/code/.git` and `/.git`) are unconditionally refused.

Artifact-basename carve-out:

- `obvious_build_artifact_basename_exact_matches` — every entry in the exact-match list is recognized (covers all 19 bare names including the bare `.rch-target`, `.rch_target`, `rch-target`, `rch_target` variants).
- `obvious_build_artifact_basename_prefix_matches` — `target-*`, `target_*`, `.rch-target-*`, `.rch_target_*`, `rch-target-*`, `rch_target_*`, `.cargo-target-*` patterns recognized.
- `obvious_build_artifact_basename_negatives` — confusables (`targets` plural, `my-target`, `untargeted`, `nodemodules` without underscore, etc.) and real source basenames (`src`, `lib`, `tests`, `docs`, `frankenterm-core`, etc.) do NOT match. Includes regression cases for the prefix-without-separator class (`.rch-targetfoo`, `rch-targetfoo`, `rch_targetfoo`, `.cargo-targetfoo`, `targetfoo`) that an earlier permissive prefix matcher would have wrongly exempted.
- `obvious_build_artifact_basename_handles_no_basename` — `/` and empty paths return false.

Hybrid behavior:

- `hardcoded_source_tree_allows_target_under_data_projects` — `target/`, `node_modules/`, `.next/`, `__pycache__/` under `/data/projects/foo/` are NOT vetoed.
- `hardcoded_source_tree_allows_rch_targets_under_data_projects` — full rch per-job target paths are recognized via the prefix-match list.
- `hardcoded_source_tree_allows_target_under_users_projects` / `_under_home_projects` — carve-out applies equally to all three protected roots.
- `hardcoded_source_tree_still_vetoes_source_basenames_under_protected_root` — `src`, `docs`, `legacy_code`, working-tree root names, and the actual 2026-05-22 incident target (`frankenterm-core`) all STAY vetoed.
- `hardcoded_source_tree_git_check_overrides_artifact_carveout` — `/srv/code/.git/target` and `/srv/code/.git/objects/pack/target` are refused despite the artifact basename, because the `.git` ancestor check runs after the carve-out.

Source-code marker veto:

- `looks_like_source_code_detects_cargo_toml` / `_rust_files` / `_package_json` / `_python_files` / `_go_files` — positive triggers across languages.
- `looks_like_source_code_ignores_build_artifacts` — pure cargo `target/` dir is NOT classified as source.
- `looks_like_source_code_skips_unreadable_dir` — `read_dir` failure returns false (matches existing helper behavior).

Preflight wiring:

- `preflight_vetoes_hardcoded_source_tree` — step 0 fires for `/data/projects/frankenterm/crates/frankenterm-core`.
- `preflight_vetoes_source_code_dir` — step 5b fires for a dir with `package.json` + `index.ts`.
- `preflight_cargo_manifest_still_takes_precedence_over_source_marker` — locks in step 5 (ContainsCargoManifest) firing before step 5b (LooksLikeSourceCode) when a dir matches both, so a future refactor that swaps the order is visible in test diffs.

### Fleet status as of this release

This crate version is not yet built or deployed. The je fleet currently runs v0.4.24 with operator-patched `/etc/sbh/config.toml` (`root_paths = ["/tmp", "/data/tmp"]`). The config patch alone is sufficient to prevent the recurring scenario (walker never descends into `/data/projects`); v0.4.25 lets operators safely add `/data/projects` back to `root_paths` because the in-code defenses fire at deletion time — refusing source-shaped paths while permitting `target/` and friends.

## v0.4.24 **[release]**

Tag: [`v0.4.24`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.24) | Compare: [`v0.4.23...v0.4.24`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.23...v0.4.24) | 2026-05-17

### Fixed — release artifacts are verified against their matrix target

- v0.4.23 shipped the macOS aarch64 binary inside the Linux x86_64 tarball, so every Linux self-update failed with `Exec format error`. The release workflow now verifies each tarball's binary matches its matrix target before upload ([`b15e1e0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b15e1e0da3ac4cc8362f3e2af1a955bcd28a30ac)).

### Changed — log truncation sees the measured free space

- The v0.4.23 truncation hook mapped pressure levels to synthetic free percentages; it now receives the measured `free_pct` and opens files defensively ([`19d8814`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/19d88147ff7dc9e197c687718a74f01a6127fafb)); the non-UTF-8 filename test is gated to Linux ([`5854496`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/58544962980f0a6b9a8806c40f8c21399c8c2a32)).

## v0.4.23

Tag: [`v0.4.23`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.23) | Compare: [`v0.4.22...v0.4.23`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.22...v0.4.23) | 2026-05-14. A GitHub Release exists but carries no assets: the artifacts were mispackaged (see v0.4.24).

### Added — truncate-in-place for active append-only logs

- The 2026-05-13 fleet incident drove three hosts to 99% because the open-file veto refused to touch `~/.codex/log/codex-tui.log` while codex held it open (318 GB, 132 GB, and 81 GB). Active append-only logs are now truncated in place under pressure ([`508fe4c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/508fe4ca36c5f2d1b84994cba886142d8b733fe5)); the macOS docs record the v0.4.22 release ([`13abf49`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/13abf49953f98863c3e64a738c09dcc7d89583f1)).

## v0.4.22 **[release]**

Tag: [`v0.4.22`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.22) | Compare: [`v0.4.21...v0.4.22`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.21...v0.4.22) | 2026-05-12

- The release publisher and Homebrew tap updater download only `sbh-*` build artifacts, keeping the archive contract to the four build artifacts plus checksum sidecars. v0.4.21 had proven the gates and the signed, notarized builds but failed at publish ([`d8bfa92`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d8bfa924a511ac02ad0644639ce8cf529d589144)).

## v0.4.14 **[release]**

Tag: [`v0.4.14`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.14) | Compare: [`v0.4.13...v0.4.14`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.13...v0.4.14) | 2026-05-12

### Fixed — macOS cross builds

- `libproc` generated its Darwin bindings with host-side cfg checks, so Linux cross builds for `aarch64-apple-darwin` failed before linking. Its process-list, pidpath, rusage, and region-path calls moved behind the existing `sbh_mach` platform crate ([`079553d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/079553d2cf14b99877f046ec1cd0836469978983)).

## v0.4.8 **[release]**

Tag: [`v0.4.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.8) | Compare: [`v0.4.7...v0.4.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.7...v0.4.8) | 2026-05-11

### Changed — macOS release trust verification

- The release workflow's raw `spctl` gate is replaced by validation of Apple's accepted notary log; the Unix installer and the self-update verifier require `codesign` structural validity plus the expected Developer ID Application authority and TeamIdentifier ([`081d3e7`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/081d3e7024f046ca6e67a62f614f637cae13608e), [`52b4c3d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/52b4c3d31399a08d8f671444e746e2f98a99ed4a)).

## Unreleased

Compare: [`v0.4.6...HEAD`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.6...HEAD)

### macOS

- **Document the macOS cleanup wins in concrete operator terms.** The Unreleased macOS docs now explain the real before/after space-recovery cases instead of only listing implementation details. Before this work, a Mac operator had to infer what was safe from Linux-flavored artifact language; after it, the release notes call out the exact macOS cleanup shapes and tradeoffs: `sbh` can rank a stale 12 GB Xcode DerivedData child after 24 hours without deleting the broad `~/Library/Developer/Xcode/DerivedData/` root, surface a 64 GB Time Machine local snapshot retention case with the exact `sudo tmutil thinlocalsnapshots / 9999999999999999 4` reclaim command, classify regenerated Electron caches such as `Cache`, `Code Cache`, `GPUCache`, `IndexedDB`, `Service Worker/CacheStorage`, and `vm_bundles` so an idle 8 GB app cache can be cleaned while active app state remains guarded, and detect forgotten `~/release-work/*[-_]buildroot` staging trees after 7 days. The real incident example is preserved: `~/release-work/mcp_agent_mail_rust_buildroot` sat idle for 11 days and held 39 GB.
- **Tie the release note back to the operator trust docs.** The macOS changelog now points readers to `docs/cleanup-rules-macos.md` for the exhaustive cleanup contract and `docs/macos.md` for platform behavior such as APFS retained snapshots, launchd service expectations, and Full Disk Access checks.

### Scanner

- **Recognize bare in-tree `.rch-target/` as a first-class rch artifact pattern.** Previously the bare directory names (without a per-job suffix) only hit the generic suffix rules — `target-suffix` (`Suffix("-target")`, 0.88) for the hyphen variants and `underscore-target-suffix` (`Suffix("_target")`, 0.92) for the underscore variants — so they inherited moderate confidence. Stats grouping in `extract_pattern_label` was also lossy: `.rch-target`/`rch-target` landed in the generic `*-target` bucket while `.rch_target`/`rch_target` fell through to the catch-all `unknown` bucket (the existing `*-target` and prefix-based rch checks didn't cover them). Adds four explicit `Exact` patterns — `.rch-target` (0.95), `.rch_target` (0.94), `rch-target` (0.93), `rch_target` (0.93) — with confidences set above BOTH conflicting suffix matchers so `classify()` picks them deterministically. Updates `extract_pattern_label` to group all four with their per-job siblings under `rch_target_*`.

### Daemon

- **In-tree `.rch-target/` dirs now bypass the tmp-only path gate during Orange/Red pressure.** A 117 GB `.rch-target/` under `/data/projects/franken_engine/...` left vmi1167313 stuck at 100% disk because (a) the directory wasn't under `/tmp`/`/data/tmp`, and (b) its mtime was bumped continuously by active rch builds — so the age veto fired forever. `should_fast_track_temp_age` now consults a new `is_named_in_tree_rch_target()` helper that whitelists the four bare rch patterns added above, letting the age fast-track apply to in-tree project mounts as well. The open-file check in the executor remains the real safety net for in-flight builds.

### Tests

- Adds 7 tests covering the new behavior end-to-end: classification of all 4 bare variants, pattern-label grouping, fast-track under Red pressure outside `/tmp`, no fast-track below Orange, and the negative case (a generic `target-suffix` match in-tree must NOT fast-track).
- Adds a static changelog coverage test for the macOS examples above so future release-note edits keep the concrete Xcode, Time Machine, Electron-cache, release-work, documentation, and Full Disk Access operator details.

---

## [v0.4.6] -- 2026-05-02 **[release]**

Tag: [`v0.4.6`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.6) | Compare: [`v0.4.5...v0.4.6`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.5...v0.4.6)

Fresh-eyes review of the v0.4.5 incident-fix commit caught two bugs:

### Daemon

- **Fix wrong remediation command in `[SBH-CONFIG-WARNING]` text**. The v0.4.5 message instructed operators to "Run `sbh service install`" — but no such subcommand exists. The actual command is `sudo sbh install --systemd --auto`. Anyone hitting the warning would have been sent on a wild goose chase. Updated to reference the real subcommand for both system- and user-scope installs.

### Tests

- **`deletion_report_tracks_not_writable_paths` skips when running as root**. POSIX `access(W_OK)` always succeeds for root regardless of mode bits, so `chmod 555` doesn't actually deny write — the assertion `report.items_skipped == 1` would fail. CI runs as non-root so the test still exercises the path; on root-owned shells it skips cleanly.

---

## [v0.4.5] -- 2026-04-30 **[release]**

Tag: [`v0.4.5`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.5) | Compare: [`v0.4.4...v0.4.5`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.4...v0.4.5)

Three independent bugs combined to let `ts1` (a 1.9 TB build host) silently hit 100% disk on 2026-04-30. SBH's daemon was running, scanning, and finding candidates — but every delete was failing with `NotWritable`, the scanner was timing out before enumerating the giant directories, the dampener refused to retry recently-deleted paths even as pressure climbed, and pressure tracking missed the root mount entirely. This release fixes all four root causes, surfaces the misconfiguration as an actionable warning, and ships safer defaults.

### Daemon

- **Surface `NotWritable` skips as a single actionable `[SBH-CONFIG-WARNING]`** instead of one log line per candidate. When the systemd unit's `ProtectSystem=strict` + `ReadWritePaths=` whitelist excludes a scanner root, every delete fails silently. The warning is rate-limited to once per hour per executor and includes concrete remediation (re-run `sudo sbh install --systemd --auto` or strip `ProtectSystem=strict`). Adds `not_writable_paths` to `DeletionReport`.
- **Repeat-deletion dampener now also bypasses on imminent danger** (urgency ≥ 0.85), not just at Red pressure. On TBs of disk under high build throughput, free space can drop from Yellow (14% free) to Critical (~0%) in a single poll interval, skipping Red entirely. The predictive controller's high-urgency signal now triggers the bypass — the dampener no longer sits idle while disk fills.
- **`check_pressure()` always includes `/` alongside configured `scanner.root_paths`**. When a user configured `root_paths = ["/tmp", "/data/tmp", "/data/projects"]`, the daemon stopped monitoring `/` directly. If those subdirs don't drive pressure (e.g. `/tmp` is tmpfs), the root mount could fill silently. Per-mount dedup makes this free when `/` is already implied.

### Scanner

- **Default `scan_time_budget_secs` raised from 300 → 900**. On agent-swarm hosts, `/data/tmp` can hold 10K–48K stale test artifacts (frankenlibc/fr_live_oracle fixtures, beads_mem temp DBs, etc). 300s let the scanner enumerate ~3% of such directories before aborting, so the actual disk hogs were never identified as candidates.

### Installer / Service

- **`default_read_write_paths` now probes for `/data` and `/data/tmp`** (only adds them if the directory exists, so unit doesn't break on hosts without `/data`). Universal on the agent-fleet machines this tool was built for.
- Auto-detect release asset format (raw binary vs tar.xz) so the installer works regardless of how the release was packaged ([`9a5782a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9a5782adeb50cbe268863e6076e92dd753f6db07))

### Tests

- Two new dampener tests: `repeat_dampening_high_urgency_bypasses_at_yellow` (regression) and `repeat_dampening_low_urgency_at_yellow_still_dampens` (sanity).
- New `deletion_report_tracks_not_writable_paths` test verifies the new bucket on Unix hosts (uses `chmod 555` on a tempdir parent).

---

## [v0.4.4] -- 2026-04-18 **[release]**

Tag: [`v0.4.4`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.4) | Compare: [`v0.4.3...v0.4.4`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.3...v0.4.4)

### Installer

- systemd's ignore-error prefix (`ExecStart=-/usr/local/bin/sbh`) is parsed to the binary path, and the user-scope error path reports correctly ([`7225f38`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7225f38e3fdcdc70cd3ecb3b695f72c7df1073a8)).
- After a `--user` install, a system unit whose `ExecStart` points at a different binary is detected and synced, since most fleet machines run the system unit at `/usr/local/bin/sbh`; adds a rustfmt pre-commit hook ([`9a446b9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9a446b90e512c002b69b98184ce82a7e0837326b)).

---

## [v0.4.3] -- 2026-04-16 **[release]**

Tag: [`v0.4.3`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.3) | Compare: [`v0.4.2...v0.4.3`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.2...v0.4.3)

### Scanner

- Structural rescue uses graduated confidence: 0.75 with three or more cargo markers (`.fingerprint`, `deps`, `incremental`, `build`) versus 0.55 for fewer, and `.rch-target-` is a recognized pattern ([`6323bd8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6323bd8deb709bf719b2c1909a1832d861c636ae)).
- `cmd_result_to_artifact` is gated behind the `tui` feature ([`0e3506b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0e3506b0ce0743173bd431501398ab0496d4027f)); the alternate `target-local/` cargo target directory is ignored ([`a99cfd6`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a99cfd61720fc0ad5d8b6db7e29b3fc8c08f5ddb)).

---

## [v0.4.2] -- 2026-04-07 **[release]**

Tag: [`v0.4.2`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.2) | Compare: [`v0.4.1...v0.4.2`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.4.1...v0.4.2)

First published release after the v0.3.x series; v0.4.0 and v0.4.1 were tagged only.

- `x86_64-apple-darwin` builds on `macos-13` (Intel), since `macos-latest` became ARM64; `fail-fast: false` so one target's failure no longer cancels the others ([`e50bac0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e50bac0324840e9bf38d49cfc6ea46a563617d23)).

---

## [v0.3.17] -- 2026-04-01 **[release]**

Tag: [`v0.3.17`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.3.17) | Compare: [`v0.3.16...v0.3.17`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.3.16...v0.3.17)

### Installer

- The installer hardcoded `.tar.xz`, but v0.2.8+ shipped raw binaries. It now probes the GitHub API for the actual asset format, handles both, and falls back to `cargo install` when no artifacts exist (closes #8) ([`9a5782a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9a5782adeb50cbe268863e6076e92dd753f6db07)).
- The `SHA256SUMS.txt` lookup matches the asset name as an exact field so `sbh-linux-x86_64` cannot match `sbh-linux-x86_64-musl` ([`0367ca3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0367ca3a89d20b75e9995ecd8afa755aee8135fc)).
- The nightly toolchain is unpinned to rolling latest for this verification release ([`2e7d05c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2e7d05c10da781baccc8b088862abcdff4683743)).

---

## [v0.3.16] -- 2026-03-15

Tag: [`v0.3.16`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.3.16) | Compare: [`v0.3.15...v0.3.16`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.3.15...v0.3.16)

This tag has no corresponding GitHub Release. It decouples the CI release pipeline from the quality gate so releases are no longer blocked by unrelated gate failures.

### CI / Build

- Decouple release builds from quality gate ([`44f26a4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/44f26a40792268ad6e40148bd5d36a90fc7968c9))
- Bump version to 0.3.16 for release ([`0d85778`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0d8577845bb2bb69ee2de8c23d3343123b6b544d))

---

## [v0.3.15] -- 2026-03-12

Tag: [`v0.3.15`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.3.15) | Compare: [`v0.2.8...v0.3.15`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.8...v0.3.15)

This tag has no corresponding GitHub Release. It covers all development from v0.2.8 through v0.3.15 -- a rapid series of production-tuning point releases (v0.3.0 through v0.3.15) that were not individually published. Version numbers v0.3.6 and v0.3.9 were skipped. The intermediate version bumps are noted in subsection headers below.

### Prediction Engine (v0.3.0)

- **Burst detection in EWMA rate estimator**: two-factor burst detection (rate acceleration + magnitude) prevents the predictor from extrapolating transient spikes into false exhaustion forecasts ([`6516579`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6516579b58ce5496e72a1aea0b390840b56c0b06), [`e00c4e3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e00c4e3ee36cd757c148a316d8dff1399b97425e))
- **Prediction scorecard**: tracks prediction accuracy over time, solving the self-defeating prophecy problem where successful interventions make the predictor look wrong ([`c0dcc23`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c0dcc239a14e36a6d82f3b20be81fb96037303c1))
- **Burst-aware prediction gating**: predictions during detected bursts are suppressed or confidence-degraded ([`392a250`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/392a250ce0c4b9e2c08b96b45bc4fbf276719b8d))
- Move `burst_min_confidence` to `PredictionConfig` for cleaner configuration hierarchy ([`061e33d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/061e33dba15ca2203a284c153d97160a29a6c82e))
- Make `CalibrationBreach` advisory-only, lower escalation threshold to Yellow ([`7f121e5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7f121e50493d5d86342338ef3ee1d4a1a3b76ec9))
- Exclude TUI feature from CI/release builds and enable `workflow_call` ([`61efc64`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/61efc6425268ef5ec66aae9099266403eddb885e))

### Production Stability (v0.3.1)

- **False-alarm suppression**: daemon no longer fires notifications or escalates policy during genuinely idle periods ([`120a5b9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/120a5b9555a5d49aa14f64586575decb59917fc7))
- Scan timeout tracking and circuit breaker backoff log ordering fix ([`55857bf`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/55857bf9a1c3c1fdd02337c38b1ffc034faec6c1))
- Operational improvements for scan efficiency ([`57e8bf5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/57e8bf54785dc19359a2993842b16784871b88db))
- Add missing `reason` field in predictive policy and fix boundary condition ([`4f18448`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/4f1844899e3b9015f04cf6b8a7d5fe2309460c0c))
- Regression test for green-pressure fallback recovery ([`194fce3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/194fce30555d56469476388f092f4bee8835362c))

### Calibration Guard Hardening (v0.3.2)

- Suppress calibration breach log spam and guard trigger deadlock ([`161ac4a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/161ac4a102ffd6b595974b87151f13dd795645de))

### Predictive Warning Gates (v0.3.3)

Five incremental fixes to prevent the predictive warning system from triggering false alarms on healthy disks:

- Implied-rate sanity gate + breach log suppression ([`b35eabc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b35eabcd135da3a39534c0928e2cd9d4c3418094))
- Hard gate for predictions showing >50% free space ([`9cc27a1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9cc27a1f551732579714bdc4585d333a8a43a44d))
- Persist `recalibration_count` across clean windows ([`e07c6d4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e07c6d4f98e1553bfcf8e793371d2fdb717fe63c))
- Move hard gate before burst-aware path ([`5c2553d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5c2553d7836f6b145b9efbfe3cbb1c42bf891e55))
- Gate `check_predictive_warning` on predictive policy result ([`a052990`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a052990a42a1ceb9c0703ff0a5da9f0f46e30be6))

### Burst Detection + Guard (v0.3.4)

- **MAD-based burst detection**: uses Median Absolute Deviation instead of standard deviation for robust outlier identification ([`ded16b5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ded16b561b86abd8aefb7b157add63d1a488ecb4))
- Burst-aware guard with median-rate cross-check to prevent false guard triggers during legitimate activity spikes

### Decision-Theoretic Guard (v0.3.5)

- **Multi-level PressureLevel enum**: replaces boolean `pressure_is_green` with Green/Yellow/Orange/Red/Critical levels for fine-grained policy scaling ([`7e5dfe2`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7e5dfe2a2f8dd27fdbc23b63035f622c28be5eca))
- Decision-theoretic guard override breaks policy rejection deadlock where the guard penalty prevents all deletions even under rising pressure ([`647c574`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/647c574e7388595755eb5cc779ee4b56bd9ec869))
- Rate-limit guard observations to prevent high-frequency tick flooding ([`00e2f78`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/00e2f78a33d2a68093ae13854c150e57d3f85209))

### Yellow Pressure Fixes (v0.3.7 / v0.3.8)

- Fix Yellow-pressure rejection deadlock and suppress Green false alarms ([`d969599`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d96959981dbcf15edad91fcb8bf9f3dc2246aeb4))
- Extend prediction and guard-trigger suppression to Yellow pressure ([`dce72c6`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/dce72c625e812bb5ecf64209dae6cf1b0ec7d304))
- Reduce guard penalty deadlock at Yellow pressure and suppress false alarm notifications ([`a00c77b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a00c77ba66138c6e73c7e0d339bdba8d5a79e86b))
- Tune guard penalty scaling, suppress Green-pressure predictions, reduce log noise ([`97df2d0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/97df2d020aaa366458f271afaa95f76bfad1c125))

### Calibration + Diagnostics (v0.3.10 -- v0.3.12)

- **Directional calibration guard**: only triggers on predictions in the dangerous direction, ignoring benign miscalibrations ([`0e150dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0e150ddc5770715ae2989722941f4bcbe0b6a0f2))
- Widen idle noise threshold and bound `rate_danger_ratio` denominator to prevent division-by-near-zero ([`17bc885`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/17bc88598f0606fa0aa61e18541b6c550bc450bc))
- Double `min_observations` to 60 and fix scanner candidate count reporting ([`a188332`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a1883327a823467b512503780698c5822f8d841b))
- Reduce log noise and improve e-process penalty scaling ([`181518d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/181518da26887575f5631be271977d134d8d19c8))

### Scanner Hardening (v0.3.13 -- v0.3.15)

- Suppress `HOME`-not-set warning under systemd where `$HOME` may be unset ([`33a973a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/33a973a2e6d7b45455f9beb638bf947b870b5175))
- **Scanner never treats git project roots as deletion candidates**: directories containing `.git` are unconditionally protected regardless of scoring ([`bc15173`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bc1517363c276879ec65a9399bf7dae7ebbec919))
- Add Claude session cache pattern (`~/.claude/`) and improve deletion diagnostics ([`582f365`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/582f3658a4eff7c0ccc6e41c4a8068296bd5c3dd))
- **Depth-3 artifact scanning**: walker descends up to 3 levels into directories for pattern matching with breakdown logging ([`ea8e5c0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ea8e5c00d6c7039478a679a5367f3567449cc6d3))
- Optimize git directory detection cache and suppress cross-platform dead-code warnings ([`75b3716`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/75b3716fe7b27f6cb3b20aa205d8dfd07c0c3698))
- **Heartbeat, cancellation, and backpressure in directory walker**: prevents unbounded memory growth during large scans and allows clean daemon shutdown ([`9c3ba84`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9c3ba84508d090dc2388faa379a2058180fba8cc))

---

## [v0.2.8] -- 2026-03-01 **[release]**

Tag: [`v0.2.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.2.8) | Compare: [`v0.2.1...v0.2.8`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.1...v0.2.8)

Critical production fix release. The daemon was becoming non-functional on most deployed machines due to a cascade of safety mechanisms triggering during green pressure (plenty of free disk space), which paradoxically blocked cleanup when pressure eventually rose.

Version numbers v0.2.2 through v0.2.7 were skipped; development proceeded directly from v0.2.1 to v0.2.8.

### Policy Engine

- **Green-pressure suppression**: guard-triggered FallbackSafe entries suppressed when disk pressure is green -- miscalibrated predictions are harmless when no deletions would occur ([`474f700`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/474f7009694c7c33dc25b47bed9a820c74174e4b))
- **FallbackSafe deadlock broken**: emergency escalation to Enforce mode with grace period when FallbackSafe has persisted too long under sustained pressure ([`8ddddb0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/8ddddb07651a40f70b930cbe3c54a85afebeaecf), [`103957e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/103957eb843c3ad61caa2c8f40103880f53446a3), [`006ef34`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/006ef342f947b35bb6baacc7c94ff750a9ff1727))
- **Anti-thrash cooldown**: rapid mode oscillation (canary/FallbackSafe) dampened with minimum dwell times ([`82f9d9d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/82f9d9d122ec4a00d8b4b4bf566d4949cc946a2d))
- Canary budget exhaustion pauses deletions until next hour instead of locking down the entire engine ([`82f9d9d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/82f9d9d122ec4a00d8b4b4bf566d4949cc946a2d))

### Scanner + Patterns

- Recognize `rch_target_*`, `rch-target-*`, and `target_codex*` build artifact directories from remote compilation and Codex agents ([`bf03a78`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bf03a782c1ca681ce8cf775989366e5685a5f2f1))
- Add `/data/tmp` and `/var/tmp` to default scan root paths ([`1f706dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/1f706dd324809a6baca54a7ebe28ffcf2ae41aeb))
- Configurable `scan_time_budget_secs` (default doubled from 60s to 120s) ([`1f706dd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/1f706dd324809a6baca54a7ebe28ffcf2ae41aeb))

### Daemon

- **Zram false-positive fix**: high zram usage with plenty of free RAM is normal compressed-memory behavior, not disk thrashing ([`9b81294`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9b81294b8213f772574eca7fc2ca45a7c5f0e66f))
- Correct swap thrash detection inversion and add prediction jitter confidence tracking ([`7999715`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7999715a91de716a612b529232af539470615cb2))
- Cap predictive warning severity by confidence level -- 1% confidence no longer triggers CRIT ([`3130ce1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3130ce1cf3d843210a400baf4626ecd20f38ae86))
- Rate-limit scanner saturation messages to once per 60 seconds ([`9b81294`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9b81294b8213f772574eca7fc2ca45a7c5f0e66f))

### CLI

- **`sbh log` subcommand**: read and tail the JSONL event log with `--follow` and `--type` filtering ([`9e46a58`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e46a586aadf5cca5c2d15e19e0fd0870c9ce616))
- Cross-user daemon detection via systemd/process scan when config paths differ between root daemon and non-root CLI user ([`9e46a58`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e46a586aadf5cca5c2d15e19e0fd0870c9ce616))

### Platform + Service Management

- Gate `--systemd`/`--launchd` by platform before ballast provisioning ([`c49ec5d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c49ec5d81dbca1708ece01ca4f55c534cf4a3f72))
- Require root for system-scope systemd with clear guidance ([`14e4596`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/14e45966217579706c6f01f491c92a434c7fe2b2))
- Auto-detect non-root on macOS and use user-scope launchd ([`3615ed5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3615ed5444e435fef2f7b111ef165ed70e17e6e5))
- Use `root:wheel` for chown recommendation on macOS ([`9d37d47`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9d37d47ac5b0e081cf83acd540c03ce9a6d2b076))

### TUI

- TUI gated behind optional feature flag + walker cancellation token ([`97ea033`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/97ea03311dfd57446039a77875770bea08ece7ff))
- Signal interception for TUI terminal session ([`39ea6a0`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/39ea6a046e3345ac511cf3d17bae3840f113c66b))
- Explicit lifetime annotations on TUI styled rendering functions ([`134833c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/134833c2422f217e09e51519941e728da06e588d))
- Switch ftui dependency from local paths to crates.io v0.2.1 ([`f41259c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f41259c86d5c012cb1efc38d9123baab6b6c04f2))

### Licensing

- License updated to MIT with OpenAI/Anthropic Rider ([`658fe36`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/658fe363b81fcde40e3ad8ad4e6799238898aa0c))

---

## [v0.2.1] -- 2026-02-17 **[release]**

Tag: [`v0.2.1`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.2.1) | Compare: [`v0.2.0...v0.2.1`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.0...v0.2.1)

### Predictive Cleanup

- **Predictive cleanup policy**: per-event throttling in the daemon prevents redundant scans ([`fb601b3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fb601b369d11aa1014af3fa8ce451388e4bbe13d))
- Suppress bogus predictions and fix wrong mount path in state/logs ([`28e0c4e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/28e0c4eab8ea56c161e321e5072fc41d86300421))

### TUI

- **TUI rendering overhaul**: enhanced theme, widget styling, and dashboard rendering ([`b5d7794`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b5d77940bce1f19e0519825b388ad4619859bf3e))

### Agent Integration

- Agent skill definition (`.claude/skills/sbh`) for AI agent integration ([`ddd5045`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ddd5045c5f4838e0982443f8637db33108a73f35))

### Bug Fixes

- Resolve clippy lints, compilation errors, and swap-thrash logic bug ([`fde0f2b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fde0f2bc7120c9118bd55569355938ad84328616))

### Tests

- Merkle index integration and symlink loop reproduction tests ([`a7eefac`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a7eefac4c8c320ddddcc68ee854a4df6b8b1bfe6))

---

## [v0.2.0] -- 2026-02-16 **[release]**

Tag: [`v0.2.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.2.0) | Compare: [`v0.1.0...v0.2.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.1.0...v0.2.0)

Massive release adding the interactive TUI dashboard, extensive hardening from deep code audits, cross-platform fixes, and a full test suite overhaul. 170+ commits between v0.1.0 and v0.2.0.

### TUI Dashboard

- **Full interactive TUI** with 7 screens: Overview cockpit, Timeline, Explainability, Scan Candidates, Ballast Operations, LogSearch, and Diagnostics ([`429c1a3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/429c1a3de91a45015602ee997c18f2ee90c1ceee), [`dd8a8c1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/dd8a8c1d57a3529723b89c5cb7f8e8628a5257e1), [`40a219d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/40a219d6876e41d2e6885772a2193caaa1cc7dca), [`f1b7dfc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f1b7dfc3b38bc3aec561476d7df0c29456ad914d), [`054ed6a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/054ed6ad5fd33faae94f7cb833c759f7b0198a7a))
- TUI compiled unconditionally at the time; it then became the optional `tui` cargo feature, off by default, and since 2026-09 (bd-rc-master-ajg1.4.7) `tui` is in the default feature set again ([`25388e8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/25388e80cc4de24ec24ca43629695ff5bf123aaf))
- Migrated from crossterm to ftui with layout engine, theme system, and rich overview rendering ([`4cc1010`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/4cc1010e1fb7513c71f20bcfc295270bc4665c14))
- Panic-safe terminal guard prevents TUI crashes from corrupting the terminal ([`c0d305a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c0d305adf6a52358f08418ae38dcd1a2b7c142dd))
- Frame-based rendering pipeline ([`0d0b5d2`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0d0b5d2c3ee2f147c6ab9f8068d42e9733c4b3f8))
- Guard against zero-width terminal panics ([`b9f118d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b9f118dbd5f1f7790876f1e90a2e9f37f5f10576))
- Synthesize ballast volumes from daemon state for inventory display ([`daeac2c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/daeac2c4f795e3378b61fd9506e180f657554b3d))
- Interactive pane navigation with mouse support ([`429c1a3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/429c1a3de91a45015602ee997c18f2ee90c1ceee))
- Schema-shielding layer for dashboard data models ([`373803c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/373803c933ef097c51343744c8e105b724795502))
- User preferences model for dashboard ([`bf54cf8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bf54cf8905f7fdc90e8cc718b221d259125b3716))
- Incident workflow shortcuts with playbook overlay ([`167d46c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/167d46c78bda169e739054d9aaa819ddf5d9863f))
- Responsive layout builders for all dashboard screens ([`2de84f3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2de84f325205eee5956afbe6f5a8f5233659e60c))
- Command palette and breadcrumb rendering ([`c4a41e4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c4a41e4abb81eb5ae02503b14c527560b1fd8d04))

### Scanner + Scoring

- **Production 0-deletion bug fixed**: rebalanced Bayesian decision thresholds that caused no deletions across the entire fleet ([`d6bbd81`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d6bbd814f8c4c47ed66e916b481f34d15d5914b6), [`e5987f9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e5987f909fb8d4172c33614bcbfb4b16c55bbc0f))
- **Queue starvation fix**: 15K entries/0.5s vs 17/60s ([`3bb9232`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3bb9232de1a3cb7cf848589abf54ca0bae32d573))
- Cap per-dir iteration at 2000 entries + deferred child dispatch ([`fd1e197`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fd1e19799bdad38805d36d4f471394a20949e32c))
- Parallelize `/proc` scan, optimize walker hot path ([`96ed3da`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/96ed3dad9c0d814f53b5d74d422835c509c2db5c))
- Reorder location checks so `.tmp_` and `.target` match before generic `/target` ([`f2b0b7d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f2b0b7d9488b67651bac02b8009cb882d7567c3d))
- Consolidate and simplify builtin artifact patterns ([`5e93e15`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5e93e158b81abe3eb974b95a6febc62c0d03d069))
- Case-insensitive pattern matching ([`9e789f3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e789f37f44b086b27bba5651c4a8d9eca487175))
- Defer open-file checks to post-scoring for faster scan startup ([`dd2ccc2`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/dd2ccc2ff9c00e856d25aa9acee712a5c515a445))
- Populate per-root scan duration for VOI scheduler IO cost ([`ae6808d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ae6808dda8b1f0283922644c6252b68ef4c3847d))
- Improve pattern confidence scores and predictive warning escalation ([`db2acc4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/db2acc44022225ed3e1534237eec6e536c572028))
- Memory/swap diagnostics and expanded artifact detection patterns ([`139a70d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/139a70d07a6a9260dd9b4c97364a92a1424edc27))

### Daemon + Policy Engine

- **Scanner deadlock resolved** that caused 0 scans on all production machines ([`7d87a75`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7d87a75620eb204de17ce5302209d2bffd0ac120))
- Per-mount release tracking, incremental release logic, and project-root protection ([`ea36631`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ea36631b07a312aff3d4aac5ff614e96893ea1d5))
- Gradual ballast replenishment and cumulative release targets ([`2b1309e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2b1309e9d79dd44e7693a81514a5a7c6a10ba91c))
- Repeat-deletion dampening to break agent rebuild loops ([`ffb7fdf`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ffb7fdf2f3a926c17c3b31ea89b491f1346cae64))
- Swap-thrash detection and temp artifact fast-track deletion under pressure ([`301543e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/301543e07ea7ec56452c58ca3cd1b93b9c47a9b0))
- PID slow-decay hysteresis steps one level at a time instead of jumping to raw ([`e3b8087`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e3b8087654026cf7b0446b45fb4fe6aad20ca0cc))
- Propagate `poll_interval`, prediction disable, and notification config on SIGHUP reload ([`f6124d8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f6124d8812a12bcbea30440628a1c99c8dcdc20d))
- Trigger root filesystem scan on special location pressure ([`fd683b3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fd683b30f4fad79e4be4d5a4642e51f26064e356))
- Production reclaim failure resolved ([`c289bca`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c289bcafbc55650f55d263ea28157621a06f6247))
- Constructor sets correct `pre_fallback_mode` and `fallback_reason` for kill_switch ([`fbd3070`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fbd30704d8fce980aadfdff040e7297516f9851f))

### Security + Hardening

- Hyphen injection guard, ancestor-set open-file detection, composite index ([`5e0a2db`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5e0a2dbd15fef1027b5a0812ca3f3aacb9721f80))
- Security hardening: ballast release rework, walker streaming, idiomatic Rust modernization ([`745d119`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/745d1192874d95946b2c5a30abf1f60f20721cd7))
- Multi-volume ballast, inode-based open-file detection, Cow allocation reduction ([`31b165c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/31b165cf3628cfdec3764f8b1350a495843ef90a))
- Correct `glob_to_regex` for `**/` pattern boundary matching ([`817028c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/817028c2bda2b5c7b686f708f266868c97ebd40d))
- VOI config extraction, decision record `effective_action` ([`9e789f3`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/9e789f37f44b086b27bba5651c4a8d9eca487175))
- Design-level hardening from deep audit: notification throttling, atomic config writes, PID derivative low-pass filter ([`c67fc37`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c67fc37aa0a9eaec42516b43b4765571211b0cb1))
- Handle JSONC block comments in root-brace parser ([`e39e9d1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e39e9d1ba1f6d39f05e9def65c3967cb420de0d7))

### CLI

- Cap help text width at 100 columns ([`a18b8fd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a18b8fd1f565cf44d816fa16788259d86d1383fb))
- Cosign v2 identity flags + `is_writable` parent dir check ([`4ca87af`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/4ca87afb3019aa57dd5521c9ea9cbc48f6697835))
- Implement actual curl-based asset download and robust build-dir creation ([`14f0afc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/14f0afc2176b58e19329232d33638a7f90f1e982))
- 6 bugs from deep audit: mount check, zombies, template, deprecated keys, `bytes_freed`, writable ([`0306e6b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0306e6bb87f73d9ff8bf05221c8b132126052a33))

### Logging

- Circuit-breaker logic improvements and rotation resilience ([`80708cd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/80708cd945eb9fe65adf667b44b1038a91bb7058))
- Failure-injection test suites for self_monitor and JSONL logger ([`11bfb22`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/11bfb22ad843b3bcb3c2e4e892f57168f19d357d))
- `.tmp_target` pattern, shutdown sentinel, auto_vacuum conversion ([`a50adb8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a50adb85d8cdb86a97f420e887a27c0de295fe90))

### Platform

- Stats module: push pattern extraction into SQLite custom function for server-side aggregation ([`caed1d1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/caed1d1057e0f41fce74978e856945bb483df1cb))
- Backup dir fallback, UTF-8 path truncation, RateHistory div-by-zero fix ([`748283f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/748283f46a199d95d55b8a5ebef19b1dfde7abaf))
- CoW filesystem fallocate bypass + VOI budget=1 fix ([`2e00c1a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2e00c1a8d14942a6d9dcd72f6341a7ed16939e36))

### Tests

Extensive test suite expansion as part of the TUI dashboard rollout:

- 37 snapshot/golden tests for dashboard screens ([`af667b5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/af667b5d5ca7f77a3b75ef84556903b627a89463))
- 44 fallback/rollback verification tests ([`0b44620`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0b4462097b50ef82df5e817fca90a5c5fd30a986))
- 31 integration tests for dashboard CLI and state-file contract ([`f4978e8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f4978e833e2362cd28126321a8ee4fe6dac2d59b))
- 22 unit tests with 10 duplicate test name fixes ([`5343369`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/53433691fe18b72129e34c6b493d34773db03221))
- 8 property tests for scheduler/overlay/history/detail invariants ([`7088195`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/708819583fa0b70dbd02dfd65d4f516795508924))
- Property-based tests for reducer invariants ([`ae3925a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ae3925a89e0c45a145d551210d0c23301ef6252c))
- Stress/performance test suite ([`81557a6`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/81557a66d7e6f854e9e9f4eaf7b1088579cc11d9))
- Deterministic replay regression suite ([`5491318`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/549131863426935ddf18ddf7dc1065901e2aa43e))
- Parity harness covering all 18 contracts ([`43f24ae`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/43f24ae70dcf8e22779d4826b7c8879d241f09b1))
- 9 comprehensive e2e dashboard test cases ([`a3f093a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a3f093abd7a371a6f55d2b33b7c045f5fc4b57cc))
- Scenario-driven dashboard e2e drills ([`ef0c42d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/ef0c42d4c43c03572038cfc582e9b44abecccd46))
- Operator workflow benchmark validation ([`0ade1bf`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0ade1bf135e9e24dd8221ede8f3cf1932e5f4862))

---

## [v0.1.0] -- 2026-02-15 **[release]**

Tag: [`v0.1.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.1.0) | Compare: [`91a5e28...v0.1.0`](https://github.com/Dicklesworthstone/storage_ballast_helper/compare/91a5e28...v0.1.0)

Initial release of Storage Ballast Helper -- a cross-platform disk-pressure defense system for AI coding workloads. 60+ commits from repository initialization to first tagged release.

### Core Monitoring

- **Continuous disk pressure monitoring** with EWMA forecasting and PID controller
- **Three-pronged defense**: ballast file pools, artifact scanner, special location monitor
- **Predictive cleanup** with configurable confidence thresholds
- Self-monitoring with health integration ([`76ae80c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/76ae80c186af5117db6b29e69f60138f1f041a0c))

### Scoring + Safety

- **Multi-factor scoring engine** for safe artifact cleanup with deterministic ranking
- **Decision-plane policy engine** with shadow/canary/enforce modes and evidence ledger ([`52a0877`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/52a087791b4eb606bfcc132fa80e4eb86c9f24c0))
- **Hard safety vetoes**: `.git` directories, protected paths, too-recent files, open files
- Canonicalize paths in protect/unprotect to prevent symlink traversal ([`b4e9412`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b4e9412060c70c3a06eab47e92107a8c8f14e80b))
- Guard ballast size calculation against integer overflow ([`5ef86fe`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5ef86fe03eb424e1dd2af5c944c53fcafabd28cd))
- 0o600 permissions on ballast files, log files, state files, merkle checkpoints ([`b7ebeb4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/b7ebeb4eb7b2499dd6c2e96e15daf0ac30a6ba5e), [`848211d`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/848211d80e3adf5a7dae8dcdb4ebd26eaab58ac8), [`49a01f8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/49a01f8badf1e4e118e5af04a7a5994156e1e3ee), [`fe765c9`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/fe765c98a7ecda457eb18e5d5b7f1cc4afb3f316))
- Reject ballast `file_size_bytes` below 4096-byte header size ([`07654a4`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/07654a4a7ff1e165d7da08dcde4e52d3e2ffdc42))
- Validate protected_paths glob patterns at config load time ([`6d9813e`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6d9813e8c3bc33c3373bf86a5dce57f1d4bd4d87))

### CLI Commands

- `sbh check` -- inspect pressure and forecast
- `sbh scan` -- run cleanup scan and review candidates
- `sbh clean` -- execute safe cleanup with confirmation
- `sbh emergency` -- zero-write emergency recovery mode
- `sbh ballast provision` / `release` / `replenish` / `verify` -- per-volume ballast management
- `sbh protect` / `unprotect` -- project protection via `.sbh-protect` markers
- `sbh explain` -- show decision evidence and rationale
- `sbh stats` -- storage trend statistics
- `sbh blame` -- identify top space consumers
- `sbh dashboard` -- text-mode dashboard with pressure gauges and sparklines ([`c5992fc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c5992fc4e56efe0a3bf73a3b09e448b40dc8eb90))
- `sbh install` / `uninstall` -- systemd/launchd service integration
- `sbh setup` / `bootstrap` -- migration self-healing and VOI scan scheduler ([`d4da084`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d4da08410c3bb038537ec3466b93d47d4a317b2d))
- `sbh tune` -- tuning recommendations
- `sbh update` -- sigstore bundle verification and install/update with backup/rollback/prune ([`7f57b7f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/7f57b7fa63e012027137b334b2c43ba9e5c705f9), [`6c81f3a`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/6c81f3ace37b1f90118c423b85d8c061edc5713d))
- Asset management and from-source build modules ([`0560d66`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/0560d66de886aae15b22f88eedd7a9b890829dc2))
- Deterministic offline bundle builder with strict path-safety guards ([`e00b892`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e00b89253c6df5c6cdee753612026b1ab97bcbca))

### Daemon

- Systemd and launchd service manager integration ([`62ba3e1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/62ba3e183d0e8e9617afee1f64d429db424a0ab0))
- Coordinator for scan/cleanup/ballast orchestration ([`5f0176b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/5f0176b8405cafc86c92b80d6db8ba31c2d171bd))
- Worker reporting, shared config, rendezvous channels ([`32d1fae`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/32d1fae41b2dafe76a6c2b7ed4b54281dfbe7e9b))
- Stale daemon detection, early ballast release, recursive inode scanning, predictive target floor ([`83603d7`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/83603d7be423aa3e5f17c7df1100dc5cf5fa182e))
- Poll interval validation, prediction bounds, monotonic heartbeat ([`c5e53d5`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/c5e53d57fc2c6f6b8f398d8c8c103a4cb3c69c4e))

### Observability

- Dual logging: SQLite + JSONL with full explainability
- Decision records with traceable evidence and rationale
- SQLite recovery mechanism and new activity event types ([`af00f9b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/af00f9bd8f74da3a9fd8a1b3e7cd37cc4fbdaa99))
- Dropped log event surfacing in state.json ([`98891e8`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/98891e81d3cfa90a9379099bad3e5a2f3ce5d03e))

### Platform Abstraction

- macOS `statvfs` type mismatch fix for cross-platform builds ([`e78e3a1`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/e78e3a1cfaa62895a904eca82970c9e848cf8a43))
- Parse meminfo unit suffix instead of assuming kB ([`085238b`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/085238b68ee469a8f299e4b711b6e88856baac77))
- Decode all octal escape sequences in mount paths ([`0156847`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/01568478042c67c655d51e01fb37e11e59c256e6))
- Windows PowerShell installer ([`3bcd099`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3bcd099c26d15956206b12ffd032f7fb933d6b48))

### Build + Safety Constraints

- `#![forbid(unsafe_code)]` in both `lib.rs` and `main.rs`
- No async runtime -- OS threads with `crossbeam-channel` and `parking_lot`
- Pedantic + nursery Clippy lints enabled project-wide
- Deterministic builds: `opt-level = "z"`, LTO, `codegen-units = 1`, `panic = "abort"`, stripped
- Linux x86_64 and macOS arm64 release artifacts

### Tests

- Decision-plane proof harness with 26 tests ([`a3eaade`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/a3eaadee8d494c3b257ef8562bb1f3b0d582ca05))
- Full-pipeline integration tests ([`972ab33`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/972ab33bbe2a26109bcef01bcc9041466203869e))
- 105 unit tests across 5 installer/CLI modules ([`2c94431`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/2c9443161987a5676e8e9ccaf5b693a7f4d6e3c4))
- 8 extreme-pressure stress scenarios ([`f38b96f`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/f38b96f01001c0e93c473c3f4d2b1cb8b0b07cc7))
- Comprehensive E2E test suite ([`85f96ea`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/85f96eaa0a4a997346821ba860acfc956e4a8c6a))
- Deep code audit fixes across scoring, deletion, PID, EWMA, PAL, bootstrap, guardrails ([`822e5ce`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/822e5ce4d01f8e21e44d2e3e5b7d86ebdeefbd0a), [`aeb873c`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/aeb873c5316329e80bfb7114f31abc62f9509957))

### Repository Initialization

- Repository scaffold and source modules ([`91a5e28`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/91a5e28f315d9869b37add11caeaa9ab27cd64f7))
- Core CLI commands and scanner subsystems ([`61332bc`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/61332bc4ba1a2edd8d3b2149b6c3c713bf091dc0))
- Merkle scan index ([`3bcd099`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/3bcd099c26d15956206b12ffd032f7fb933d6b48))
- VOI scan scheduler ([`d4da084`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/d4da08410c3bb038537ec3466b93d47d4a317b2d))
- Uninstall with safe cleanup modes ([`bf36edd`](https://github.com/Dicklesworthstone/storage_ballast_helper/commit/bf36eddf073a2d2fc869031796494c50097288fb))

---

## Statistics

| Metric | Value |
|--------|-------|
| Total commits | 904 (as of 2026-09-02) |
| Tags | 51 (v0.1.0 through v0.5.1) |
| GitHub Releases with assets | 28, each marked **[release]** above (`scripts/changelog_check.sh --all` audits this) |
| GitHub Releases without assets | 1 (v0.4.23) |
| Tags without GitHub Releases | 22 (v0.3.15, v0.3.16, v0.3.18, v0.3.19, v0.4.0, v0.4.1, v0.4.7, v0.4.9--v0.4.13, v0.4.15--v0.4.21, v0.4.26, v0.4.34, v0.4.35) |
| Development period | 2026-02-14 to present |
| Intermediate point releases (in-tree only) | v0.3.0 through v0.3.14; v0.4.31 |
| Skipped version numbers | v0.2.2--v0.2.7, v0.3.6, v0.3.9 |

[v0.3.16]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.3.15...v0.3.16
[v0.3.15]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.8...v0.3.15
[v0.2.8]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.1...v0.2.8
[v0.2.1]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/Dicklesworthstone/storage_ballast_helper/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.1.0
