# Sacred Paths

`sbh` treats some paths as non-reclaimable user or project state, even when
they appear inside a directory that otherwise looks disposable. These rules are
more important than cleanup score, pressure level, or reclaim target.

This document explains the built-in sacred path catalogs and the reasoning
behind each family of protected patterns.

## Enforcement Model

Sacred path checks are hard safety gates:

| Kind | Meaning | Example |
| --- | --- | --- |
| `ExactMatch` | The named path is protected exactly. | `~/.ssh` |
| `GlobMatch` | Paths matching the shell-style glob are protected. | `~/Pictures/*.photoslibrary` |
| `ContainsAny` | Any cleanup candidate containing this descendant is blocked. | `.git/` inside an old buildroot |
| `StowawayMarker` | Any cleanup candidate containing this file name or glob is blocked. | `*.sqlite3`, `beads.db-wal` |
| Marker | Any directory containing `.sbh-protect` protects itself and descendants. | `sbh protect /data/projects/app` |

When a candidate overlaps a sacred path, `sbh` classifies the relationship as:

| Relationship | Meaning |
| --- | --- |
| Exact sacred path | The candidate is the sacred path. |
| Inside sacred path | The candidate is a child of a sacred path. |
| Contains sacred path | The candidate is a parent that would delete a sacred child. |
| Contains sacred marker | A stowaway scan found protected state inside the candidate. |

Destructive cleanup rules must pass parent checks and sacred-overlap checks.
User-configured `scanner.protected_paths` are converted into sacred paths at
runtime, and `.sbh-protect` markers are discovered during scans and direct
daemon preflight checks.

## Cross-Platform Built-ins

These rules are embedded in `src/platform/sacred.toml`.

| Pattern | Kind | Why it is sacred |
| --- | --- | --- |
| `.git/` | `ContainsAny` | Git metadata is source history, branch state, refs, hooks, and in-progress work. A buildroot or trash-like directory containing `.git/` is not disposable until a human confirms it. |
| `.beads/` | `ContainsAny` | Beads state is the issue tracker and agent memory for the project. Losing it breaks coordination and audit history. |
| `beads.db` | `StowawayMarker` | The primary Beads SQLite database is project memory, not cache. |
| `beads.db-wal` | `StowawayMarker` | SQLite WAL files contain committed or about-to-be-checkpointed issue data. |
| `beads.db-shm` | `StowawayMarker` | SQLite shared-memory files are part of the live Beads database set. |
| `*.db` | `StowawayMarker` | Database files commonly contain application state, test fixtures, local indexes, or operator records. |
| `*.db-wal` | `StowawayMarker` | WAL sidecars are database state and must be kept with the database. |
| `*.db-shm` | `StowawayMarker` | Shared-memory sidecars are database state and must be kept with the database. |
| `*.sqlite` | `StowawayMarker` | SQLite files are often durable project or application state. |
| `*.sqlite-wal` | `StowawayMarker` | SQLite WAL sidecars can contain recent durable writes. |
| `*.sqlite-shm` | `StowawayMarker` | SQLite shared-memory sidecars belong to the active database set. |
| `*.sqlite3` | `StowawayMarker` | SQLite3 files are often durable state and should not be inferred disposable by location alone. |
| `*.sqlite3-wal` | `StowawayMarker` | SQLite3 WAL sidecars can contain recent durable writes. |
| `*.sqlite3-shm` | `StowawayMarker` | SQLite3 shared-memory sidecars belong to the active database set. |
| `~/.ssh` | `ExactMatch` | SSH private keys, host trust, and connection config are security-sensitive user credentials. |
| `~/.ssh/*` | `GlobMatch` | Every file inside the SSH directory inherits that credential risk. |
| `.ssh/` | `ContainsAny` | A nested SSH directory inside an otherwise disposable tree is a high-risk stowaway. |
| `~/.gnupg` | `ExactMatch` | GnuPG keyrings, trust databases, and agent state are security-sensitive credentials. |
| `~/.gnupg/*` | `GlobMatch` | GnuPG children include keys, trustdb files, revocation certs, and private configuration. |
| `.gnupg/` | `ContainsAny` | A nested GnuPG directory inside a cleanup candidate is credential state. |
| `~/.config/age` | `ExactMatch` | age identity files are encryption keys. |
| `~/.config/age/*` | `GlobMatch` | Everything under the age config directory may be needed to decrypt user data. |
| `.config/age/` | `ContainsAny` | A nested age config directory inside a candidate is credential state. |
| `{~,/home/*,/Users/*}/.claude`, `.codex`, `.gemini` | `GlobMatch` | Agent session histories are operator-sacred memory (indexed by cass); never reclaimed, even under disk pressure. Listed for every home form because the fleet daemon runs as root while agents run as other users. |
| `{~,/home/*,/Users/*}/.cass-memory`, `.local/share/coding-agent-search*` | `GlobMatch` | cass memory, index, databases and recovery copies. |
| `{~,/Users/*}/Library/Application Support/com.coding-agent-search.coding-agent-search`, `Library/Caches/cass-*` | `GlobMatch` | cass data and index work directories on macOS. |

## macOS Built-ins

These rules are embedded in `src/platform/macos/sacred.toml`. The common theme
is that macOS puts valuable user data under paths that can look like caches or
application support directories. `sbh` must not infer that those paths are safe
to delete merely because they live under `~/Library`.

| Pattern | Kind | Why it is sacred |
| --- | --- | --- |
| `~/Pictures/*.photoslibrary` | `GlobMatch` | Photos libraries contain originals, edits, albums, face/object metadata, and import history. Damage can be hard to detect until later. |
| `~/Library/Mobile Documents/com~apple~CloudPhotos*` | `GlobMatch` | iCloud Photos state syncs across devices. Local deletion can become a cloud-side destructive change or cause expensive resync. |
| `~/Library/Mail/*` | `GlobMatch` | Mail includes local mailboxes, cached messages, indexes, attachments, and account state. Offline mail can be user-critical. |
| `~/Library/Containers/com.apple.mail/*` | `GlobMatch` | Mail sandbox container data belongs to the user and can include preferences, indexes, and local state. |
| `~/Library/Messages/*` | `GlobMatch` | Messages stores conversations, attachments, and local chat databases. These are user records, not cache. |
| `~/Library/Containers/com.apple.iChat/*` | `GlobMatch` | Messages sandbox container data is part of the same user conversation state. |
| `~/Library/Group Containers/group.com.apple.notes/*` | `GlobMatch` | Notes can include local-only notes, attachments, and sync state. Treating it as regenerated cache risks data loss. |
| `~/Library/Calendars/*` | `GlobMatch` | Calendar data is personal information and can include local calendars, subscriptions, and sync metadata. |
| `~/Library/Group Containers/group.com.apple.reminders/*` | `GlobMatch` | Reminders data is user information and may include local or sync-sensitive task state. |
| `~/Library/Mobile Documents/com~apple~CloudDocs/*` | `GlobMatch` | iCloud Drive changes propagate to cloud storage and other devices. sbh must not clean arbitrary iCloud documents. |
| `~/Movies/*.fcpbundle` | `GlobMatch` | Final Cut Pro libraries are project bundles containing media, edits, render metadata, and production work. |
| `~/Movies/*.imovielibrary` | `GlobMatch` | iMovie libraries are creative project data, not rebuildable cache. |
| `~/Music/Logic/*` | `GlobMatch` | Logic sessions and audio assets are creative work; missing files can break projects silently. |
| `~/Music/GarageBand/*` | `GlobMatch` | GarageBand projects and media are creative work and may include original recordings. |
| `~/Pictures/Lightroom*` | `GlobMatch` | Lightroom catalogs and libraries hold edit metadata, imports, previews, and project organization. |
| `~/Pictures/Capture One*` | `GlobMatch` | Capture One catalogs and sessions are photo project state. |
| `~/Library/Application Support/Firefox/Profiles/*` | `GlobMatch` | Browser profiles contain credentials, sessions, extensions, history, and user settings. |
| `~/Library/Application Support/Google/Chrome/*` | `GlobMatch` | Chrome profiles contain credentials, sessions, extensions, history, and user settings. |
| `~/Library/Application Support/BraveSoftware/*` | `GlobMatch` | Brave profiles contain credentials, sessions, extensions, history, and user settings. |
| `~/Documents/**/*tax*` | `GlobMatch` | Tax records are high-value documents; filename casing and folder layout vary by user. |
| `~/Documents/**/*Tax*` | `GlobMatch` | Same as above, with common title-case naming. |
| `~/Documents/**/*.tax` | `GlobMatch` | Files with tax-specific extensions are finance records. |
| `~/Documents/**/*.qbo` | `GlobMatch` | QuickBooks export files are finance records. |
| `~/Documents/**/*.qbb` | `GlobMatch` | QuickBooks backup files are finance records. |
| `~/Documents/**/*cpa*` | `GlobMatch` | CPA/accounting files are finance records even when kept in ad hoc folders. |

## Relationship To macOS Cleanup Rules

The macOS cleanup catalog in `src/platform/macos/cleanup_catalog.rs` can still
surface reclaimable paths near sacred areas. The distinction is intentional:

| Cleanup family | Reclaim behavior | Sacred-path interaction |
| --- | --- | --- |
| Xcode DerivedData | Definite, remove per-project derived-data children after age and active-file checks. | Never bypasses sacred-overlap checks; does not delete user source projects. |
| CoreSimulator caches | Definite cache removal. | Simulator `Devices` state is not a cleanup candidate. |
| Electron caches | Likely removable cache shapes such as `Cache`, `Code Cache`, `GPUCache`, `IndexedDB`, `Service Worker/CacheStorage`, and `vm_bundles`. | Browser profile roots are sacred; cache rules target cache subtrees only. |
| `/private/tmp/*-target`, `*_target`, `target_*` | Likely removable build output after age and active-file checks. | Sacred-overlap checks still block candidates containing `.git`, `.beads`, databases, credentials, or `.sbh-protect`. |
| User-named trash directories | Unclear, prompt before removal. | Stowaway scans refuse or downgrade if project state, databases, credentials, or protection markers are inside. |
| `~/release-work/*[-_]buildroot` | Likely stale release staging after seven days. | Stowaway scans catch embedded repos, Beads state, databases, credentials, and markers. |
| `~/Library/Logs/*` | Likely cleanup of logs older than seven days. | Does not imply arbitrary `~/Library` data is disposable. |
| iPhone `.ipsw` software updates | Definite cleanup for firmware files older than 30 days in the Apple software update directory. | Only that update directory and extension are matched. |
| `~/.Trash/*` and iCloud Drive `.Trash/*` | Report only. | User must explicitly empty trash; sbh does not auto-empty it. |
| Time Machine local snapshots | Uses `tmutil thinlocalsnapshots`, not path deletion. | The operation asks APFS/Time Machine to thin snapshots; it does not delete user files directly. |
| Spotlight index | Report only. | Rebuilding Spotlight can be expensive and disruptive, so sbh does not casually remove it. |

## User-Configured Protection

Operators can add protection without changing code:

```bash
sbh protect /data/projects/important-repo
```

That writes a `.sbh-protect` marker. The marker protects the directory and all
descendants. It also acts as a stowaway marker if a parent cleanup candidate
would contain the protected directory.

Operators can also set `scanner.protected_paths` in config. These patterns are
converted to sacred path entries at runtime:

```toml
[scanner]
protected_paths = [
  "/data/projects/production-*",
  "/Users/me/Library/Mobile Documents/com~apple~CloudDocs/Client Records/*",
]
```

Config protections are hard vetoes. If a cleanup candidate is the protected
path, inside it, or a parent that would contain it, the candidate is skipped.

## Adding A New Sacred Pattern

Before adding a built-in sacred pattern, answer these questions in the same
patch:

1. Is the data irreplaceable, credential-bearing, sync-sensitive, or expensive
   to reconstruct?
2. Should the rule protect an exact path, a glob family, a contained descendant,
   or a stowaway file marker?
3. Could the pattern accidentally protect broad cache directories and prevent
   useful cleanup?
4. Is there a cleanup rule nearby that needs a test proving the sacred overlap
   check wins?
5. Does the reason string explain the risk in operator language, not just code
   language?

Every new built-in rule should include a test in the relevant catalog module and
an update to this document.
