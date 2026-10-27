# Agent-session scratch inventory

`sbh check --agent-scratch [PATH]` inventories Claude Code scratch sessions
that can hold substantial space without qualifying as regenerable build
artifacts. The command reports evidence for manual review. It does not delete,
move, truncate, compress, or approve cleanup of a session, and does not start a
daemon or create state, activity logs, or journals.

```sh
sbh check --agent-scratch /data/tmp --min-idle-days 9
sbh --json check --agent-scratch /tmp --agent-scratch-top 50
```

## Roots and transcripts

Recognized sessions have the layout
`<tmp>/claude-<uid>/<project>/<session-uuid>`. An explicit `PATH` selects one
temporary-storage root or one `claude-<uid>` directory. Without `PATH`, the
command checks existing configured scanner roots, platform temporary roots,
and `/tmp` and `/data/tmp` where present. This discovery does not add cleanup
roots to the daemon.

The command loads normal configuration to report configured path protection.
Use the global `--config FILE` option to select it. A transcript normally comes
from the UID owner's home:
`~/.claude/projects/<project>/<session-uuid>.jsonl`. For a relocated transcript
store or a fixture, select its `projects` directory explicitly:

```sh
sbh --json check --agent-scratch /data/tmp/claude-1000 \
  --transcript-root /home/agent/.claude/projects
```

Only transcript metadata is inspected; transcript contents are not read.
An absent, inaccessible, or unsafe transcript prevents an idle conclusion.

## What the classifications mean

| State | Evidence |
| --- | --- |
| `active` | A live process has a working directory, open file, or mapped file referring to the session or its transcript. |
| `recent` | The observed tree or transcript changed within the requested inactivity window. |
| `unknown` | Available evidence cannot establish inactivity, for example because a transcript is missing, a tree changed during traversal, or process visibility is incomplete. |
| `idle` | Complete tree and transcript observations satisfy the inactivity window, and a complete process sweep found no live references. Manual review is still required. |

An active or recent observation remains useful even if another part of the
inspection is incomplete. Such a row can have `complete=false`; it never becomes
`idle` on the strength of missing evidence. Inactivity uses the newest observed
mtime **or ctime**, so restoring an old file modification time does not hide a
recent metadata change. Protection markers, source-control markers and
configured protection are shown separately; an idle label does not override
them. The report is an observation, not an atomic filesystem snapshot.

Logical bytes count distinct regular-file inodes within each session. Allocated
bytes count observed inode blocks, including directory blocks. Hardlinks within
a session count once; shared/reflinked extents and links in other sessions can
still be counted elsewhere. Neither total establishes exclusive reclaimable
space. `reclaimable_bytes` is therefore always `null`, and partial-walk sizes are
only observed lower bounds.

## Bounded, read-only inspection

Caller-supplied root aliases such as macOS `/tmp` are resolved once. Descendant
traversal is relative to open directory descriptors, does not follow symlinks,
and does not cross filesystem boundaries. Changed directory identities,
inaccessible entries, skipped symlinks and mount boundaries produce explicit
uncertainty. Protection-marker contents are not read, including markers that
are FIFOs. The process collector is bounded by the shared report deadline;
missing visibility is not treated as an empty process list.

| Option | Default | Allowed range |
| --- | --- | --- |
| `--min-idle-days` | 7 days | 1–3650 days |
| `--agent-scratch-timeout-secs` | 30 seconds | 1–120 seconds |
| `--agent-scratch-max-entries` | 2,000,000 | 1–5,000,000 |
| `--agent-scratch-top` | 25 sessions | 1–2048 sessions |

Discovery and traversal share the time and entry budgets. The implementation
also limits roots to 64, discovered sessions to 2048, and traversal depth to 64.
Time bounds are cooperative: an in-flight filesystem operation can exceed its
deadline. Exhausted budgets yield partial results instead of an idle verdict.
The display limit omits smaller observed sessions after the survey; it does not
hide uncertainty or change the total discovered/idle counts. Results are ranked
only among observed sessions.

## JSON and exit status

`--json` produces one `sbh.agent_scratch.v1` document. It includes `read_only`,
`complete`, `min_idle_days`, `sessions_found`, `idle_sessions`,
`omitted_sessions`, `entries_examined`, `sessions`, `issues`, and `exit_code`.
Each session carries its path and lossless `native_path_hex`, owner UID, project,
session ID, transcript path, observed sizes, ages, state, reasons, protections,
and completeness. Native path bytes keep non-UTF-8 names distinguishable.

| Exit | Meaning |
| --- | --- |
| 0 | Complete inventory, regardless of whether any idle sessions were found. |
| 1 | Invalid runtime limits or configuration. |
| 2 | Collection/output failure, unsupported platform, or CLI argument error. |
| 4 | Partial discovery, traversal, transcript, or process evidence. |

`--quiet` suppresses human output while retaining the exit status; `--json`
still requests the structured report. Agent scratch mode cannot be combined
with ordinary space/prediction checks or `--ram-scratch`. On supported Unix
platforms, process visibility depends on the caller's permissions. More
privilege can improve visibility but cannot guarantee a complete snapshot.
