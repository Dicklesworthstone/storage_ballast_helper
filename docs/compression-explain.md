# Explain a compression operation

Compression apply reports an `operation_id` such as `abc-42-0:1`. Use the explicit
`compress:` namespace with the normal explanation command:

```sh
sudo sbh --json explain --id compress:abc-42-0:1
```

Use the same effective user and configuration as the original apply. For a
custom installation, pass its existing global `--config PATH`. The command
resolves `RUN:SEQUENCE` to `compression-journal/RUN.jsonl` beside that config's
state file. Run IDs cannot contain slashes, traversal, encoded paths or unit
specifiers. No directory scan or guessed fallback journal is used.

The schema is `sbh.compression.explanation.v1`, with `source` set to
`compression_journal`. The selected operation includes the original outcome,
content-verification status, before/after physical data allocation, referenced
savings or growth, pending old allocations and confirmed net data-only reclaim
when recorded. The original pass policy and its completion/torn-tail status are
also included. These are historical measurements, not today's free-space state.

The existing recovery validator is reused for ownership, permissions, hardlinks,
active locks, input-size bounds, sequence consistency and false-success footers.
A missing operation or mismatched journal is an error; another operation is not
silently substituted. Ordinary deletion IDs still go through the existing
explanation path. Compression IDs cannot request deletion replay or why-not mode.

An unfinished intent proves only that a mutation was prepared. It is not proof
that compression ran, finished, or reclaimed bytes. Interrupted or torn runs
remain exit 4, even when one of their earlier operations has a recorded outcome.
A fully recorded run retains its recorded exit code.

This lookup is for explanations, not full source-file hashing. It uses a
five-second cooperative recovery budget and at most one input byte across the
run, exposed as `input_rehash_budget_bytes`; ordinary large unfinished inputs
are therefore left unverified. For full read-only content verification, use:

```sh
sudo sbh --json compress --recover-journal /var/lib/sbh/compression-journal/RUN.jsonl \
  --max-bytes 8589934592 --timeout-secs 300
```

Neither explanation nor recovery replays compression, restores file bytes, or
edits journal records. Compression records remain distinct from deletion
`decision_log` rows. Automatic pressure-tier scheduling, recursive apply and
persistent compression policy configuration are still unfinished.

## Shared activity stream

Explicit-file `sbh compress --apply` now attempts to publish each prepared file's
outcome through the existing JSONL/SQLite activity logger. Publication happens
immediately after that file's postflight and synchronous outcome-journal write
attempt, before the next file is considered, rather than waiting for the final
stdout report. Both successful and partial/failed prepared outcomes are included.
No new logging flags or database migrations are needed.

The top-level activity envelope is the existing `info` event. Decode its
`details` JSON string and select `kind = "compression_outcome"` and
`schema = "sbh.compression.activity.v1"`. This is a typed audit event internally,
so repetitive-diagnostic throttling does not coalesce a batch of similar file
outcomes. The existing bounded queue, SQLite degradation, JSONL rotation and
fallback policies still apply. This is not a second durable journal.

The payload includes the namespaced operation ID, observation timestamp,
journal location, `journal_outcome_recorded`, native pathname bytes in hex,
and the complete per-file `result`. Failed outcome-journal writes are explicitly
marked; successfully submitting an activity event never changes that flag.
The two activity backends receive the same original observation timestamp and
serialized details. Recovery and `sbh explain --id compress:...` continue to use
the validated journal, not unverified activity projections.

Generic `size`/`size_bytes`, deletion decision IDs and scoring fields are unset.
Logical input bytes, referenced physical savings, growth, pending allocations
and confirmed data-only reclamation remain separate fields inside `result`.
Compression cannot inflate deletion/ballast counters or be mistaken for an
approval to delete a file. Unknown accounting stays null rather than becoming
an estimated saving.

The CLI response retains its existing `sbh.compression.v1` fields and adds
`activity_delivery` (schema `sbh.compression.activity_delivery.v1`). It reports
prepared outcomes observed, submission attempts, rejected projections, queue
drops, diagnostic suppression, writer lifecycle status, and the first known
transport error. `backend_durability` is always `"not_verified"`: a successful
queue attempt or joined writer is not evidence that either activity backend
persisted the record. Backend failures may be reported by the logger even when
its lifecycle finishes normally. Known transport loss also emits a diagnostic
on stderr, including in quiet/JSON mode.

The command exit code continues to describe the compression operation and its
durable journal, not the secondary activity transport. Inspect activity delivery
separately. A logger problem does not retry compression, erase a successful
mutation, alter its accounting, or authorize a subsequent operation. Shutdown
uses the existing logger supervisor (five-second wait budget); a timed-out
writer may finish later and is not forcibly cancelled. This final flushing time
is separate from the cooperative compression work budget.

Activity backends are initialized lazily after the first prepared outcome.
Preview, discovery, recovery, explanation, and apply passes with no prepared
input create no activity files or directories through this integration. sbh's
own control files, configured activity destinations, SQLite sidecars, RAM
fallback, and compression-journal subtree are excluded from compression before
logger initialization, including existing configured aliases. Protection
failures still fail closed; no control-file or deletion safety gate is weakened.
