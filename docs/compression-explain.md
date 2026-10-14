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
`decision_log` rows. Publishing compression outcomes into the shared activity
stream, automatic pressure-tier scheduling and persistent compression policy
configuration are still unfinished.
