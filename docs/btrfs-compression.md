# Lossless Btrfs compression

`sbh compress` is an opt-in operator command for explicitly selected cold,
unshared regular files. It does not delete files, truncate logs or change daemon
policy. The daemon compresses on its own only when `[compress]` is enabled (see
[Daemon tier](#daemon-tier)). Preview is the default:

```sh
sudo sbh --json compress -- /data/old-debug-binary /data/old-session.jsonl
```

To select cold files beneath directories instead of naming them, use
`--discover`, and add `--apply` to compress that selection in the same pass
(`compression-discovery.md`).

The native backend supports Linux x86-64 and AArch64 on Btrfs. Other filesystems
are skipped and other operating systems report an unsupported no-op. Linux
`openat2` support and sufficient privileges for Btrfs tree inspection are
required; denied or incomplete inspection fails closed. Directories and
symlink inputs are not recursively followed.

## Apply deliberately

Stop writers and disable concurrent snapshot/reflink creation for the pass.
Process inspection is not a filesystem-wide mutation lock. The command requires
both acknowledgements, even when the filesystem already uses zstd:

```sh
sudo sbh --json compress \
  --apply --allow-zstd-feature --quiescent \
  -- /data/old-debug-binary /data/old-session.jsonl
```

`--allow-zstd-feature` acknowledges that a first zstd write can enable the
filesystem-wide COMPRESS_ZSTD incompatibility feature, requiring Linux 4.14 or
later to read the filesystem. `--quiescent` acknowledges the operational
precondition; it does not stop processes or snapshot services for you. There is
no `--force` override. `--dry-run` explicitly requests preview and conflicts with
`--apply`.

The existing `--config` path is honored, including configured protected paths
and the associated sacred configuration. Protection markers, sacred catalog
matches, active/uncertain target leases, open references, executing files,
memory mappings, and active build directories veto compression. Shared/reflinked,
already encoded, preallocated, inline, hard-linked, NOCOW, NOCOMP, immutable,
append-only, and unknown extent layouts are excluded. An incomplete process
inspection is not treated as an empty result.

Every apply pass holds a pinned, no-symlink descriptor. The exact inspection
file descriptor is exempt from open-file checks; other descriptors in the same
process, including redirected standard output, are not. Cooperating compression
processes are serialized with an advisory file lock. These measures do not make
concurrent uncooperative writers or snapshot creation safe.

## Work limits

Defaults are a 16 MiB minimum file size, 24-hour modification age, 128 files,
8 GiB of admitted logical input, a 300-second cooperative deadline, and a 1 GiB
available-space reserve plus two 16 MiB rewrite chunks. Apply uses idle I/O
priority and fresh protection, process, identity, and headroom checks between
chunks. Logical input limits bound work, not expected savings.

Use `--min-size-bytes`, `--min-age-secs`, `--max-files`, `--max-bytes`,
`--timeout-secs`, and `--min-free-bytes` to select limits. Safety floors refuse
ages below one hour, reserves below 256 MiB, zero limits, more than 4096 files,
or deadlines above one hour. A file larger than the remaining byte budget is
skipped rather than partly admitted.

An in-flight kernel operation cannot be forcibly interrupted by this deadline.
After any attempted rewrite, content verification has its own 120-second
cooperative budget and accounting its own 30-second budget. Exhaustion is
reported as incomplete, never as successful verification. Partial/unverified
mutations or measured allocation growth stop the pass before the next file.

## Durable audit and interrupted-run inspection

Before the first rewrite of each eligible file, apply synchronizes an intent
record containing its native pathname bytes, device/inode, length, timestamps,
preflight SHA-256 and measured physical allocation. Each file's final outcome is
synchronized immediately after postflight, not postponed until the final stdout
report. A journal error before mutation refuses the operation; an outcome-write
error after mutation stops the pass and leaves the intent for inspection.

Journals are created lazily under `compression-journal/` beside the configured
state file, for example `/var/lib/sbh/compression-journal/RUN.jsonl`. The state
file's parent directory must already exist. The journal directory is private
(mode 0700) and files are created exclusively (mode 0600); existing permissions
are never widened. The new file, its directory, and the parent directory are
synchronized before an intent can authorize a rewrite. Files are capped at
32 MiB and individual records at 128 KiB. This feature does not automatically
rotate, delete or prune audit history. Preview and no-eligible-input passes
create no journal files or directories.

The apply report includes `journal_path`, and each prepared file report includes
an `operation_id`. To inspect a recorded or interrupted pass, as the same effective
user that created the journal:

```sh
sudo sbh --json compress \
  --recover-journal /var/lib/sbh/compression-journal/RUN.jsonl \
  --max-bytes 8589934592 --timeout-secs 300
```

Recovery is **read-only** and does not load the current daemon config. It refuses
an actively locked journal, symlinked or multi-link journal files, foreign/non-private
ownership, oversized input, inconsistent sequences, mismatched run IDs, malformed
complete records, and false success footers. An unterminated last record is
reported as torn/uncertain; earlier complete records remain inspectable.

For an unfinished intent, recovery rechecks the original file identity, length,
mtime and SHA-256 within the selected byte/time budget. Native pathname bytes are
retained independently of lossy display strings. Replaced, renamed, missing,
changed or unverified files remain uncertain. Recovery never replays compression,
restores old bytes, or edits the journal. Completed outcomes are shown as
**historical records**, not newly verified current state.

An intent proves only that mutation was prepared, not that a kernel call happened.
Even successful post-interruption content verification does **not** establish
compression completion or physical reclaim. Interrupted/torn runs always return
exit 4; a fully recorded run retains its recorded exit code.

## Read the evidence, not just the exit code

The `sbh.compression.v1` JSON report records per-file eligibility/failure reasons,
attempted mutation, processed bytes, before/after SHA-256, content/size/mtime
verification, physical allocation measurements, and unvisited inputs. Display
paths use lossy UTF-8 for unusual filenames; they are not replay authority.

Physical accounting uses Btrfs EXTENT_DATA disk allocation lengths, deduplicated
by allocation. It does not infer disk savings from logical lengths, `st_blocks`,
or FIEMAP lengths. `referenced_bytes_saved` is the reduction in allocations
referenced by this file; growth is recorded separately. `old_data_bytes_pending`
means retired allocations still exist in the extent tree. Transaction and
relocation delays can prevent immediate reuse.

`confirmed_data_bytes_reclaimed` subtracts newly allocated data from retired
allocations observed absent from the extent tree. It excludes metadata overhead
and is **not** a measurement of immediately available mount space. A failed
accounting query yields unknown evidence, not a fabricated zero or an estimate.
Recheck actual filesystem headroom before any subsequent reclamation action.

Exit 0 means the pass completed, previewed, or was a no-op; inspect individual
outcomes because a skipped file is not compressed. Exit 1 indicates invalid
configuration or input. Exit 2 indicates a runtime/inspection failure before
mutation. Exit 4 indicates incomplete visitation, a partial mutation, or a later
failure after an earlier mutation; inspect `mutation_attempted`, `content_verified`,
the journal, and the accounting fields. Recovery emits `sbh.compression.recovery.v1`
and preserves uncertainty rather than converting verified contents into success.

## Validation and scope

The dedicated Btrfs workflow contains dependency-free backend tests, application
policy/journal/CLI tests, Linux UAPI assertions, and opt-in native tests on a
disposable Btrfs loop mount. The native tests check byte preservation, size/mtime
stability, physical allocation reduction, and reflink refusal. Journal tests
exercise interrupted and torn records, locking, identity/hash changes, ownership,
write/read budgets, failure poisoning, and native filename preservation. To run:

```sh
cargo test --locked --manifest-path crates/sbh_btrfs/Cargo.toml
cargo test --locked --no-default-features --features cli,daemon,sqlite --lib scanner::compression
cargo test --locked --no-default-features --features cli,daemon,sqlite --bin sbh cli_compress
# Root and an explicitly prepared disposable Btrfs filesystem are required:
SBH_BTRFS_TEST_ROOT=/path/to/disposable/btrfs \
  cargo test --locked --manifest-path crates/sbh_btrfs/Cargo.toml -- --ignored
```

The durable compression journal is not a fabricated deletion decision.

## Daemon tier

With `[compress] enabled = true`, the daemon runs the same discover-then-apply
pass on its own. A pass starts when a configured root sits on Btrfs whose mount
is at or above `start_level` (default `yellow`), no pass is running, and
`interval_minutes` (default 30) have passed since the last one started. Each
pass is bounded by `[compress.policy]`: by default files idle for 24 hours and at
least 16 MiB, at most 128 files and 8 GiB, and 300 seconds. Discovery resumes
where the previous pass stopped. Every file outcome reaches the activity log, as
for the CLI, and an `[SBH-COMPRESS]` line summarizes the pass and the referenced
bytes saved. The tier never deletes anything, and never touches a root on another
filesystem.

```toml
[compress]
enabled = true
roots = ["/data/tmp"]
allow_zstd_feature = true   # required: the first zstd write sets COMPRESS_ZSTD
start_level = "yellow"
interval_minutes = 30

[compress.policy]
min_age_secs = 86400
```

Enabling the tier stands in for the CLI's `--quiescent`, which no daemon can
promise on a shared host. Content stays protected by the checks every apply runs
anyway:

- the minimum idle age;
- the open, mmap and lease vetoes;
- the file stamp and root scope, rechecked between chunks;
- a SHA-256 re-read from disk after the rewrite.

What you accept by enabling it is about space, not data: a snapshot or reflink
made during a pass keeps the old extents alive, so those bytes are freed only
when it goes away.

The scheduling is in `src/daemon/compress_tier.rs`. `sbh daemon reload` applies
config changes.
