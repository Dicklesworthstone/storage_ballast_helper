# Lossless Btrfs compression

`sbh compress` is an opt-in operator command for explicitly selected cold,
unshared regular files. It does not delete files, truncate logs, change daemon
policy, or enable automatic compression. Preview is the default:

```sh
sudo sbh --json compress -- /data/old-debug-binary /data/old-session.jsonl
```

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
outcomes because a skipped file is not compressed. Exit 1 indicates the command
could not start. Exit 2 indicates a failed file admission/operation or priority
restoration. Exit 4 indicates incomplete visitation or a partial mutation;
inspect `mutation_attempted`, `content_verified`, and the accounting fields.

## Validation and scope

The dedicated Btrfs workflow contains dependency-free backend tests, application
policy/CLI tests, Linux UAPI assertions, and opt-in native tests on a disposable
Btrfs loop mount. The native tests check byte preservation, size/mtime stability,
physical allocation reduction, and reflink refusal. To run the backend lane:

```sh
cargo test --locked --manifest-path crates/sbh_btrfs/Cargo.toml
# Root and an explicitly prepared disposable Btrfs filesystem are required:
SBH_BTRFS_TEST_ROOT=/path/to/disposable/btrfs \
  cargo test --locked --manifest-path crates/sbh_btrfs/Cargo.toml -- --ignored
```

Automatic Yellow/Orange pressure scheduling, persistent `[scanner.compress]`
configuration, and activity-ledger/`sbh explain` integration are not implemented
by this operator command. The command returns its report to standard output;
retain it outside the selected inputs. It does not provide a durable recovery
journal if the process is killed before reporting.
