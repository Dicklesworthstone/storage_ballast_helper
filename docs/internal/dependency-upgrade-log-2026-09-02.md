# Dependency Upgrade Log

Date: 2026-09-02

Project: `storage_ballast_helper` (binary `sbh`), plus the path crate `crates/sbh_mach`

## Scope

- Preserve the project policy that SBH builds with nightly Rust (`rust-toolchain.toml`, channel `nightly`).
- Apply dependency updates through the library-updater workflow: one dependency at a time, research before each bump, verify after each.
- Verification gate per dependency: `rch exec -- cargo check --all-targets`, `rch exec -- cargo test --workspace --no-fail-fast` (0 failures), `cargo fmt --check`.
- `cargo clippy --all-targets -- -D warnings` is NOT a pass/fail gate this sweep because it already fails at baseline with 62 pre-existing pedantic-lint errors from the current nightly (see Baseline); it is run once at the end and compared against that count.
- No commits, no pushes, no file deletions, no git-based rollbacks; a rollback is a re-edit of the version string plus `cargo update -p <crate>`.

## Baseline

- Baseline measured at HEAD `320d04d` (by the calling agent, artifacts in the session scratchpad): `cargo fmt --check` clean; `cargo test --workspace` 0 failures across 23 suites (1419 lib + 122 bin + 212 integration + 3 doc-tests = 1756 passed, 1 ignored); `cargo clippy --all-targets -- -D warnings` fails with 62 errors (61 lib-test + 1 bin-test): 37 `assert!` empty, 16 `assert!` not-empty, 5 `Duration` unit readability, 2 unchecked `Duration` subtraction, 1 constant assertion, 1 redundant clone.
- HEAD at the start of this sweep is `7c1b388` (docs-only commit on top of `320d04d`, but it also advanced `Cargo.lock`: `chacha20` 0.10.1→0.10.2, `clap` 4.6.4→4.6.6, `clap_builder` 4.6.2→4.6.6, `clap_complete` 4.6.7→4.6.9, `inotify` 0.11.4→0.11.5, `libsqlite3-sys` 0.38.1→0.38.2, `rusqlite` 0.40.1→0.40.2, `thiserror`/`thiserror-impl` 2.0.19→2.0.20, `toml` 1.1.3→1.1.4, `toml_parser` 1.1.2→1.1.3). Those moves were committed before this sweep started and are not entries below; the final gate in this log covers them.
- Pre-existing uncommitted working-tree change from another agent (NOT made by this sweep, left untouched): `Cargo.toml` `whichdisk = "0.5"` → `"0.6"` with the matching `Cargo.lock` move `whichdisk` 0.5.0 → 0.6.0 (macOS-only dependency).
- Toolchain observed: `rustc 1.100.0-nightly (0dfb098f3 2026-08-31)`, `cargo 1.100.0-nightly (e8cb624d5 2026-08-22)`.
- Tools available: `cargo-outdated` (installed), `cargo-audit` 0.22.1 (installed), `rch` 1.0.62 (15/15 workers healthy at start).
- Inventory commands:
  - `cargo outdated --root-deps-only --workspace` → only `bincode` 2.0.1 → 3.0.0 reported for the root package.
  - `cargo outdated --workspace` (transitive) → additionally `mach2` 0.6.0 → 0.7.0 (from `crates/sbh_mach`), plus cfg-irrelevant `getrandom` 0.4.3/`r-efi` 6.0.0 rows (wasm32 / uefi cfgs only) and spurious "Removed" rows that are artifacts of evaluating the poisoned `bincode` 3.0.0.
  - `cargo update --dry-run` → "Locking 0 packages" (lockfile already at the highest semver-compatible versions for every requirement).
  - crates.io API (`https://crates.io/api/v1/crates/<name>`, `max_stable_version`) queried for every direct dependency to cross-check `cargo outdated`; pre-releases ignored (`libc` 1.0.0-alpha.4).
  - `git ls-remote --tags https://github.com/Dicklesworthstone/frankentui` → newest tags `v0.5.0`, `v0.6.0` (pinned tag stays `v0.4.1`).

## Direct Dependency Inventory

### Root `Cargo.toml`

| Crate | Requirement | Resolved (Cargo.lock) | Latest stable | Kind / platform | Outcome |
| --- | --- | --- | --- | --- | --- |
| `clap` | `4.5` | 4.6.6 | 4.6.6 | optional (`cli`) | already latest |
| `clap_complete` | `4.5` | 4.6.9 | 4.6.9 | optional (`cli`) | already latest |
| `colored` | `3.0` | 3.1.1 | 3.1.1 | optional (`cli`) | already latest |
| `crossterm` | `0.29` | 0.29.0 | 0.29.0 | optional (`cli`) | already latest |
| `serde` | `1.0` | 1.0.229 | 1.0.229 | normal | already latest |
| `serde_json` | `1.0` | 1.0.151 | 1.0.151 | normal | already latest |
| `toml` | `1.1` | 1.1.4+spec-1.1.0 | 1.1.4+spec-1.1.0 | normal | already latest |
| `plist` | `1.9.0` | 1.10.0 | 1.10.0 | normal | already latest |
| `bincode` | `2.0.1` | 2.0.1 | 3.0.0 (poisoned) | normal | skipped — preserved by policy |
| `rusqlite` | `0.40` | 0.40.2 | 0.40.2 | optional (`sqlite`) | already latest |
| `thiserror` | `2.0` | 2.0.20 | 2.0.20 | normal | already latest |
| `ftui`, `ftui-backend`, `ftui-tty` | git tag `v0.4.1` | 0.4.1 @ `436e917` | tags `v0.5.0`, `v0.6.0` exist | optional (`tui`) | skipped — preserved by policy (tag not changed) |
| `chrono` | `0.4` | 0.4.45 | 0.4.45 | normal | already latest |
| `parking_lot` | `0.12` | 0.12.5 | 0.12.5 | normal | already latest |
| `crossbeam-channel` | `0.5` | 0.5.16 | 0.5.16 | normal | already latest |
| `memchr` | `2.7` | 2.8.3 | 2.8.3 | normal | already latest |
| `regex` | `1.11` | 1.13.1 | 1.13.1 | normal | already latest |
| `sha2` | `0.11` | 0.11.0 | 0.11.0 | normal | already latest |
| `signal-hook` | `0.4` | 0.4.4 | 0.4.4 | optional (`daemon`) | already latest (`crossterm` 0.29 still pulls 0.3.18 transitively; expected) |
| `rand` | `0.10.1` | 0.10.2 | 0.10.2 | normal | already latest (`proptest` pulls 0.9.5 transitively; expected) |
| `nix` | `0.31.3` | 0.31.3 | 0.31.3 | unix | already latest |
| `libc` | `0.2` | 0.2.189 | 0.2.189 (1.0.0-alpha.4 is pre-release) | unix | already latest |
| `rustix` | `=1.1.4` | 1.1.4 | 1.1.4 | unix | already latest; see note on the exact pin below |
| `inotify` | `0.11.1` | 0.11.5 | 0.11.5 | linux | already latest |
| `objc2-foundation` | `0.3.2` | 0.3.2 | 0.3.2 | macos | already latest |
| `proc_pidinfo` | `0.1.4` | 0.1.4 | 0.1.4 | macos | already latest |
| `sbh_mach` | path `crates/sbh_mach` | 0.1.0 | n/a | macos | preserved (path dependency; its own deps handled below) |
| `sysctl` | `0.7.1` | 0.7.1 | 0.7.1 | macos | already latest |
| `whichdisk` | `0.6` (uncommitted; was `0.5` at HEAD) | 0.6.0 | 0.6.0 | macos | already latest — bump is another agent's uncommitted change, not this sweep's |
| `tempfile` | `3.17` | 3.27.0 | 3.27.0 | dev | already latest |
| `proptest` | `1.6` | 1.11.0 | 1.11.0 | dev | already latest |
| `filetime` | `0.2` | 0.2.29 | 0.2.29 | dev | already latest |
| `criterion` | `0.8.2` | 0.8.2 | 0.8.2 | dev | already latest |
| `insta` | `1.47.2` | 1.48.0 | 1.48.0 | dev | already latest |

### `crates/sbh_mach/Cargo.toml`

| Crate | Requirement | Resolved (Cargo.lock) | Latest stable | Outcome |
| --- | --- | --- | --- | --- |
| `dispatch2` | `0.3.1` | 0.3.1 | 0.3.1 | already latest |
| `libc` | `0.2` | 0.2.189 | 0.2.189 | already latest |
| `mach2` | `0.6.0` | 0.6.0 | 0.7.0 | update candidate (see entry) |
| `proc_pidinfo` | `0.1.4` | 0.1.4 | 0.1.4 | already latest |

Requirement floors (e.g. `clap = "4.5"`, `tempfile = "3.17"`) were deliberately left as they are: they already admit the latest versions, the lockfile is already at those versions, and raising the floors would change nothing in the resolved graph while adding churn to a manifest other agents are editing.

## Preserved / Policy Notes

- `bincode = "2.0.1"`: left as is. 3.0.0 is a poisoned release (a `compile_error!` lib.rs, `serde` feature dropped) — see the comment in `Cargo.toml` and the 2026-05-13 log.
- `ftui*` git dependencies: tag `v0.4.1` left as is per instruction. Newer upstream tags `v0.5.0` and `v0.6.0` exist; moving would be a separate, deliberate TUI migration.
- `rustix = "=1.1.4"` exact pin: no recorded reason exists. It was introduced as `=1.1.3` in commit `1c0f8f5` ("bd-hnxg.1 add PAL preallocation") with no explanatory commit body and no `Cargo.toml` comment; the 2026-05-13 sweep only bumped the pin to `=1.1.4`. Usage is two `rustix::fs::{FallocateFlags, fallocate}` call sites (`src/platform/linux/mod.rs`, `src/platform/macos/pal.rs`). Treated as a normal dependency: the latest 1.x on crates.io is 1.1.4, which is already resolved, so there is no version to try. The `=` operator itself was left untouched (relaxing it has zero effect on the current lock and is a policy call for a human).
- Nightly toolchain: unchanged.
- `sbh_mach` path dependency: unchanged; its own dependencies were swept (table above).

## Upgrade Entries

### `mach2` 0.6.0 -> 0.7.0 (`crates/sbh_mach/Cargo.toml`)

- Research (`gh api repos/JohnTitor/mach2/releases`, `gh api repos/JohnTitor/mach2/compare/0.6.0...0.7.0`): 0.7.0 was published 2026-08-30. The 0.x "major" bump is driven by a `BOOTSTRAP_*` constant correction (`src/bootstrap.rs`), signature/const changes in `vm.rs`, `semaphore.rs`, `port.rs`, `thread_act.rs`, `vm_statistics.rs`, and three new modules (`host_info`, `mach_host`, `machine`). None of those are used by `sbh_mach`.
- Modules `sbh_mach` imports and how they changed: `kern_return` (six new `KERN_*` consts, additive), `mach_port` (three new extern fns, additive), `mach_types` (new aliases `thread_suspension_token_t`, `ledger_entry_id_t`, additive), `message` (new `MACH_MSG_TYPE_PORT_*` consts, additive), `traps` (new `task_name_for_pid`, `mach_vm_reclaim_update_kernel_accounting_trap`, `thread_set_x86_64_compat`, additive), `vm_types` (new `err_vm_reclaim`, additive). `task`, `task_info`, `mach_init`, `time_value` are unchanged. Edition stays 2024. No breaking change for the items `sbh_mach` uses (`kern_return_t`, `KERN_SUCCESS`, `KERN_INVALID_ARGUMENT`, `mach_host_self`, `mach_thread_self`, `mach_port_deallocate`, `thread_act_t`, `mach_msg_type_number_t`, `task_info`, `MACH_TASK_BASIC_INFO*`, `TASK_THREAD_TIMES_INFO*`, `mach_task_basic_info`, `task_thread_times_info`, `time_value_t`, `mach_task_self`, `integer_t`, `natural_t`).
- Reverse dependencies: `cargo tree -i mach2 --target aarch64-apple-darwin` shows only `sbh_mach` -> `storage_ballast_helper`, so no second `mach2` copy enters the graph.
- Action: edited `crates/sbh_mach/Cargo.toml` from `mach2 = "0.6.0"` to `mach2 = "0.7.0"`, then `cargo update -p mach2` ("Locking 1 package": `mach2` 0.6.0 -> 0.7.0; no other lock entries touched by this command).
- No source changes were required.
- Verification:
  - `rch exec -- cargo check --all-targets` (Linux): passed, exit 0, remote worker `hz3` (172s). Note: `sbh_mach` is `cfg(target_os = "macos")`, so the Linux gate validates the lockfile but does not compile the crate.
  - `rch exec -- cargo check --target aarch64-apple-darwin -p sbh_mach --all-targets`: passed, exit 0, 0 warnings; `Checking mach2 v0.7.0` and `Checking sbh_mach v0.1.0` both compiled. rch fell back to local (`[RCH] local`, no worker declares `os = "darwin"`), which is acceptable.
  - `rch exec -- cargo check --target aarch64-apple-darwin --all-targets` (whole crate): could not be completed on this host — exit 101 in the `libsqlite3-sys` 0.38.2 bundled C build because the host `cc` rejects `-arch arm64` / `-mmacosx-version-min`; a single retry with `CC_aarch64_apple_darwin="zig cc -target aarch64-macos"` also failed (zig rejects cc-rs's added `--target=arm64-apple-macosx` alongside `-target`). This is a cross-toolchain limitation, not a code failure; the root crate does not reference `mach2` directly and `sbh_mach`'s public API was not changed, so the `-p sbh_mach` cross-check is the load-bearing verification. A native macOS `cargo check`/`cargo test` of `sbh_mach` remains unverified from this Linux host.
  - `rch exec -- cargo test --workspace --no-fail-fast` (Linux): passed, exit 0, remote worker `hz3` (98.9s); 23 suites, 1756 passed, 0 failed, 1 ignored (1419 lib + 122 bin + 212 integration + 3 doc-tests) — identical to baseline.
  - `cargo fmt --check`: clean.
- Result: updated.

### Lockfile moves observed during the sweep (not made by this workflow)

- While this sweep was in progress, another agent committed the working tree as `944e3ce` ("chore(deps,docs): bump whichdisk to 0.6, mach2 to 0.7, and add 2026-09-02 bridge plan"). That commit captured this sweep's `mach2` bump, the pre-existing `whichdisk` bump, and the first 90 lines of this log, plus 26 transitive patch/minor moves that this sweep did not perform (`cargo update -p mach2` locked exactly one package): `aho-corasick` 1.1.4→1.1.5, `android_system_properties` 0.1.5→0.1.6, `cc` 1.4.0→1.4.4, `cpufeatures` 0.3.0→0.3.1, `either` 1.17.0→1.18.0, `find-msvc-tools` 0.1.9→0.1.11, `futures-core`/`futures-task`/`futures-util` 0.3.33→0.3.34, `hybrid-array` 0.4.13→0.4.14, `indexmap` 2.14.0→2.14.1, `js-sys`/`web-sys` 0.3.103→0.3.104, `log` 0.4.33→0.4.34, `lru` 0.18.1→0.18.3, `pkg-config` 0.3.33→0.3.34, `regex-automata` 0.4.16→0.4.18, `smallvec` 1.15.2→1.16.0, `syn` 3.0.3→3.0.4, `time` 0.3.54→0.3.55, `wasm-bindgen`(+`-macro`, `-macro-support`, `-shared`) 0.2.126→0.2.127, `zerocopy`/`zerocopy-derive` 0.8.55→0.8.56. No packages were added or removed.
- This workflow made no commits. The final gate below ran against the lockfile as committed in `944e3ce` (the `cargo test`, final `cargo check`, and `cargo clippy` runs all started after 00:18:28 local, the commit time), so those transitive moves are covered by it.
- After that commit, `cargo update --dry-run` reports "Locking 0 packages" (only `bincode` remains behind latest, by policy), and `git diff HEAD -- Cargo.toml Cargo.lock crates/sbh_mach/Cargo.toml` is empty.

## Final Quality Gates

All compilation went through `rch`; every run below used the lockfile as committed in `944e3ce` (which is byte-identical to the working tree for `Cargo.toml`, `Cargo.lock`, and `crates/sbh_mach/Cargo.toml`).

- `rch exec -- cargo check --all-targets`: passed, exit 0 (remote `hz3`).
- `cargo fmt --check`: clean.
- `cargo metadata --locked --format-version 1`: exit 0 (lockfile consistent).
- `cargo update --dry-run`: "Locking 0 packages" — only `bincode` remains behind latest, by policy.
- `cargo audit` (cargo-audit 0.22.1): exit 0, 0 vulnerabilities; 1 allowed warning, RUSTSEC-2025-0141 "bincode is unmaintained" (`bincode` 2.0.1, known and accepted — 3.0.0 is poisoned).
- `rch exec -- cargo clippy --all-targets -- -D warnings`: exit 101 with exactly the 62 pre-existing lint errors from baseline (61 lib-test + 1 bin-test): 37 `used assert! to check that a value is empty`, 16 `... is not empty`, 5 `Duration` unit readability, 2 `unchecked subtraction of a Duration`, 1 `constant assertion`, 1 `redundant clone`. No new error kinds and no count change versus baseline; these are not addressed by this sweep (another agent's task).
- `rch exec -- cargo test --workspace --no-fail-fast`, run three times on remote `hz3`:
  - Run 1 (98.9s): 23 suites, 1756 passed, 0 failed, 1 ignored — exit 0.
  - Run 2 (final-gate re-run): 1755 passed, 1 failed — `tests/integration_tests.rs::daemon_exits_nonzero_when_rss_hard_cap_exceeded` panicked at line 2489 with "timed out waiting for child exit" (the test gives the daemon a hard 10 s `wait_for_child_exit` budget at line 1643). The identical tree had just passed in run 1; re-running the single test in isolation on the same worker passed 3/3 (7.46 s, 2.21 s, 0.45 s wall). Classified as a timing flake under worker load, not a dependency regression.
  - Run 3 (58.9s): 23 suites, 1756 passed, 0 failed, 1 ignored — exit 0.
  - Split for the passing runs: 1419 lib + 122 bin + 212 integration + 3 doc-tests, matching baseline exactly.
- macOS coverage caveat: `sbh_mach` and the root crate's macOS platform code are `cfg(target_os = "macos")` and are not compiled or tested by the Linux gate. The `mach2` bump was cross-checked with `cargo check --target aarch64-apple-darwin -p sbh_mach --all-targets` (clean). A native macOS build/test was not possible from this host.

## Summary

- Updated: 1 — `mach2` 0.6.0 → 0.7.0 (`crates/sbh_mach`).
- Already latest (no action): 32 direct dependencies across both manifests (see inventory tables); the lockfile was already at the highest semver-compatible version for every requirement, and `cargo update --dry-run` locks 0 packages.
- Skipped / preserved by policy: 3 — `bincode` 2.0.1 (3.0.0 poisoned), `ftui`/`ftui-backend`/`ftui-tty` git tag `v0.4.1` (upstream `v0.5.0`, `v0.6.0` exist), `sbh_mach` path dependency (its own deps were swept).
- Failed / rolled back: 0.
- Code changes: none. Manifest changes by this sweep: `crates/sbh_mach/Cargo.toml` (one line) and the corresponding single `Cargo.lock` entry.
- Commits: none by this workflow. Commit `944e3ce` was made by another agent mid-sweep and includes this sweep's manifest/lock change and the first 90 lines of this log.
- Final test totals: 1756 passed / 0 failed / 1 ignored across 23 suites (runs 1 and 3); one timing flake in run 2 documented above.

## Needs Attention (human decisions)

- `tests/integration_tests.rs::daemon_exits_nonzero_when_rss_hard_cap_exceeded`: the 10 s child-exit budget is tight on loaded workers (7.46 s in an isolated pass; one timeout in a full parallel run). Consider raising the budget or marking the test serial. Not touched by this sweep.
- `rustix = "=1.1.4"`: no recorded reason for the exact pin (introduced as `=1.1.3` in `1c0f8f5` with no explanation). Latest 1.x is 1.1.4 already, so nothing changed; decide whether to relax to `"1.1"` so future sweeps can move it without a manifest edit.
- `ftui*` git tag: upstream frankentui has `v0.5.0` and `v0.6.0`; a TUI migration would be a separate, deliberate task.
- `bincode` 2.0.1 is flagged unmaintained (RUSTSEC-2025-0141) and 3.0.0 is poisoned; a long-term replacement (e.g. `postcard`, `bitcode`, or plain `serde_json`) is a design decision outside this sweep.
- `libc` 1.0.0-alpha.4 exists as a pre-release; ignored per policy until a stable 1.0 ships (note `nix`, `rustix`, and others must move first).

## Addendum: post-sweep working-tree change by another agent (not part of this sweep)

- At 2026-09-02 00:29:42 local, after this sweep's final gates had run, another agent edited `Cargo.toml` to move the three `ftui` git dependencies (`ftui`, `ftui-backend`, `ftui-tty`) from tag `v0.4.1` to `v0.6.0`. This sweep did not make that change and, per its instructions, left the `v0.4.1` pin untouched; the edit is uncommitted and belongs to that other agent.
- `Cargo.lock` was not updated alongside it (still resolves the `v0.4.1` commit `436e917`), so the working tree is currently manifest/lock-inconsistent: `cargo metadata --locked --format-version 1` now exits 101 with: `error: cannot update the lock file /data/projects/storage_ballast_helper/Cargo.lock because --locked was passed to prevent this
help: to generate the lock file without accessing the network, remove the --locked flag and use --offline instead.`
- Every gate result recorded above was produced against the `v0.4.1` manifest and matching lockfile (as committed in `944e3ce`). The `v0.6.0` move is NOT covered by this sweep's verification; it needs its own lock update (`cargo update -p ftui -p ftui-backend -p ftui-tty`) and a `--features tui` build/test pass by whoever owns it.
