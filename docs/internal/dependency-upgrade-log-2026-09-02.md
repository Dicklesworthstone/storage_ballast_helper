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

