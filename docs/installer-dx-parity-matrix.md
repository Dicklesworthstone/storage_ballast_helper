# Installer DX Parity Matrix (dcg -> sbh/fsfs)

This document is the implementation contract for bead `bd-2j5.1`.

Goal: map each dcg installer/update capability to explicit `sbh`/`fsfs` behavior, including scope, status, security posture, and test/logging gates.

## Status Legend

- `implemented`: shipped and covered by tests
- `planned`: scoped and linked to an open bead
- `deferred`: intentionally postponed with rationale
- `n/a`: not applicable to sbh/fsfs

## Capability Matrix

| Capability Area | dcg Baseline | sbh/fsfs Target Contract | Status | Linked Beads | Required Gates |
| --- | --- | --- | --- | --- | --- |
| Unix installer (`curl \| bash`) | Rich flags, platform detection, preflight, verify, fallback, PATH/completions | Provide `install.sh` with deterministic flag contract, idempotent reruns, explicit remediation on failure | planned | `bd-2j5.2`, `bd-2j5.3`, `bd-2j5.4`, `bd-2j5.5`, `bd-2j5.6` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Windows installer parity | PowerShell installer with same integrity guarantees | `install.ps1` parity with checksum verification, rollback-ready install flow | planned | `bd-2j5.16`, `bd-2j5.3`, `bd-2j5.4` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Artifact resolution contract | Deterministic target/platform resolution | Canonical resolver for OS/arch/artifact naming shared by install/update paths | implemented | `bd-2j5.3` | unit: `bd-2j5.19`; e2e: `bd-2j5.14` |
| Supply-chain verification | SHA256 default, optional Sigstore | Verify-by-default for official artifacts; explicit `--no-verify` bypass path with warning and logs | implemented | `bd-2j5.4`, `bd-2j5.13` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| From-source fallback | Build from source when binary path fails | Controlled fallback mode with prerequisite checks and clear performance caveats | planned | `bd-2j5.5` | unit: `bd-2j5.19`; e2e: `bd-2j5.14` |
| Post-install automation | PATH + shell completion setup + verification | Auto-wire PATH/completions with reversible edits and post-install validation checks | planned | `bd-2j5.6` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; docs: `bd-2j5.15` |
| AI integration bootstrap | Auto-configure host tools with backup/merge semantics | Backup-first integration mutations and deterministic repair of stale snippets | planned | `bd-2j5.7`, `bd-2j5.21` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Update orchestration | Check/apply/pin/list/rollback/system-user controls | `sbh update` supports check/apply/pin/list/rollback with non-interactive support | planned | `bd-2j5.8`, `bd-2j5.9`, `bd-2j5.10` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Update cache + notices | Cached metadata + controlled prompts | Cached index refresh and user/CI-friendly notice policy with opt-out controls | planned | `bd-2j5.9` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Backup + rollback | Update safety with retention policy | Automatic backup before mutation; bounded retention; deterministic rollback semantics | planned | `bd-2j5.10` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| First-run wizard | Guided bootstrap + automation | Interactive wizard plus `--auto` non-interactive mode with explicit defaults | planned | `bd-2j5.11` | unit: `bd-2j5.19`; e2e: `bd-2j5.14` |
| Model/assets bootstrap | Fetch + verify runtime assets | Download/verify/cache workflow with resumability and deterministic cache layout | planned | `bd-2j5.12`, `bd-2j5.20` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Release artifact contract | Stable release assets + checksums/signatures | Publish predictable archives + `.sha256` (+ optional sigstore bundle) for installer/updater compatibility | planned | `bd-2j5.13` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; docs: `bd-2j5.15` |
| End-to-end matrix | Happy path + failure injection | Installer/update/bootstrap/uninstall scenarios with artifacted traces on failure | planned | `bd-2j5.14` | e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Operator handbook | Troubleshooting + security model | Single handbook for operators/agents with policy defaults, bypass guidance, and failure playbooks | planned | `bd-2j5.15` | docs: `bd-2j5.15` |
| Uninstall parity | Safe cleanup + optional purge | `sbh uninstall` supports dry-run/confirm/purge tiers and rollback-safe teardown | planned | `bd-2j5.17` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Structured observability | Phase-level diagnostics | Trace-ID correlated start/success/failure events for install/update flows | planned | `bd-2j5.18` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |
| Unit-test matrix | Coverage of installer/update internals | Dedicated deterministic unit suite with explicit schema/behavior contracts | planned | `bd-2j5.19` | unit: `bd-2j5.19` |
| Offline/airgapped mode | Limited parity in dcg; desired for sbh | Offline bundle flow for installer/update/assets using local artifact manifests | planned | `bd-2j5.20` | unit: `bd-2j5.19`; e2e: `bd-2j5.14` |
| Migration + self-heal | Repair stale footprints | Detect and repair partial/legacy installs with backup-first mutation model | planned | `bd-2j5.21` | unit: `bd-2j5.19`; e2e: `bd-2j5.14`; logs: `bd-2j5.18` |

## Explicit CLI/Flag Contract

All flags below are contract-level and must be kept stable unless the parity matrix is updated and linked beads are revised.

### Install (`sbh install` and installer scripts)

| Flag | Meaning | Expected Behavior |
| --- | --- | --- |
| `--version <semver\|tag>` | Pin specific release | Installs exact requested version or fails with explicit reason |
| `--dest <path>` | Override install destination | Uses destination with same verification and rollback guarantees |
| `--easy` | Opinionated defaults mode | Enables safe defaults + non-interactive prompts where possible |
| `--verify` / `--no-verify` | Integrity policy | `--verify` default; `--no-verify` allowed only with warning + logged reason code |
| `--from-source` | Compile fallback | Builds from source when artifacts unavailable/unsupported |
| `--offline <bundle>` | Airgapped source | Uses local bundle metadata and artifacts only |
| `--quiet` | Minimal output | Suppresses non-error human logs |
| `--no-color` | Disable ANSI output | Forces plain-text output |
| `--no-configure` | Skip integrations | Installs binary only, no shell/tool bootstrap |
| `--json` | Machine output mode | Emits structured events/payloads for automation |

### Update (`sbh update`)

| Flag | Meaning | Expected Behavior |
| --- | --- | --- |
| `--check` | Check for update only | No mutation; report available versions |
| `--refresh-cache` | Force metadata refresh | Bypasses cached index data |
| `--force` | Apply despite soft guards | Still obeys hard safety constraints and logs override reason |
| `--rollback [version]` | Roll back to prior backup/version | Restores selected backup with verification |
| `--list-versions` | Show available versions | Deterministic sorted version list |
| `--pin <version>` | Pin active version | Sets/update pin and enforces on future checks |
| `--system` / `--user` | Scope selection | Chooses install root and privilege model |
| `--json` | Machine output mode | Phase-level structured output with trace ID |

### Bootstrap (`sbh bootstrap` or install-time integration phase)

| Flag | Meaning | Expected Behavior |
| --- | --- | --- |
| `--auto` | Non-interactive bootstrap | Applies safe defaults for unattended workflows |
| `--integrations <list>` | Restrict integration targets | Applies only selected tool integrations |
| `--no-integrations` | Skip all integrations | Bootstrap without config mutation |
| `--backup-dir <path>` | Backup location override | Stores reversible snapshots before mutation |
| `--json` | Machine output mode | Emits migration + bootstrap event records |

### Uninstall (`sbh uninstall`)

| Flag | Meaning | Expected Behavior |
| --- | --- | --- |
| `--dry-run` | Preview actions | No mutation; prints/returns deterministic uninstall plan |
| `--purge` | Remove data/logs/cache | Performs full teardown after explicit confirmation |
| `--keep-config` | Preserve configs | Removes binaries/services while retaining user config |
| `--rollback` | Restore previous install state | Reinstalls from latest valid backup snapshot |
| `--json` | Machine output mode | Structured uninstall events and reason codes |

## Security Policy Contract

| Policy Area | Default | Allowed Override | Required Logging |
| --- | --- | --- | --- |
| Artifact integrity verification | enabled | `--no-verify` | reason code + operator-visible warning |
| Signature verification (sigstore) | opportunistic/required per policy bead | explicit opt-out when policy allows | verification result, digest, signature status |
| Network trust | release source allowlist | explicit alternate source flag | source URL, trust policy decision |
| Update rollback safety | backup-first mandatory | none | backup ID, retention decision, rollback viability |
| Destructive uninstall behaviors | off by default | `--purge` only | preflight summary + final mutation report |

## Linked Gaps and Dependency Assertions

- This matrix maps every identified parity gap to at least one child bead in epic `bd-2j5`.
- Primary dependency chain unlocked by `bd-2j5.1`:
  - `bd-2j5.1` -> `bd-2j5.3` (artifact resolution contract)
  - `bd-2j5.1` -> `bd-2j5.2` (Unix installer implementation)
  - `bd-2j5.1` -> `bd-2j5.16` (Windows installer parity)
- Cross-cutting quality gates are fixed:
  - unit correctness: `bd-2j5.19`
  - end-to-end behavior: `bd-2j5.14`
  - observability contract: `bd-2j5.18`

## Divergences from dcg (Intentional)

| Area | dcg Behavior | sbh/fsfs Divergence | Rationale |
| --- | --- | --- | --- |
| Asset bootstrap | limited | includes model/asset bootstrap and offline bundles | sbh runtime may require additional artifacts |
| Migration scope | narrower | explicit self-healing of partial installs/integrations | multi-agent environments drift frequently |
| First-run mode | installer-centric | explicit wizard + `--auto` dual path | support both human and agent operators |

## Exit Criteria for `bd-2j5.1`

- Matrix maintained in-repo (this file) and referenced by downstream beads.
- CLI/flag/security/test contracts are explicit and implementation-ready.
- No parity capability remains unclassified (`implemented/planned/deferred/n/a`).
- Every planned capability maps to concrete bead(s) and validation gates.
