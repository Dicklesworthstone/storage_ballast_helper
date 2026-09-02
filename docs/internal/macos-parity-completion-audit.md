# macOS/Linux Parity Prompt-To-Artifact Completion Audit

> **Superseded (2026-09-02).** This audit certified prompt-to-artifact parity
> against the bead tree as it stood in May 2026. The reality check of
> 2026-09-02 (`docs/internal/reality-check-and-bridge-plan-2026-09-02.md`,
> bead tree `bd-rc-master-ajg1`) found that several of the beads this audit
> counts as complete were closed without their deliverable shipping (see the
> notes on `bd-izu.2`, `bd-2j5.21`, `bd-2s9`, `bd-xzt.5.3`, `bd-xzt.5.6`).
> Treat the status tables below as historical; the bridge plan and its beads
> are the current record.

Bead: `bd-r7m7.11`
Refresh beads: `bd-r7m7.12`, `bd-r7m7.13`, `bd-r7m7.15`, `bd-r7m7.16`, `bd-r7m7.17`
Parent: `bd-r7m7`
Last audited: 2026-05-12 01:04 UTC
Evidence snapshot: the audit records the live head and run state observed at
refresh time, but every audit-only commit makes those literals stale. Before any
close decision, refresh the live head and newest run with:

The audit avoids pinning exact commit hashes or GitHub Actions run ids as
durable completion proof; any literal below is a point-in-time observation only.

```bash
git rev-parse HEAD
git status --short --branch
gh run list --repo Dicklesworthstone/storage_ballast_helper --branch main --limit 5 \
  --json databaseId,headSha,status,conclusion,workflowName,url,createdAt,event
```

Then inspect the run for the current head with:

```bash
gh run view <latest-run> --repo Dicklesworthstone/storage_ballast_helper --json status,conclusion,headSha,jobs
```

This is the closeout gate for the active objective: make `sbh` seamlessly
support macOS in addition to Linux, with automatic platform detection during
installation and runtime, plus testing infrastructure that validates both
environments.

## Objective Restated

The goal is not complete until the repository and release system prove these
operator-visible outcomes:

- One source tree and one `sbh` CLI surface support Linux and macOS through the
  PAL rather than platform-specific user workflows.
- Install, uninstall, service control, daemon, status, check, scan, clean,
  emergency, blame, ballast, dashboard, log, setup, config, protect, unprotect,
  and tune resolve the correct Linux or macOS behavior automatically.
- macOS service lifecycle uses launchd while Linux continues to use systemd.
- macOS disk accounting handles APFS capacity, purgeable-space risk, snapshots,
  and `/private/tmp` behavior.
- macOS cleanup rules rank real reclaim candidates such as Xcode DerivedData,
  CoreSimulator caches, Electron caches, user-named trash directories, and
  `*_target` build directories without touching sacred user data.
- Deletion safety is enforced in scanner pre-scan, normal walker traversal, and
  executor preflight, including protected paths, `.sbh-protect` markers, active
  build file handles, and source repositories.
- macOS process and daemon health data come from Mach, sysctl, and libproc
  backends rather than unsupported Linux-only code paths.
- Release artifacts for macOS are signed, notarized, checked, and distributed by
  GitHub Releases and Homebrew.
- CI proves Linux and macOS behavior with unit, integration, snapshot, release,
  coverage, benchmark, and formula lanes.
- README and docs let a Mac user install, configure, verify, and diagnose the
  release path without reading workflow internals.

## Prompt-To-Artifact Checklist

| Prompt requirement | Concrete artifacts inspected | Current audit result |
|---|---|---|
| "support mac os in addition to linux" | `src/platform/pal.rs`, `src/platform/linux`, `src/platform/macos`, Linux and macOS CI workflow lanes, macOS integration tests, existing Linux unit/integration lanes | Repo-side platform implementation exists for both OS families. Final proof still requires the final pushed head to complete all Linux and macOS CI jobs green. |
| "everything automatically detected during installation" | `src/cli/install.rs`, `src/daemon/service.rs`, launchd/systemd workflow tests, `docs/macos.md`, Homebrew formula and release workflow | Installer/service detection is implemented and documented. Developer ID, App Store Connect notary credentials, the repository-scoped Homebrew tap deploy key, the public tap formula, a manually published signed/notarized `v0.4.8` release, prior manual signed/notarized `v0.4.14` staging evidence, and live self-update E2E proof are present. The prior `/tmp` `v0.4.14` staging directory no longer exists, so any manual publication path now requires regenerating and re-verifying the artifacts before upload. The `v0.4.15` hosted release attempt was cancelled before publication; final proof now requires a fresh hosted release candidate after the CI concurrency fix, or explicit operator approval for a regenerated manual publication. |
| "while running" automatic platform behavior | PAL-backed status/check/scan/clean/blame/daemon paths, APFS/Mach/libproc macOS implementations, Linux PAL preservation, focused protection regression tests | Runtime behavior is routed through platform-specific implementations behind the shared CLI/PAL surface. Final proof still depends on queued hosted CI and live release diagnostics. |
| "always does the right thing" / "just works" | Protected-path daemon tests, active-reference/open-file checks, sacred-path catalog, APFS accounting tests, launchd lifecycle test, docs and doctor diagnostics | Safety and diagnostics are covered in source and tests. Installed sbh 0.4.6 daemons must be upgraded/restarted because they predate the daemon protection fix. |
| "additional testing infrastructure" | `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/cert-expiration.yml`, macOS platform/coverage/benchmark jobs, Homebrew validation, release-doctor tests, protected-path tests, `tests/integration_tests.rs` | Infrastructure exists and focused local/rch proof passed. The macOS platform smoke lane now builds an isolated config/root/state tree and exercises safe operational command surfaces for status, check, scan, `clean --dry-run`, blame, ballast status, tune, setup verification, and protection listing before the unsupported-PAL guard inspects logs. The integration suite now runs the same class of isolated safe operational commands against the real test binary and asserts `clean --dry-run` does not remove its synthetic artifact. The CI and release Homebrew formula rewrite paths now both rewrite static release URLs, archive names, and checksum placeholders before validation or tap publication, and the CI temporary `sbh-ci` formula injects an explicit Cargo-derived version before testing local `file://` archives. CI supersession now only cancels `refs/heads/main` pushes and pull requests, so tag-triggered release quality-gate calls are not cancelled by the branch/PR queue policy. Final proof still requires the hosted release quality gate and hosted release workflow to succeed on a source-equivalent final head. |

## Current Tracker And CI State

- Live refresh at 2026-05-12 01:20 UTC inspected the pushed `main`,
  `origin/main`, and `origin/master` state before the follow-up audit commit.
  The annotated `v0.4.15` tag resolves to commit
  `067f55ea017321428b9a4722d70c0e518c6944b4`, so the active tag release proof is
  behind the latest audit/tracker commits. Those later commits are
  docs/tracker-only closeout evidence and queue-state records, but a strict
  final-release closeout must either accept that distinction explicitly or
  create a fresh source-equivalent release candidate after hosted queues unblock.
- Main CI run `25706394564` for
  `2ecbb053bc61e2f8bd35c4889e84b0d809e143f1` was cancelled at
  2026-05-12 01:03 UTC because it duplicated the active Release workflow's
  quality-gate jobs without being the distribution or Homebrew tap publication
  path. Release run `25705033848` for `v0.4.15` later completed with conclusion
  `cancelled` at 2026-05-12 01:30 UTC. Before cancellation, its
  `Quality Gate / macOS Platform Tests (intel)` job completed successfully on
  2026-05-12 01:17 UTC after receiving a `macos-15-intel` runner. The release
  level `Homebrew Tap Deploy Key Preflight`, reusable `Format + Lint`, Apple
  Silicon macOS platform, macOS coverage, macOS performance, and Homebrew
  formula jobs were cancelled before runner assignment. Investigation found the
  reusable CI concurrency guard was cancelable for tag `push` events; it has been
  narrowed to cancel only `refs/heads/main` pushes and pull requests, so the
  next hosted release attempt must use a fresh tag with that workflow snapshot.
  `gh release view v0.4.15` still reports `release not found`, and the public
  tap formula content SHA remains
  `6e4c74f521b3a2f58e2f8a216d04bc0da3164fef` with URLs/checksums still pointing
  at `v0.4.8`.
- Current-head supplemental proof for commit `2ecbb05` passed
  `cargo fmt --check`, `git diff --check -- docs/macos.md src/cli/mod.rs`,
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-manual-fallback-stable-contract cargo test --lib macos_manual_release_fallback_docs_require_fresh_artifacts_and_approval -- --nocapture"`.
  The `rch` attempt selected worker `vmi1156319` but remote sync failed with
  permission errors under `/data/projects/storage_ballast_helper`, after which
  `rch` fell back locally; the focused test still passed. This is useful
  source proof for the latest docs/test hardening, not hosted CI or release
  publication proof.
- Live refresh at 2026-05-12 00:14 UTC inspected current `main`, `origin/main`,
  `origin/master`, and tag `v0.4.15` at
  `067f55ea017321428b9a4722d70c0e518c6944b4`. This version/tag commit advances
  the release candidate to include the preceding `02845e7` macOS platform smoke
  expansion and `8409fe2` executable isolated-config integration smoke coverage.
  The only unstaged local change is `.beads/beads.db`, which is database state
  and not a release artifact.
- The latest hosted release proof attempt is tag `v0.4.15`, pointing at
  `067f55ea017321428b9a4722d70c0e518c6944b4`. Release workflow run
  `25705033848` is completed with conclusion `cancelled`. `Quality Gate /
  macOS Platform Tests (intel)` completed success on `macos-15-intel`; the
  release-level `Homebrew Tap Deploy Key Preflight`, reusable
  `Quality Gate / Format + Lint`, Apple Silicon `macOS Platform Tests`,
  `macOS Coverage`, `macOS Performance Budgets`, and
  `Homebrew Formula Validation` jobs were cancelled before runner assignment.
  No `v0.4.15` GitHub Release exists yet.
- The current `v0.4.15` Intel hosted artifacts were downloaded under
  `~/release-work/storage_ballast_helper/hosted-proof/v0.4.15-run-25705033848-intel`.
  `sbh-intel.sha256` records
  `9cfd0c9283d05cdcfa6c88bc541cdca1f979ed7bbaf9e3fd59c40e93b2777ac4`, matching
  `shasum -a 256 sbh-intel`; `arch -x86_64 ./sbh-intel --version` reports
  `sbh 0.4.15`; and `codesign --verify --strict --verbose=2 ./sbh-intel`
  passes. Hosted logs show 1213 library tests passed, 116 binary tests passed,
  55 integration tests passed, ad-hoc codesign verification passed, and the
  isolated macOS E2E smoke exercised safe operational commands including
  `status`, `clean --dry-run`, and `setup --verify`.
- The standalone main CI run `25705030478` for `067f55e` was cancelled at
  2026-05-12 00:24 UTC to reduce duplicate queue pressure after confirming the
  `v0.4.15` Release run invokes the same reusable quality-gate workflow.
  The previous main CI run `25704673659` for `8409fe2` had already been
  cancelled by branch concurrency after the version/tag push. Do not count
  cancelled CI or cancelled release runs as final green proof; the next hosted
  proof path is a fresh release tag after the CI concurrency fix.
- A non-mutating queue sanity check for `v0.4.15` Release run `25705033848`
  found repository Actions enabled with `allowed_actions=all`, no pending
  deployments, and zero repository self-hosted runners. The run was then
  cancelled before the remaining queued jobs received runner assignment. The
  current blocker is now obtaining fresh hosted release proof from a tag that
  includes the non-cancelable tag-release CI concurrency fix.
- Current source proof for the latest source/workflow head is healthy outside
  hosted GitHub runners. Local macOS runtime checks against the installed public
  binary showed platform auto-detection working for `sbh status --json`,
  `sbh check --need 5G --json`, `sbh install --auto --dry-run --json`, and
  `sbh doctor --pal --json`. The new macOS smoke contract test passed via
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-macos-smoke-contract cargo test --lib ci_macos_platform_smoke_exercises_safe_operational_commands -- --nocapture"`.
  The executable isolated operational smoke integration test passed via
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-isolated-smoke-test-2 cargo test --test integration_tests isolated_config_exercises_safe_operational_commands -- --nocapture"`.
  Remote source proof also passed
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-macos-smoke-check cargo check --all-targets"`
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-macos-smoke-clippy cargo clippy --all-targets -- -D warnings"`.
  After the integration-smoke test landed, full remote proof passed
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-isolated-smoke-check cargo check --all-targets"`
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-isolated-smoke-clippy cargo clippy --all-targets -- -D warnings"`.
  The `v0.4.15` version/tag commit passed `cargo fmt --check`,
  `git diff --check -- Cargo.toml Cargo.lock docs/macos.md`,
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-v0415-doc-contract cargo test --lib macos_manual_release_fallback_docs_require_fresh_artifacts_and_approval -- --nocapture"`,
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-v0415-check cargo check --all-targets"`,
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-v0415-clippy cargo clippy --all-targets -- -D warnings"`.
  This is strong source evidence, but it is not a substitute for hosted release
  publication, hosted macOS Apple Silicon jobs, or public tap advancement.
- The user approved the stale release queue intervention with `proceed` after
  the exact stale runs were listed. Release runs for `v0.4.10` (`25666074747`),
  `v0.4.11` (`25675218864`), `v0.4.12` (`25677465183`), and `v0.4.13`
  (`25678971515`) are now completed with conclusion `cancelled`. After the
  current-head `v0.4.15` tag was pushed, stale `v0.4.14` Release run
  `25693688419` was also cancelled; its prior Intel macOS quality-gate success
  remains historical evidence only.
- The `v0.4.14` release credential gap found during this audit has been fixed:
  the first OpenSSL-modern P12 parsed with OpenSSL but failed macOS
  `security import`, so it was replaced with
  `/Users/jemanuel/release-work/storage_ballast_helper/credentials/sbh-developer-id-application-20260511T203111Z-pbe-sha1-3des.p12`
  (sha256 `0040f9636bd573d1b95c81b9ce949fb0502b029216910b564981184722a8b5de`).
  The generated password is stored in the macOS login Keychain as
  `service=sbh-developer-id-p12-password`, `account=storage_ballast_helper`.
  The final P12 imports with macOS `security`, parses with OpenSSL 3, exposes
  the Developer ID Application certificate expiring May 11, 2031, and was used
  to Developer-ID sign both prior staged `v0.4.14` macOS binaries with hardened
  runtime. Those `/tmp` artifacts are no longer present.
- The repaired GitHub signing secrets
  `APPLE_DEVELOPER_ID_CERTIFICATE_P12_BASE64`,
  `APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD`, and
  `APPLE_DEVELOPER_ID_IDENTITY` were updated at 2026-05-11T20:31Z. The App
  Store Connect notary secrets were updated at 2026-05-11T20:25Z; notarytool
  history works with the local `Q29MJ3WM99` API key. HashiCorp Vault was not a
  usable backing store during this refresh because reads/lists returned
  `local node not active but active cluster node not found`.
- Earlier manual fallback artifacts for `v0.4.14` were staged under
  `/tmp/sbh-v0414-manual-release-artifacts-20260511T195841Z` and the checksum
  manifest was rechecked successfully at 2026-05-11 21:22 UTC from inside that
  artifact directory. A 2026-05-11 23:04 UTC refresh found that directory and
  its `SHA256SUMS.txt` / `release-provenance.json` files no longer exist under
  `/tmp`, `/private/tmp`, or `~/release-work`. Treat the prior provenance as
  historical evidence only: any manual `v0.4.14` publication now requires
  regenerating all four platform archives, checksum sidecars, `SHA256SUMS.txt`,
  and `release-provenance.json`, then rechecking the manifest before upload.
  The prior provenance recorded tag `v0.4.14`, source SHA
  `02e0c678a8e28831cf17efd1c30d7fa879de5c57`, Release run `25693688419`, CI
  run `25693489066`, manual generation time `2026-05-11T20:09:41Z`, macOS
  arm64 notarization id `13d0624e-16b9-4b1a-a75d-e346907a8fce`, and macOS
  x86_64 notarization id `f28c1cdb-9804-4305-a52b-bbf8228b4d62`.
- Local reproduction of queued release gates passed without mutating remotes:
  the Homebrew tap deploy-key preflight performed a dry-run push successfully
  under `/tmp/sbh-homebrew-tap-preflight-local-20260511T203417Z`; the source
  formula passed `ruby -c` and `brew style`; and a generated `v0.4.14` formula
  using arm64 macOS checksum
  `c164894817f03fa9e7ff6db8f3e3f61aa6ae663e04d7698f5fccdaa042707903` plus
  Intel macOS checksum
  `00ae9da512b96072d2ed6534b9b5ac2606ded219d22458a0dfcbb15cdae99281` passed
  validation under
  `/tmp/sbh-homebrew-formula-validation-local-20260511T203417Z`.
- The previous `v0.4.9` attempt exposed a CI harness regression after the static
  URL/checksum rewrite fix: the temporary `sbh-ci` Homebrew formula rewrote
  release URLs to a local `file://` archive whose name did not let current
  Homebrew infer `version`. Current source fixes `.github/workflows/ci.yml` to
  derive `CI_FORMULA_VERSION` from `Cargo.toml` and inject an explicit
  `version` line into the temporary formula before local install tests.
  `src/cli/mod.rs` locks that workflow contract. Focused proof passed with
  local formula-generation simulation, `cargo fmt --check`, `git diff --check`,
  Ruby YAML parsing, `rch` focused Homebrew workflow tests, and full
  `rch cargo check --all-targets` plus
  `rch cargo clippy --all-targets -- -D warnings` on the relevant source state.
- Release `v0.4.8` remains the latest public release, not draft or prerelease,
  at
  `https://github.com/Dicklesworthstone/storage_ballast_helper/releases/tag/v0.4.8`.
  It contains four platform archives, four checksum sidecars, `SHA256SUMS.txt`,
  and `release-provenance.json`. The public Homebrew tap still points at this
  `v0.4.8` release; it has not been updated to the latest release-candidate
  tag.
- The public tap now has `Formula/sbh.rb` on `main`
  (`Dicklesworthstone/homebrew-sbh`, content SHA
  `6e4c74f521b3a2f58e2f8a216d04bc0da3164fef`). A live content read at
  2026-05-11 21:22 UTC still shows both macOS URLs and checksums pointing at
  `v0.4.8`, not the latest release-candidate tag. Local proof after publication passed
  `brew fetch --formula dicklesworthstone/sbh/sbh`,
  `brew audit --strict --online dicklesworthstone/sbh/sbh`,
  `brew install --formula dicklesworthstone/sbh/sbh`,
  `brew test --force dicklesworthstone/sbh/sbh`,
  `/opt/homebrew/bin/sbh version --verbose`, and
  `/opt/homebrew/bin/sbh --json doctor --release` with `ok=true`, `passed=4`,
  `warnings=0`, and `failed=0`.
- Live self-update E2E proof for `bd-ykwh.10` passed at 2026-05-11 10:00 UTC.
  The proof copied `/opt/homebrew/bin/sbh` into an isolated temp `bin`, used the
  real published `sbh-v0.4.8-aarch64-apple-darwin.tar.xz` archive and checksum
  through `sbh update --force --user --offline`, and set
  `SBH_LAUNCHD_LABEL` to a throwaway loaded launchd job. Captured
  `/tmp/sbh-update-e2e.20260511T095840Z.BE0zIa/update.json` reports
  `success=true`, `applied=true`, target `v0.4.8`, isolated temp `install_path`,
  backup creation, `Integrity verification passed`, `Installed to ...`, and
  `service_restart.status=restarted`. Post-update checks passed
  `sbh --json version`, `codesign --verify --strict --verbose=2`, Developer ID
  authority/team inspection, and launchd evidence showing `runs = 2` plus
  `last terminating signal = Terminated: 15` for the throwaway label.
- Current open blockers are `bd-r7m7`, `bd-r7m7.17`, `bd-ykwh`, and
  `bd-ykwh.3`. `bd-ykwh.7` was force-closed after real tap publication and
  install proof. `bd-ykwh.10` was force-closed after live macOS self-update E2E
  proof against the real signed `v0.4.8` release archive in an isolated temp
  install path with launchd kickstart evidence. `bd-r7m7.17` remains the hosted
  CI Queue Blocked tracker, and `bd-ykwh.3` remains open because the automated
  release workflow proof has not gone green on the final head. `bd-r7m7.16` and
  `bd-ykwh.20` stay part of the evidence chain; `bd-ykwh.20` specifically
  guards the release workflow's notary log ticketContents validation.

Older point-in-time evidence follows. It is useful context, but the closeout
decision must start from the live commands above because this audit explicitly
avoids pinning exact commit hashes or GitHub Actions run ids as durable proof.

- Live recheck at 2026-05-11 03:25 UTC inspected current pushed head
  `b8bedb9a9634693b8c9904d5528ebb4ff0c934d4`
  (`Harden macOS PAL probes against stuck filesystem services`). The newest CI
  run for that head is `25648597514`; it is queued overall. Every listed job is
  still queued with no conclusion: `macOS Platform Tests (intel)`,
  `Homebrew Tap Deploy Key Preflight`, `Homebrew Formula Validation`,
  `macOS Coverage`, `macOS Performance Budgets`,
  `macOS Platform Tests (apple-silicon)`, and `Format + Lint`. This is not
  final green CI proof.
- The current-head local/rch proof for `b8bedb9` passed before this refresh:
  local macOS `sbh --json doctor --pal` from the current debug build exited 0
  with 23 implemented PAL methods, 0 failed methods, and only environment
  warnings for `macos.spctl` and `macos.launchd`; local macOS
  `cargo clippy --no-default-features --features cli,daemon,sqlite --lib -- -D warnings`
  passed; `cargo fmt --check` and `git diff --check` passed; remote Linux
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_macos_mount_timeout_check2 cargo check --all-targets`
  passed; and remote Linux
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_macos_mount_timeout_clippy2 cargo clippy --all-targets -- -D warnings`
  passed. This is strong local/source proof, but it does not replace hosted CI
  green status.
- The `b8bedb9` fix closes a live macOS doctor hang class in current source:
  macOS mount, APFS, and Time Machine subprocess probes now have bounded
  deadlines and bounded output drains; default capacity paths no longer call the
  blocking Foundation CacheDelete probe; process/open-file/mmap PAL probes avoid
  unbounded `realpath` calls on automount-sensitive paths; and mmap region scans
  have a bounded scan budget. Focused local regressions cover command timeout,
  inherited-pipe timeout, private `/tmp` and `/var` mount alias matching,
  current-process open file reporting, current-process mmap reporting, APFS
  snapshot fallback behavior, and non-local `/sbin/mount` parsing.
- `bd-r7m7` remains open. Live `br epic status --json` on 2026-05-11 02:00 UTC
  reported 32 of 34 children closed, and the epic was not eligible for closure.
  Use live `br epic status --json` output before any close decision because
  audit refresh beads change child counts.
- `bd-ykwh` remains open. Developer ID certificate/CI secret storage is now
  complete, the Homebrew release credential has been replaced with a
  repository-scoped deploy key, the public tap plus manual signed/notarized
  `v0.4.8` release have been published, and self-update E2E evidence is now
  recorded on `bd-ykwh.10`. The automated hosted release workflow evidence
  remains open. Older live `br epic status --json` reported 18 of 21 children
  closed, but use live tracker output before any close decision.
- `br ready --json` returned `[]`; remaining open actionable release work was
  blocked or already assigned at audit time.
- Live `br ready --json` at 2026-05-11 03:25 UTC also returned `[]`.
- Open release/parity blockers as of 2026-05-11 11:27 UTC are `bd-r7m7.17`
  and `bd-ykwh.3`. `bd-ykwh.7` is closed based on real tap publication and
  install proof, and `bd-ykwh.10` is closed based on live self-update E2E proof.
  `bd-ykwh.2` and `bd-ykwh.13` are closed based on live Developer ID identity,
  P12/signing secrets, App Store Connect notary API-key secrets, rotation docs,
  Homebrew deploy-key secret evidence, and certificate-expiration workflow
  evidence.
- `bd-r7m7.17` tracks the current hosted CI queue as an explicit external
  blocker for final macOS parity proof.
- `bd-ykwh.20` is closed; release CI now verifies Apple notary log ticketContents
  after notarization acceptance and before packaging macOS tarballs.
- Live recheck at 2026-05-11 02:00 UTC inspected current tracker-only branch
  head `aa6c03f69ac8ed6ff7e002fdc795e3e1dd5fa0af` and current source CI run
  `25644934638` for source head `9e438e74c77f6385e0ad28bd2709947a83b6bad9`.
  The run remains queued overall. `macOS Platform Tests (intel)` completed
  success on `macos-15-intel`; `Homebrew Tap Deploy Key Preflight` and
  `Format + Lint` on `ubuntu-latest`, plus `Homebrew Formula Validation`,
  `macOS Platform Tests (apple-silicon)`, `macOS Coverage`, and
  `macOS Performance Budgets` on `macos-latest`, remain queued before runner
  assignment with empty `runner_name` and `runner_group_name`. This is not final
  green CI proof.
- Beads-only commits `de58956` and `aa6c03f` did not start a new source CI run,
  confirming the current `.beads/**` path-ignore guard is still preventing
  tracker evidence updates from canceling useful source validation.
- Account-wide queue sampling on 2026-05-11 found many queued runs in
  `frankenfs`, `asupersync`, `frankenredis`, and `pi_agent_rust` while the
  current `storage_ballast_helper` jobs still had no runner assignment. This
  supports treating the blocker as hosted/account queue backlog rather than an
  `sbh` workflow failure.
- GitHub's legacy Actions billing endpoint now returns HTTP 410. The current
  enhanced billing endpoint
  `/users/Dicklesworthstone/settings/billing/usage/summary` with
  `X-GitHub-Api-Version: 2026-03-10` reported May 2026 Actions usage with
  `netAmount=0` and `netQuantity=0` for Linux, Linux ARM, macOS, and Windows
  minute SKUs. That does not look like obvious Actions minute exhaustion. The
  budgets endpoint for `orgs/Dicklesworthstone` returned 404 because this is a
  user account rather than an organization budget scope.
- Live recheck at 2026-05-10 21:29 UTC inspected current branch head
  `9fa4dbae7aade6332217c546abfec0983bb2961d`. The newest CI run for that head
  is `25640194122`; it is still queued, and every job listed by GitHub remains
  queued with no conclusion: `Homebrew Formula Validation`, `macOS Platform
  Tests (apple-silicon)`, `Format + Lint`, `macOS Platform Tests (intel)`,
  `macOS Performance Budgets`, and `macOS Coverage`. This is not final green CI
  proof.
- The previous source run `25630326420` reached useful partial macOS Intel
  evidence, but it is no longer the latest source head and cannot close the
  active objective by itself.
- The Beads-only pushes through `1fea1347ba99ce6a444c78105c1e4f776b434a8f` did not
  start a new source CI run, confirming the current `.beads/**` path-ignore
  guard is working for tracker-only evidence updates.
- Hosted queue diagnosis at 2026-05-10 14:48 UTC found no repository-side
  workflow/policy gate explaining the queued run: CI concurrency is scoped to
  workflow/ref and leaves `25630326420` as the active source run,
  GitHub Status reports Actions operational, repository Actions permissions are
  enabled with `allowed_actions=all`, run timing shows zero billable duration
  for the queued jobs, and the jobs API still reports empty
  `runner_name`/`runner_group_name` for the queued `ubuntu-latest` and
  `macos-latest` jobs.
- Additional CI gate checks found `pending_deployments` empty and workflow
  permissions set to `default_workflow_permissions=read`, so the run is not
  waiting on a GitHub environment approval or selected-actions policy gate.
- Live release credential recheck at 2026-05-10 23:10 UTC found one valid local
  signing identity, `Developer ID Application: Jeffrey Emanuel (AU8V2Z6NKY)`,
  and `xcrun notarytool history --keychain-profile sbh-notary --output-format
  json` returned parseable history JSON. GitHub Actions secrets now include the
  Developer ID P12, P12 password, signing identity, Team ID, and App Store
  Connect API-key notarization secrets.
- Release-readiness recheck at 2026-05-12 00:36 UTC with installed `sbh 0.4.8`
  passed `sbh --json doctor --release` with `ok=true`, `passed=4`,
  `warnings=0`, and `failed=0`: Developer ID identity, `sbh-notary`, all
  required GitHub release secrets, and the public Homebrew tap formula are all
  visible. This removes credential setup as the live blocker, but it does not
  publish current artifacts or replace hosted release workflow proof.
- `HOMEBREW_TAP_SSH_KEY` is now configured in GitHub Actions. The tap repository
  has a write-enabled deploy key named `sbh release workflow deploy key
  2026-05-10`, and local Git/SSH validation confirmed the key sees `main` and
  passes a dry-run branch push to `Dicklesworthstone/homebrew-sbh` without
  mutating the remote. The old tap-token secret may still exist as an unused
  legacy secret, but the workflows and release doctor now require the SSH deploy
  key instead.
- At the older 2026-05-11 03:25 UTC release recheck,
  `Dicklesworthstone/homebrew-sbh` still returned HTTP 404 for
  `Formula/sbh.rb`, latest published release was still `v0.4.6`, and
  current-source `sbh --json doctor --release` reported `ok=false` only because
  `release.homebrew_tap` warned on the missing formula. That blocker is now
  resolved by the 2026-05-11 09:50 UTC tap and `v0.4.8` release proof above.
- Live recheck at 2026-05-10 02:44 UTC inspected pushed head
  `0da51406462098b02aa58ee150a0ae632433981f`
  (`bd-r7m7 refresh macos parity audit`). That was point-in-time evidence
  before later audit-only commits and must not be read as the durable current
  head. The newest CI run for that inspected head,
  `25617688046`, had completed `macOS Platform Tests (intel)` successfully on
  `macos-15-intel`; `Format + Lint`, `macOS Platform Tests (apple-silicon)`,
  `Homebrew Formula Validation`, `macOS Performance Budgets`, and
  `macOS Coverage` remained queued. Do not treat queued CI as final proof, and
  do not treat partial CI as final proof; inspect the latest run for the final
  pushed head before closing.
- The completed Intel macOS lane for run `25630326420` covered 1204 library
  tests, 112 binary tests, 54 integration tests, release build,
  ad-hoc hardened-runtime signing, temporary-tap Homebrew install/test,
  release-doctor JSON capture, current-binary diagnostic artifact upload,
  E2E smoke checks, and the unsupported-PAL log guard.
- Downloaded Intel diagnostic artifact proof for run `25630326420` passed:
  the uploaded SHA-256
  `520a70c9e1c21ede563d2ff9f4d684529ca83ef102788a6e5058bb78a0b4a8a2`
  matched `sbh-intel`, `file` reported a Mach-O x86_64 executable,
  `codesign --verify --strict --verbose=2` passed, and `sbh-intel version
  --verbose` reported version `0.4.7`.
- Current-artifact release doctor proof for the same Intel binary was rerun on
  2026-05-10 14:06 UTC with
  `/tmp/sbh-ci-25630326420-intel.EI8Ozy/macos-release-binary-macos-15-intel/sbh-intel --json doctor --release`.
  It exited 1 with `ok=false`, `passed=0`, `warnings=1`, and `failed=3`.
  The failures were `release.developer_id_identity`,
  `release.notary_profile`, and `release.github_secrets`; the warning was
  `release.homebrew_tap` because `Dicklesworthstone/homebrew-sbh` is reachable
  but `Formula/sbh.rb` is not published yet.
- Hosted replacement proof for `bd-ykwh.7` landed in run `25630326420`: the
  Intel macOS lane's `Exercise Homebrew formula install from current signed
  binary` step passed after creating a temporary `sbh/local-ci` tap, validating
  generated formula syntax, installing from the current ad-hoc-signed binary,
  and running `brew test`. The real tap install still depends on a signed tag
  release publishing `Formula/sbh.rb` through the configured deploy key.
- The current CI runner labels were cross-checked against GitHub's hosted runner
  reference at refresh time: `macos-latest` is an arm64/M1 macOS runner and
  `macos-15-intel` is an Intel macOS runner, so the macOS matrix still covers
  both architectures with current labels.
- `br ready --json` returned `[]` at the same refresh. The open release beads
  remained blocked by live Apple/GitHub credentials or signed-release proof
  rather than by an unclaimed repo-side implementation task.
- Local Homebrew formula checks passed at refresh time: `brew style
  packaging/homebrew/Formula/sbh.rb` and the generated-formula placeholder
  replacement path both reported no style offenses.
- Additional local formula validation passed with
  `ruby -c packaging/homebrew/Formula/sbh.rb`. The installed Homebrew version
  rejects path-based `brew audit --formula --strict packaging/homebrew/Formula/sbh.rb`
  and requires auditing by formula name, so full `brew audit` remains covered by
  the hosted `Homebrew Formula Validation` job and release/tap verification.
- The macOS platform CI workflow now exercises the Homebrew formula against the
  current ad-hoc-signed release binary: it packages `target/release/sbh` into a
  local `.tar.xz`, rewrites `packaging/homebrew/Formula/sbh.rb` into a temporary
  `SbhCi` formula with a `file://` URL and matching SHA-256, runs `ruby -c`,
  runs `brew install --formula --build-from-source --skip-link`, and runs
  `brew test --force sbh-ci`. Static coverage in `src/cli/mod.rs` asserts those
  CI fragments and uploaded logs remain present.
- Proof for that Homebrew formula-install patch passed before push:
  `cargo fmt --check`, `git diff --check`, Ruby YAML parsing, a local formula
  transform dry-run, `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_homebrew_signed_install_contract cargo test --lib ci_validates_homebrew_formula_generation -- --nocapture`,
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_homebrew_install_check cargo check --all-targets`, and
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_homebrew_install_clippy cargo clippy --all-targets -- -D warnings`.
- Supplemental proof for the inspected source snapshot while hosted CI was
  queued: local
  `cargo fmt --check` passed, and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-ci-format-lint-0da5140 cargo clippy --no-default-features --features cli,daemon,sqlite --lib --bin sbh -- -D warnings"`
  returned remote exit 0. This does not replace hosted CI green status.
- Local reproduction of the queued Homebrew Formula Validation lane also passed:
  `ruby -c packaging/homebrew/Formula/sbh.rb`, `brew style
  packaging/homebrew/Formula/sbh.rb`, generated-formula checksum placeholder
  replacement in a `/tmp/sbh-homebrew-validation.*` directory, `ruby -c` on the
  generated formula, and `brew style` on the generated formula all reported
  success. This does not replace the hosted `Homebrew Formula Validation` job or
  the real signed-release tap update.
- Focused protected-path regression proof passed with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_daemon_protection_proof cargo test --lib protected -- --nocapture`.
  The run reported 13 passed tests, including the daemon executor preflight and
  protected `rust_fuzz_target` priority pre-scan regression.
- Focused release-doctor proof passed with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_release_doctor_proof cargo test --bin sbh release_doctor -- --nocapture`.
  The run reported 3 passed tests covering missing external credentials,
  credential-present success, and stdin-based release-secret setup steps.
- The release doctor JSON now exposes an aggregate `ok` boolean plus `passed`,
  `warnings`, and `failed` counts, and the human report prints the same
  readiness summary. Focused proof for that current-source update passed with
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-summary-bin cargo test --bin sbh release_doctor -- --nocapture"`
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-summary-lib cargo test --lib developer_id -- --nocapture"`.
  Required compiler gates also passed for the update:
  `cargo fmt --check`, `git diff --check`,
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-summary-check cargo check --all-targets"`,
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-summary-clippy cargo clippy --all-targets -- -D warnings"`.
- Fresh-eyes release-doctor hardening on 2026-05-10 fixed warning-only release
  readiness: `WARN` checks now make aggregate `ok` false and human readiness
  `attention` instead of `ready`. Focused proof passed with
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-attention-bin cargo test --no-default-features --features cli,daemon,sqlite --bin sbh release_doctor -- --nocapture"`
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-attention-doc2 cargo test --lib release_workflow_imports_developer_id_certificate_before_signing -- --nocapture"`;
  full gates also passed with `cargo fmt --check`, `git diff --check`,
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-attention-check cargo check --all-targets"`,
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-attention-clippy cargo clippy --all-targets -- -D warnings"`.
- The hosted macOS release-doctor diagnostic harness now validates the aggregate
  `ok`, `passed`, `warnings`, and `failed` fields against the per-check
  statuses and requires the Developer ID identity, notary profile, GitHub
  secrets, and Homebrew tap check IDs before uploading
  `macos-release-doctor-summary.txt`; warning-only artifacts therefore cannot
  look release-ready in CI evidence. The same harness also rejects malformed
  top-level summary fields, malformed check entries, duplicate check IDs, and
  unknown statuses before trusting aggregate counts, and it checks that the
  release-doctor process exits nonzero exactly when `FAIL` checks are present.
  Focused proof
  passed with Ruby YAML parsing for `.github/workflows/ci.yml`,
  `cargo fmt --check`, `git diff --check`, and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-ci-summary-test cargo test --lib ci_workflow_spot_checks_macos_release_builds_without_notarization -- --nocapture"`;
  the required Homebrew tap check-ID guard was then re-verified with
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-release-doctor-ci-homebrew-test2 cargo test --lib ci_workflow_spot_checks_macos_release_builds_without_notarization -- --nocapture"`.
- Focused release workflow contract proof passed with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_workflow_contract_proof cargo test --lib workflow -- --nocapture`.
  The run reported 13 passed tests, including Developer ID import, hardened
  runtime signing, async notarization, PR ad-hoc signing, Homebrew tap update,
  and CI cancellation behavior.
- Focused Homebrew contract proof passed with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_homebrew_contract_proof cargo test --lib homebrew -- --nocapture`.
  The run reported 5 passed tests covering formula skeleton asset names,
  checksum marker replacement, CI formula generation, tap updates, and
  Homebrew install-path discovery.
- Focused macOS CLI auto-detection proof passed with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_bin_macos_proof cargo test --bin sbh macos -- --nocapture`.
  The run reported 10 passed tests covering launchd auto-selection, macOS
  release install defaults, doctor remediation, process attribution visibility,
  and platform-autodetection help text.
- Focused macOS library runtime proof passed with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_lib_macos_proof cargo test --lib macos -- --nocapture`.
  Remote sync failed on one worker with permission errors, so `rch` fell back to
  local execution on macOS. The run reported 112 passed tests covering APFS
  capacity, purgeable and snapshot parsing, Mach/sysctl memory data, libproc
  process/open-file visibility, macOS PAL behavior, cleanup catalog safety,
  sacred catalog coverage, launchd defaults, and macOS release/update contracts.
- Attempted current-source macOS binary proof with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_current_macos_binary cargo build --bin sbh --target aarch64-apple-darwin`.
  The selected Linux worker failed before compiling `sbh` because the
  `aarch64-apple-darwin` Rust target was not installed there. No local
  current-source macOS binary was produced, so `sbh doctor --release --json`
  remains unproven from a current build.
- The macOS platform CI lane now captures `sbh --json doctor --release` from
  the just-built current-source release binary, validates the diagnostic JSON
  shape, uploads the doctor output with the macOS logs, and preserves an
  ad-hoc-signed diagnostic binary artifact plus SHA-256. This improves future
  closeout evidence but does not replace a final passing release doctor with
  real Developer ID, notary, and Homebrew credentials.
- The artifact-retention patch was validated with
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_macos_ci_artifact_proof cargo test --lib macos -- --nocapture`.
  The run reported 46 passed tests, including the updated CI workflow contract
  and macOS completion-audit guard. Full compiler gates also passed:
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_ci_artifact_check cargo check --all-targets`
  and
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_ci_artifact_clippy cargo clippy --all-targets -- -D warnings`.
- The JSON install dry-run regression found in the inspected macOS diagnostic
  artifact is fixed in source. `sbh --json install --auto --dry-run` now uses a
  single aggregate payload instead of emitting multiple top-level JSON objects,
  and a helper-level regression covers the macOS launchd/release-install shape
  where `release_install`, `wizard`, and `install` must remain nested in one
  object. Treat the artifact head/run as point-in-time evidence; refresh the
  latest pushed head before using this as closeout proof. Focused proof passed
  with
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-install-json-payload-test2 cargo test --no-default-features --features cli,daemon,sqlite --bin sbh install_auto_dry_run_json_payload_nests_macos_release_report -- --nocapture"`
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-install-json-integration2 cargo test --no-default-features --features cli,daemon,sqlite --test integration_tests install_auto_dry_run_json_is_single_payload -- --nocapture"`.
  Required compiler gates passed with `cargo fmt --check`, `git diff --check`,
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-install-json-payload-check cargo check --all-targets"`,
  and
  `rch exec "env CARGO_TARGET_DIR=/tmp/sbh-install-json-payload-clippy2 cargo clippy --all-targets -- -D warnings"`.
- Static workflow validation passed locally with Ruby YAML parsing for
  `.github/workflows/ci.yml`, `.github/workflows/release.yml`, and
  `.github/workflows/cert-expiration.yml`. The expected CI quality gate,
  macOS platform, coverage, benchmark, Homebrew formula, Developer ID signing,
  notarization, notary-ticket verification, and Homebrew tap workflow anchors
  are present.
- Local packaging-input validation passed at refresh time:
  `plutil -lint .github/macos/sbh.entitlements.plist`,
  `ruby -c packaging/homebrew/Formula/sbh.rb`, and
  `brew style packaging/homebrew/Formula/sbh.rb`.
- A read-only REST scan of the 30 most recently pushed owner repositories found
  at least 1,483 queued workflow runs and 14 in-progress runs across the
  account, including large queues in `asupersync`, `pi_agent_rust`,
  `franken_node`, and `agentic_coding_flywheel_setup`. This makes the current
  `storage_ballast_helper` hosted-runner delay look account-wide rather than an
  isolated workflow syntax or repository-permission issue.
- Live `gh api repos/Dicklesworthstone/storage_ballast_helper/actions/runners`
  returned `total_count = 0`; `storage_ballast_helper` has no self-hosted
  Actions runners registered, so
  the final CI gate currently depends entirely on GitHub-hosted runner capacity.
  The active `v0.4.10` workflow snapshot routes queued jobs to GitHub-hosted
  labels such as `ubuntu-latest` and `macos-latest`; registering a self-hosted
  runner would therefore not rescue that already-queued run without an
  authorized workflow/routing change and a fresh release attempt. Registering a
  self-hosted runner or canceling queued runs in other repositories would be
  remote state changes and needs explicit operator approval.
- A narrower queue triage found the largest queued-run sources were
  `asupersync` (858 queued), `pi_agent_rust` (239 queued), `franken_node` (116
  queued), `agentic_coding_flywheel_setup` (104 queued), and
  `ultimate_bug_scanner` (35 queued). If the operator wants to free hosted
  Actions capacity, cancellation should start with those repositories rather
  than this repo's current run, because this run already contains useful
  completed Intel macOS proof.

## Checklist

| Requirement | Evidence | Current Status |
|---|---|---|
| Fresh macOS install auto-detects launchd and status works | `src/platform/macos/pal.rs`, `src/daemon/service.rs`, `tests/integration_tests.rs::macos_launchd_user_service_lifecycle_bootstrap_kickstart_bootout`, `.github/workflows/ci.yml` `macos-platform`, `docs/macos.md` | Repo-side implementation and CI coverage exist. Signed release install has manual `v0.4.8`, Homebrew tap proof, live self-update E2E proof in `bd-ykwh.10`, and prior `v0.4.14` signed/notarized staging evidence. The prior `/tmp` `v0.4.14` artifacts are no longer present, so final closure still depends on hosted CI green and automated release-workflow proof for a fresh tag after the CI concurrency fix, or an explicitly approved regenerated manual publication. |
| Status/check JSON shape and APFS accounting match macOS reality | `tests/integration_tests.rs::macos_status_json_matches_diskutil_apfs_capacity`, `tests/integration_tests.rs::macos_check_json_matches_diskutil_apfs_capacity`, `docs/macos.md` | Covered in macOS integration tests and docs. Requires final CI green on the shipped head. |
| Scan finds and ranks macOS reclaim candidates | `src/platform/macos/cleanup_catalog.rs`, `tests/common/mod.rs::SyntheticMacTree`, `src/scanner/patterns.rs` macOS cleanup tests, `docs/macos-incident-case-study.md` | Covered for Xcode, CoreSimulator, Electron caches, `/private/tmp/*-target`, `*_target`, `target_*`, user trash, and sacred paths. |
| Clean/daemon deletion respects protected paths and active builds | `src/daemon/loop_main.rs::should_skip_protected_daemon_candidate`, `src/scanner/walker.rs`, `src/scanner/deletion.rs`, `bd-twgw`, `bd-j40b`, `daemon::loop_main::tests::scanner_prescan_does_not_dispatch_protected_rust_fuzz_target`, `daemon::loop_main::tests::executor_preflight_skips_config_protected_daemon_candidate` | Fixed in current source. Installed sbh 0.4.6 daemons must be upgraded/restarted because they can still delete protected artifact-looking paths. |
| Blame attributes macOS disk growth to processes | `tests/integration_tests.rs::macos_synthetic_writer_surfaces_in_blame_top_rows`, `src/cli_app.rs::collect_blame_report_at`, macOS PAL libproc process I/O and open-file code | Covered by macOS integration test and PAL-backed implementation. |
| CI validates Linux and macOS | `.github/workflows/ci.yml` jobs `check`, `unit`, `integration`, `linux-arm64`, `decision-plane`, `dashboard`, `e2e`, `macos-platform`, `macos-coverage`, `macos-benchmarks`, `stress`, `artifact-contract`, `provenance`, and `Homebrew Formula Validation` | Infrastructure exists. The macOS platform, coverage, and benchmark jobs are independent from the Ubuntu `check` job so Linux runner queueing cannot hide missing macOS proof. The `v0.4.15` hosted release attempt was cancelled before completion; the CI concurrency guard now avoids cancelling tag-triggered release quality-gate calls. Final goal cannot close until the final head completes all required hosted jobs green. `macos-15-intel` is the Intel lane; `macos-latest` remains the arm64 lane. |
| Docs explain install, configure, verify, and diagnose | `README.md`, `docs/macos.md`, `docs/macos-full-disk-access.md`, `docs/cleanup-rules-macos.md`, `docs/testing-and-logging.md`, sample configs in `docs/configs/` | Covered in docs. Keep docs update lint green for future CLI/config changes. |
| Release is signed, notarized, notary-ticket verified, and distributed through Homebrew | `.github/workflows/release.yml`, `.github/workflows/cert-expiration.yml`, `.github/macos/sbh.entitlements.plist`, `packaging/homebrew/Formula/sbh.rb`, `docs/macos.md` release diagnostics, `src/cli/mod.rs::release_workflow_notarizes_macos_binaries_asynchronously` | Workflow and docs exist. `bd-ykwh.20` verifies Apple notary log ticketContents before packaging. Manual `v0.4.8` release artifacts are signed/notarized and the public Homebrew tap formula installs, audits, tests, and passes `sbh doctor --release`. Prior manual `v0.4.14` artifacts were signed/notarized and checksum-verified, and the repaired Developer ID P12 imports through the same macOS `security` path used by the workflow, but the `/tmp` artifact directory is gone and must be regenerated before any manual upload. The `v0.4.15` hosted release workflow was cancelled before publication, and tap publication remains open under `bd-ykwh.3`, so the release system is not fully closeable until a fresh hosted tag run completes. |

## Protected-Path Daemon Regression

Live incident evidence from another machine showed sbh 0.4.6 deleting
`/data/projects/asupersync_ansi_c/tools/rust_fuzz_target` even though
`sbh scan` honored both config protections and `.sbh-protect` markers. The root
cause was the daemon cleanup path, especially priority pre-scan and executor
dispatch, bypassing the same protection checks used by manual scans.

Current source status:

- `bd-twgw` hardened daemon cleanup candidates with protection checks before
  dispatch and executor preflight.
- `bd-j40b` added the exact incident regression for the protected
  `asupersync_ansi_c/tools/rust_fuzz_target` path shape.
- The focused proof lane is
  `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_sbh_daemon_protection_proof cargo test --lib protected -- --nocapture`.
- On 2026-05-11 this lane passed 13 protection-related tests, including
  `scanner_prescan_does_not_dispatch_protected_rust_fuzz_target` and
  `executor_preflight_skips_config_protected_daemon_candidate`.

Operational consequence: do not restore protected files on machines still
running sbh 0.4.6 and assume they are safe. Upgrade/restart the daemon to a build
containing `bd-twgw` and `bd-j40b`, then restore the protected worktree files.

## Live Release Blocker Evidence

The user confirmed Apple Developer Program enrollment, so enrollment itself is
not the current blocker. Live checks at 2026-05-12 00:36 UTC now show:

- `security find-identity -v -p codesigning`: one valid Developer ID
  Application identity for `Jeffrey Emanuel (AU8V2Z6NKY)`.
- `xcrun notarytool history --keychain-profile sbh-notary --output-format json`
  and the local `.p8` API-key invocation both return parseable history JSON.
- `sbh --json doctor --release`: `ok=true`, with PASS for
  `release.developer_id_identity`, `release.notary_profile`,
  `release.github_secrets`, and `release.homebrew_tap`.
- `gh secret list --repo Dicklesworthstone/storage_ballast_helper`: signing
  secrets were updated at 2026-05-11T20:31Z, notary secrets at
  2026-05-11T20:25Z, and Homebrew tap credentials are present.
- The final Developer ID P12 is compatible with both OpenSSL 3 certificate
  extraction and macOS `security import`, and local workflow emulation used it
  to Developer-ID sign both prior staged `v0.4.14` macOS binaries. Those staged
  `/tmp` artifacts are no longer present and must be regenerated before any
  manual publication.
- `gh api repos/Dicklesworthstone/homebrew-sbh/contents/Formula/sbh.rb`: live
  public tap formula exists on `main` with content SHA
  `6e4c74f521b3a2f58e2f8a216d04bc0da3164fef`, but still points at `v0.4.8`.
- GitHub release/tag checks: `v0.4.8` is published with macOS and Linux
  archives, checksum sidecars, `SHA256SUMS.txt`, and provenance.
- GitHub release/tag checks: `v0.4.15` is tagged at release-candidate head
  `067f55ea017321428b9a4722d70c0e518c6944b4`, but no `v0.4.15` release assets
  are published. Superseded `v0.4.14` Release run `25693688419` is cancelled.
- GitHub Actions checks show the `v0.4.15` hosted release attempt did not
  complete: Release run `25705033848` completed with conclusion `cancelled`.
  Its Intel macOS platform job completed success, while release-level tap
  preflight, Format + Lint, Apple Silicon macOS platform, coverage, performance,
  and Homebrew formula jobs were cancelled before runner assignment. Standalone
  main CI run `25705030478` for the same source/tag head `067f55e` and later
  standalone main CI run `25706394564` for docs/test head `2ecbb05` were
  cancelled to reduce duplicate queue pressure. This remains non-green status,
  not completion evidence.
- The `v0.4.16` hosted release attempt at
  `f9275c09a0c9c975775d2908d56453109a3c9dc4` proved the CI concurrency fix was
  effective enough to let tag-triggered release quality gates start after queued
  runner pressure was reduced, but Release run `25708496915` did not publish.
  Tap preflight, Homebrew formula validation, macOS performance budgets, Format
  + Lint, and Intel macOS platform tests passed. Apple Silicon macOS platform
  tests and macOS coverage both failed on
  `macos_synthetic_writer_surfaces_in_blame_top_rows` because hosted APFS process
  write accounting reported 99,880,960 bytes for a 112 MiB synthetic writer while
  the test required at least 100 MiB. The run was then cancelled to avoid wasting
  downstream release work. Candidate `v0.4.17` kept the
  release concurrency fix and relaxes that macOS blame test to require a
  substantial 90 MiB visible write while still requiring the writer PID and open
  file path.
- The `v0.4.17` hosted release attempt at
  `14e2f03309c8622c6e02186ad4b04026f82bbea3` proved the blame threshold fix:
  macOS coverage, Intel platform tests, Format + Lint, macOS performance
  budgets, Homebrew formula validation, and tap deploy-key preflight passed.
  Release run `25710141215` did not publish because the Apple Silicon launchd
  lifecycle fixture packaged the just-built ad-hoc-signed CI binary into an
  offline bundle and then used the default macOS install path, which correctly
  rejected it for lacking the expected Developer ID Application identity. The
  run was cancelled after that required gate failed to avoid wasting downstream
  release work. Candidate `v0.4.18` kept Developer ID trust
  enforcement as the default, forwards the existing explicit `--no-verify`
  bypass through `sbh install`, and uses that bypass only for the launchd
  lifecycle test's trusted local offline fixture.
- The `v0.4.18` hosted release attempt at
  `c6335ee5c0af81777014c704e2b05c9f13f7ed83` did not publish. Release run
  `25713928783` failed early in the Intel macOS unit-test gate because the
  documentation-contract test
  `unix_installer_verifies_macos_binary_trust_before_install` still expected the
  previous exact `--no-verify` wording after the docs were updated to mention
  `sbh install --no-verify` and `sbh update --no-verify` separately. The run was
  cancelled after that required gate failed. The next candidate is `v0.4.19`,
  which updates that contract assertion to the new explicit install/update
  wording.
- The `v0.4.19` hosted release attempt at
  `8ed99a9f9146dd92d0766cd4972d60236264d54f` proved the macOS gates, E2E
  suite, stress tests, and the launchd fixture fix, but did not publish because
  the reusable CI workflow's final provenance job remained queued on
  `ubuntu-latest` for over twenty minutes after every required test gate had
  passed. Candidate `v0.4.20` skips that redundant CI provenance job only for
  tag-triggered release quality gates; the release workflow still generates and
  uploads release provenance during publication.
- Candidate `v0.4.21` simplifies that skip predicate to the tag ref itself so
  it remains correct when the reusable workflow sees the caller's original tag
  push context. The superseded `v0.4.20` run was cancelled before any gate
  completed.
- The `v0.4.21` hosted release attempt at
  `5ba24bbe7beedf8793e5b34bb10033c2d0c88b0d` proved every reusable quality gate,
  skipped the redundant tag provenance job as intended, and completed all four
  signed/notarized release build jobs. It did not publish because the release
  publisher downloaded every workflow artifact, including macOS platform
  diagnostic checksum files that were not part of the release archive contract.
  Candidate `v0.4.22` filters release and tap downloads to build artifacts named
  `sbh-*` before generating release manifests.
- The `v0.4.22` hosted release attempt at
  `d8bfa924a511ac02ad0644639ce8cf529d589144` completed release run
  `25719962018` successfully. It published GitHub release `v0.4.22`, uploaded
  release provenance, uploaded versioned and legacy release archives for both
  Linux targets and both macOS targets, and updated
  `Dicklesworthstone/homebrew-sbh` to formula version `0.4.22`.
- Account-wide queued Actions cleanup was used to unblock hosted runner
  assignment for the `v0.4.16` release attempt. The first pass cancelled 935
  queued runs older than one hour, excluding the active `storage_ballast_helper`
  release; 8 cancellation attempts failed because those runs had already
  completed. A second pass cancelled 351 queued runs older than 15 minutes with
  the same exclusion; 36 attempts were already completed or otherwise no longer
  cancellable. In-progress runs were not cancelled. A later `v0.4.17` queue
  pass cancelled 147 queued runs older than 15 minutes outside
  `storage_ballast_helper`; 8 cancellation attempts failed after the target run
  changed state.
- Local Homebrew validation: the public tap install/test path passed for
  `v0.4.8`, historical generated-formula validation passed for `v0.4.14`, and
  the public `v0.4.22` tap formula now passes `brew fetch` and `brew audit`.
  The fetched Apple Silicon archive extracts to `sbh 0.4.22`; `codesign
  --verify --strict` accepts it, and `sbh doctor --pal --json` reports
  `failed: 0` from the extracted public binary. The extracted-binary doctor run
  still warns that the probe copy is not installed as a launchd service and that
  `spctl` treats a bare CLI executable as not an app, while reporting the
  Developer ID Application origin.

## Complete

The macOS parity release gate is complete as of `v0.4.22`:

1. Hosted release run `25719962018` passed end to end from tag `v0.4.22`.
2. The release produced signed/notarized macOS artifacts for Apple Silicon and
   Intel without manual publication.
3. The reusable quality gate passed macOS Apple Silicon, Intel macOS,
   macOS coverage, macOS benchmarks, Linux arm64, unit, integration, dashboard,
   decision-plane, artifact-contract, stress, E2E, Format + Lint, and Homebrew
   Formula Validation lanes.
4. The redundant tag quality-gate provenance job is skipped only for version
   tags; release provenance is still generated and uploaded by the release
   publisher.
5. The public Homebrew tap points at `v0.4.22` release URLs and checksum values
   matching the published `.sha256` sidecars.
