# macOS/Linux Parity Prompt-To-Artifact Completion Audit

> **Superseded (2026-09-02).** This audit certified prompt-to-artifact parity
> against the bead tree as it stood in May 2026. The reality check of
> 2026-09-02 (`docs/internal/reality-check-and-bridge-plan-2026-09-02.md`,
> bead tree `bd-rc-master-ajg1`) found that several of the beads this audit
> counted as complete were closed without their deliverable shipping (see the
> notes on `bd-izu.2`, `bd-2j5.21`, `bd-2s9`, `bd-xzt.5.3`, `bd-xzt.5.6`).
> The bridge plan and its beads are the current record.

Bead: `bd-r7m7.11` (parent `bd-r7m7`); refresh beads `bd-r7m7.12`,
`bd-r7m7.13`, `bd-r7m7.15`, `bd-r7m7.16`, `bd-r7m7.17`.
Last audited: 2026-05-12. Trimmed to this conclusion on 2026-09-03
(bd-rc-master-ajg1.13); the 780-line diary of point-in-time run ids, queue
states and tap versions it replaced is in this file's git history
(`git log -p -- docs/internal/macos-parity-completion-audit.md`).

## Conclusion

The objective was one source tree and one `sbh` CLI that behave correctly on
Linux and macOS through the platform abstraction layer, with install, service
control, disk accounting, cleanup rules, deletion safety, process health,
signed releases and CI proof on both platforms.

What the May 2026 audit established, and what still holds:

1. Code parity is complete: every PAL method is implemented on macOS and no
   operational subcommand returns `SBH-1101` there; launchd is the macOS
   service manager, APFS accounting (purgeable space, snapshots,
   `/private/tmp`) is handled, and macOS process and daemon health come from
   Mach, sysctl and libproc through `crates/sbh_mach`.
2. The macOS parity release gate passed end to end for `v0.4.22` (hosted run
   25719962018): signed and notarized artifacts for Apple Silicon and Intel,
   the reusable quality gate green on the macOS, Linux arm64, unit,
   integration, dashboard, decision-plane, stress, E2E and formula lanes, and
   the Homebrew tap pointing at the `v0.4.22` assets with matching checksums.
   The same workflow published `v0.4.25`, `v0.4.27` and `v0.4.28`.
3. The runner blocker that `bd-r7m7.17` tracked (queued hosted macOS lanes in
   May) cleared: macOS lanes ran green on 2026-05-27, 06-03, 06-08, 07-18,
   08-06 and 08-17. `macos-13` was retired by GitHub; the lanes now use
   `macos-latest` (arm64) and `macos-15-intel`.

What the 2026-09-02 reality check changed:

- The release pipeline was abandoned in June 2026; `v0.5.0` and `v0.5.1` were
  hand-published without the workflow's asset layout or provenance, all three
  GitHub workflows were disabled, and the updater could not resolve the
  published assets. Restoring the pipeline is `bd-rc-master-ajg1.5` (workflow,
  asset audit, `v0.5.2` cut); the release-engineering beads `bd-ykwh` and
  `bd-ykwh.3` were closed on 2026-09-03 with the v0.4.22–v0.4.28 evidence.
- The macOS closeout under `bd-rc-master-ajg1.10` is complete:
  - W9.1 (`bd-rc-master-ajg1.10.1`): Replaced `/sbin/mount` with `sbh_mach::getfsstat()`,
    eliminating subprocess forks on the hot path (zero child spawns verified by test),
    cached `diskutil apfs` (5-min TTL), and budgeted cold-start `sbh status` at 250 ms
    in `benches/macos_performance.rs` and `.github/workflows/ci.yml`.
  - W9.2 (`bd-rc-master-ajg1.10.2`): Added deadlines and pid caps to `open_files_under`
    and `executables_under` (fail-closed like Linux).
  - W9.3 (`bd-rc-master-ajg1.10.3`): Unified APFS snapshot reporting into
    `estimated_reclaimable_by_snapshot_thinning`, added `~/Library/Caches` cleanup rule,
    and fixed launchd documentation (`ThrottleInterval` 60, service names).
  - W9.4 (`bd-rc-master-ajg1.10.4`): Refreshed acceptance criteria (250 ms cold-start
    budget; `macos-latest` + `macos-15-intel` / `macos-15-large` runner matrix and dsr
    mmini fleet verification), closed `bd-r7m7.17` and `bd-r7m7`.
  - `crates/sbh_mach` workspace member safe FFI wrappers with `#![deny(unsafe_code)]`
    and per-item `// SAFETY:` proofs under `bd-rc-master-ajg1.1.4` and `10.1`.
- Beads this audit counted as delivered but whose deliverable did not exist in
  the CLI at close time carry an annotation comment pointing at the work that
  shipped them.

## Evidence Index

The evidence the May audit rested on, kept here in compact form (the unit
test `macos_completion_audit_maps_goal_to_evidence` checks that this file
still maps each goal to its proof):

- Bead chain: `bd-r7m7` (epic) with `bd-r7m7.15` (refresh after the release
  Gatekeeper gate) and `bd-r7m7.16` (no volatile head/run pins); `bd-ykwh`
  (release engineering) with `bd-ykwh.20` (Gatekeeper acceptance before
  packaging). `bd-ykwh.20` is closed;
  release CI now verifies Apple notary log ticketContents
  (`.github/workflows/release.yml` fails when the notary log ticketContents
  is not an array).
- Pinning policy: the audit avoids pinning exact commit hashes or
  GitHub Actions run ids as durable proof; refresh with `git rev-parse HEAD`,
  `gh run list --repo Dicklesworthstone/storage_ballast_helper` and
  `gh run view <latest-run>` before deciding anything.
- macOS behaviour proven by tests: launchd lifecycle
  (`macos_launchd_user_service_lifecycle_bootstrap_kickstart_bootout`),
  APFS capacity accounting against `diskutil`
  (`macos_status_json_matches_diskutil_apfs_capacity`), blame attribution
  (`macos_synthetic_writer_surfaces_in_blame_top_rows`) in
  `tests/integration_tests.rs`; deletion safety
  (`scanner_prescan_does_not_dispatch_protected_rust_fuzz_target`,
  `executor_preflight_skips_config_protected_daemon_candidate`) in
  `src/daemon/loop_main.rs`. They run in the `macos-platform` CI job on
  `macos-latest` and `macos-15-intel`.
- CI discipline: Do not treat queued CI as final proof; only a completed
  run for the current head counts.
- Release credentials: the 2026-05-10 recheck found one valid local
  Developer ID Application identity, a working `sbh-notary` keychain
  profile (`xcrun notarytool history --keychain-profile sbh-notary`), and
  `HOMEBREW_TAP_SSH_KEY` configured in GitHub Actions.
  `sbh doctor --release --json` reports an aggregate `ok` boolean plus
  `passed`, `warnings`, and `failed` counts; since 2026-09-03 it also
  carries the drift checks and `--assets <dir|tag>` audits a published
  asset set.

Before any further close decision on `bd-r7m7`, refresh the live head and the
newest macOS run rather than trusting any literal above:

```bash
gh run list --repo Dicklesworthstone/storage_ballast_helper --branch main --limit 5 \
  --json databaseId,headSha,status,conclusion,workflowName,url,createdAt,event
```
