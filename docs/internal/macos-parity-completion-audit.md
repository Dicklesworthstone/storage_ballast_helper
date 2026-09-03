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
- The macOS closeout that remains (getfsstat, cold-start budget, open-file
  deadlines, snapshot estimate, docs, the parity re-audit and the closing of
  `bd-r7m7.17` / `bd-r7m7`) is `bd-rc-master-ajg1.10` and its children;
  `crates/sbh_mach` became a workspace member whose tests run in the macOS
  lanes under `bd-rc-master-ajg1.1.4`.
- Beads this audit counted as delivered but whose deliverable did not exist in
  the CLI at close time carry an annotation comment pointing at the work that
  shipped them.

Before any further close decision on `bd-r7m7`, refresh the live head and the
newest macOS run rather than trusting any literal above:

```bash
gh run list --repo Dicklesworthstone/storage_ballast_helper --branch main --limit 5 \
  --json databaseId,headSha,status,conclusion,workflowName,url,createdAt,event
```
