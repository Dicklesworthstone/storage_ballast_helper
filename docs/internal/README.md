# docs/internal — index and repository-hygiene decisions

Internal notes are working documents, not user docs; each line says what a
file is and whether it is current. The second table is the operator
decision list for root-level oddities: **no agent deletes any of them**
(AGENTS.md rule 1). Non-destructive parts (ignore rules, corrections, this
index) were applied on 2026-09-03 under bead `bd-rc-master-ajg1.13.3`;
the operator records each decision here.

## Internal documents

| File | What it is | Status |
| --- | --- | --- |
| `cfg-audit.md` | `target_os` cfg audit of the platform layer | historical (macOS parity work) |
| `codebase-audit-findings-2026-02-15.md` | consolidated audit findings, Feb 2026 | historical; fixes landed |
| `codebase-review-findings-2026-02-15.md` | review findings, Feb 2026 | historical; fixes landed |
| `dependency-upgrade-log-2026-05-13.md` | dependency upgrade log, May 2026 | historical |
| `dependency-upgrade-log-2026-09-02.md` | dependency upgrade log, Sep 2026 | current |
| `macos-parity-completion-audit.md` | macOS/Linux parity completion audit | superseded header added 2026-09-02; epic reopened |
| `pressure-mapping.md` | memory-pressure level mapping plus the forecast-bound note | current |
| `reality-check-2026-09-01.md` | parallel reality check (agent OliveIbis), folded into the plan below | historical input |
| `reality-check-and-bridge-plan-2026-09-02.md` | the reality check and bridge plan the `bd-rc-master-ajg1` bead tree was generated from | current; beads are canonical |
| `scanner-ab-2026-09-02.md` | scanner v1/v2 A/B evidence | current |

## Root-level oddities: operator decision list

| Item | What it is | Applied 2026-09-03 | Operator decision |
| --- | --- | --- | --- |
| `install.sh` (root, 91 lines, tracked) | a second installer with a weaker contract than `scripts/install.sh` (1,290 lines); `README.md` documents only `scripts/install.sh` | nothing (deletion or a shim needs a decision) | pending: delete, or replace with a shim that execs `scripts/install.sh` |
| `Codex-upgrade-progress.json` (root, tracked) | 2026-05-12 upgrade log duplicated by `dependency-upgrade-log-2026-05-13.md` | nothing | pending: delete |
| `SESSION_REPORT_EXPLORATION.md` (root, tracked) | a session note; two of its four claims were false | claims 2 and 4 corrected in place, status footer added | pending: delete, or move under `docs/internal/` |
| `gh_og_share_image.png` (351 KB, tracked) | no in-repo consumer; likely the GitHub social-preview image (`README.md` embeds `sbh_illustration.webp`) | nothing | pending: keep (if the repository's social preview uses it) or delete |
| `test_cast` (root, 4.3 MB ELF, untracked, ignored) | an April build artifact | already ignored | pending: delete |
| `&&/`, `>/`, `printf/`, `artifact-sync-ok/` (root, empty, untracked) | accident directories from mis-quoted shell commands | ignored (`.gitignore`) | pending: delete (`rmdir`) |
| `manual-release-artifacts/rch-artifact-sync-probe.txt/` (empty directory named like a file) | an rch sync probe that created a directory | ignored (`.gitignore`) | pending: delete (`rmdir`) |
| `.gate_sbh_trj.sh` (root, untracked) | a per-host quality-gate wrapper | ignored (`.gitignore`) | pending: keep local or move under `scripts/` |
| `.e2e-bin/` (root, untracked) | daemon and e2e binaries built for `tests/daemon_e2e.rs` runs | ignored (`.gitignore`) | keep local |
| `.beads/*.fsqlite-migration-state` and friends | `br` sidecars | already covered by `.beads/.gitignore` (`*.db-journal`, `*.vacuum-wal-cert*`, `*.fsqlite-migration-state`); `br doctor` passes | none needed |
