# ADR: TUI Integration Strategy (bd-xzt.1.3)

**Status:** ACCEPTED
**Decision:** Selective adaptation
**Date:** 2026-02-16
**Authors:** TanBasin (agent), CalmCompass (agent)
**Inputs:** bd-xzt.1.1 (baseline contract), bd-xzt.1.2 (triage matrix), bd-xzt.1.6 (licensing/toolchain compliance)

## Context

SBH needs a TUI overhaul to replace the current minimal crossterm-based
dashboard (738 lines, fixed grid, polling refresh) with a richer operator
cockpit inspired by FrankentUI's showcase patterns. The overhaul must maintain
full parity with the baseline contract (C-01 through C-18) while adding new
capabilities: explainability views, action timelines, VOI overlays, command
palette, and multi-screen navigation.

## Decision

**Selected strategy: (B) Selective component adaptation with SBH-native runtime.**

All FrankentUI UX patterns, layouts, and data models identified in the triage
matrix (docs/frankentui-triage-matrix.md) will be adapted into SBH's codebase
using SBH's existing toolchain and dependencies. No FrankentUI crate will be
added to Cargo.toml.

## Amendment (2026-09-03): what shipped

The paragraph above is kept as the record of the original decision; the
implementation moved past it and the code is the truth:

- `Cargo.toml` **does** depend on FrankentUI: `ftui`, `ftui-backend`, and
  `ftui-tty` are git dependencies pinned at tag `v0.6.0`, gated by the `tui`
  feature. The cockpit in `src/tui/` renders through ftui's frame pipeline;
  the crossterm direct-draw dashboard survives only behind the off-by-default
  `legacy-crossterm-dashboard` feature (`--legacy-dashboard`).
- The `tui` feature is in the crate's default feature set, so `cargo install`
  and the release binaries carry the cockpit; CI builds
  `--no-default-features --features cli,daemon,sqlite,tui` and, separately,
  the legacy feature.
- The toolchain is nightly (`rust-toolchain.toml`), so the "SBH policy forbids
  nightly" argument under alternative (A) no longer applies; what remains of
  it is the dependency-size concern, answered by `default-features = false`
  on `ftui` and by the release profile.
- `--new-dashboard` is accepted for compatibility and is the default route;
  `--replay <activity.jsonl>` drives the same cockpit from a captured log.

The Decision Invariants below still hold (invariant 1 already anticipated
"ftui-* crate dependencies").

## Decision Invariants

The following constraints are mandatory for all downstream work:

1. **Nightly toolchain:** SBH release builds use the repository nightly
   toolchain, and ftui-* crate dependencies remain intentional and audited.
2. **Zero contract regression:** baseline contract IDs C-01 through C-18 from
   `docs/dashboard-status-contract-baseline.md` remain satisfied.
3. **Safety before polish:** emergency paths, veto visibility, stale-state
   handling, and terminal cleanup guarantees are never weakened by UX changes.
4. **Deterministic runtime:** model/update/command behavior is deterministic and
   testable under degraded data sources.

## Alternatives Considered

### (A) Broader ftui runtime adoption

Add ftui-runtime, ftui-widgets, ftui-render, ftui-layout, ftui-core, ftui-style,
and ftui-text as git dependencies from the FrankentUI repo.

**Rejected because:**
- FrankentUI pins **nightly Rust** (though core crates lack `#![feature()]`
  directives and may compile on stable). SBH policy forbids nightly. Even if
  core crates happen to compile on stable today, upstream changes could
  introduce nightly dependencies at any time without notice.
- Adds ~25 direct dependencies and deep transitive tree. SBH's release profile
  (`opt-level = "z"`, `strip = true`) targets lean binaries; the dependency
  bloat is unacceptable.
- Couples SBH's TUI to an upstream framework with a single maintainer and no
  stability guarantees. Framework-level bugs become SBH blockers.
- The ftui render pipeline (custom cells, frames) is incompatible with SBH's
  existing crossterm direct-draw approach, requiring a full rewrite rather than
  incremental migration.

### (C) Hybrid: selective vendoring of ftui source files

Copy specific self-contained widget source files (badge.rs, sparkline.rs,
progress.rs) from ftui-widgets into SBH's codebase, adapting them to use
crossterm directly.

**Rejected because:**
- Even "self-contained" widgets depend on ftui-render (Frame, Cell),
  ftui-layout (Constraint, Flex), ftui-style (Style, StyleFlags), and ftui-text
  (Line, Span, Text). Vendoring any single widget requires vendoring
  significant portions of the framework.
- Per-file nightly audit is labor-intensive and error-prone. One missed
  nightly-only feature breaks the stable build.
- Creates a maintenance burden: vendored code diverges from upstream, loses
  fixes, and accumulates SBH-specific patches.

### (D) ratatui bridge

Adopt ratatui as SBH's TUI framework, then adapt FrankentUI's screen designs
to ratatui's widget API.

**Considered viable but deferred.** ratatui works on stable Rust and shares
conceptual DNA with FrankentUI (both are Elm-inspired). However:
- Adding ratatui is a significant new dependency (ratatui + crossterm + many
  feature crates).
- SBH's current TUI is optional (`tui` feature gate). Adding ratatui increases
  the cost of the optional feature.
- The current overhaul scope (7 must-copy screens) does not require a full
  framework; SBH's crossterm foundation is sufficient for operator dashboards.
- **Recommendation:** If the overhaul scope expands beyond the current 7+4
  screens, re-evaluate ratatui adoption in a follow-up ADR.

## Implementation Phases

### Phase 1: Foundation (bd-xzt.2.1, bd-xzt.2.2, bd-xzt.2.3, bd-xzt.2.10)

1. **TUI module scaffold** (bd-xzt.2.1): Create `src/tui/` module tree with:
   - `mod.rs` — canonical entry point, replaces current `run_dashboard` routing
   - `model.rs` — Elm-style state model (DashboardModel)
   - `update.rs` — message-driven update loop
   - `render.rs` — frame rendering dispatcher
   - Feature-gated behind existing `tui` feature flag

2. **State model** (bd-xzt.2.2): Implement deterministic model/update/cmd:
   - DashboardModel holds all display state
   - DashboardMsg enum for all input events and data updates
   - Pure update function: `fn update(model, msg) -> (model, cmd)`
   - Cmd enum for side effects (fetch data, start timer, quit)

3. **Data adapters** (bd-xzt.2.3): Typed adapters for daemon state:
   - StateFileAdapter: reads/parses state.json with staleness detection
   - FsStatsAdapter: live filesystem stats for degraded mode
   - TelemetryAdapter: SQLite/JSONL query interface

4. **Preferences model and persistence boundaries** (bd-xzt.2.10):
   - Versioned dashboard preference schema (default screen, density, hints)
   - Deterministic merge precedence (defaults -> persisted -> runtime overrides)
   - Non-blocking persistence failure handling with explicit degraded-mode
     signaling

### Phase 2: Layout and Theme (bd-xzt.2.5, bd-xzt.2.6)

4. **Layout/theme foundation** (bd-xzt.2.5): SBH-specific design system:
   - Pressure-level color tokens (green/yellow/orange/red/critical)
   - Semantic emphasis tokens (primary, muted, disabled, error, warning)
   - Responsive pane composition for narrow (80-col) and wide (200-col) terminals
   - Accessibility: high-contrast mode, no-color compatibility

5. **Input system** (bd-xzt.2.6): Global keymap engine:
   - Contextual key bindings per screen
   - Command palette with fuzzy matching (adapted from FrankentUI pattern)
   - Help overlay (adapted from FrankentUI HelpEntry pattern)

### Phase 3: Screens (bd-xzt.3.1 through bd-xzt.3.5, bd-xzt.3.11)

6. **Overview screen** (bd-xzt.3.1): Parity with C-05 through C-18:
   - Multi-panel layout: pressure gauges, EWMA sparklines, ballast summary,
     counters, activity log, PID state
   - Responsive reflow from 40-col to 200-col
   - Degraded mode fallback (C-17)

7. **Action Timeline** (bd-xzt.3.2): Adapted from FrankentUI action_timeline:
   - Severity-filtered event stream
   - Ring buffer storage
   - Follow mode and detail panel

8. **Explainability cockpit** (bd-xzt.3.3): Adapted from FrankentUI:
   - Evidence ledger with timeline
   - Posterior/Bayes factor display
   - Decision trace drill-down

9. **Scan Candidates** (bd-xzt.3.4): Score breakdown view:
   - Factor contribution bars
   - Safety veto indicators
   - Sortable candidate table

10. **Ballast Operations** (bd-xzt.3.5): Per-volume inventory:
    - Ballast pool status per mount
    - Release/replenish controls (guarded by confirmation)

11. **Preference-driven UX controls** (bd-xzt.3.11):
    - Default startup screen routing, density mode, and hint verbosity
    - Reset/revert controls via command palette
    - Safety visibility floor so critical pressure/safety indicators remain
      visible in all profiles

### Phase 4: Verification (bd-xzt.4.*, including bd-xzt.4.14)

All screens must pass contract verification against the baseline checklist
(docs/dashboard-status-contract-baseline.md). Every contract ID must have a
corresponding test.

Failure injection is mandatory, not optional:
- `bd-xzt.4.14` validates degraded/recovery behavior across daemon state,
  telemetry backends, and preference persistence failures.

## Feature Flag and Migration Boundaries

- All new TUI code lives behind the existing `tui` feature flag.
- The current `run_dashboard` → `run_live_status_loop` path remains the
  **default** until Phase 4 verification is complete.
- A new `--new-dashboard` CLI flag routes to the new TUI during canary testing.
- Once verified, the new TUI becomes the default and the old path becomes
  `--legacy-dashboard`.
- Legacy dashboard code is retained for one release cycle, then removed per
  bd-xzt.5.6.

## Rollback Mechanics

- If the new TUI fails to load (missing feature, terminal incompatibility),
  automatically fall back to the legacy dashboard path.
- The `--legacy-dashboard` flag is always available as an escape hatch.
- Emergency mode (`sbh emergency`) never uses the TUI; it remains zero-write
  and stdout-only.

## Ownership Boundaries

| Module | Owner | Impact |
| --- | --- | --- |
| `src/tui/` (new) | TUI overhaul team | New module, no conflict |
| `src/cli_app.rs` | TUI team + existing maintainers | Add dispatch to new TUI; preserve legacy path |
| `src/cli/dashboard.rs` | TUI team | Evolves into legacy fallback, eventually removed |
| `src/daemon/self_monitor.rs` | Daemon team | No changes; TUI reads state.json as-is |
| `src/logger/` | Logger team | No changes; TUI reads via adapter |

## Risk Controls

| Risk | Control |
| --- | --- |
| Parity regression | Contract checklist (C-01 through C-18) verified by tests |
| Performance regression | Frame-time budget: <16ms render at 60fps; measured by perf HUD |
| Terminal cleanup failure | Raw mode + alt-screen cleanup in Drop impl, plus panic hook |
| Emergency mode breakage | Emergency mode has zero TUI dependencies; separate code path |
| Feature flag confusion | Single `tui` feature; `--new-dashboard` is a runtime flag, not a feature |

## Downstream Bead Mapping

This ADR is the authority for implementation sequencing and ownership. Key
downstream beads must reference these sections:

| Bead | ADR Anchor |
| --- | --- |
| `bd-xzt.1.4` | Context + Decision Invariants + Implementation Phases |
| `bd-xzt.2.1` | Phase 1 + Feature Flag and Migration Boundaries |
| `bd-xzt.2.4` | Phase 1 Data adapters + Ownership Boundaries |
| `bd-xzt.2.10` | Phase 1 Preferences model + Decision Invariants |
| `bd-xzt.3.11` | Phase 3 Preference-driven UX controls |
| `bd-xzt.4.14` | Phase 4 Verification + Risk Controls |
| `bd-xzt.5.3` | Feature Flag and Migration Boundaries + Rollback Mechanics |
| `bd-xzt.5.4` | Risk Controls + Downstream Bead Mapping |

## Resolved Compliance Questions (from bd-xzt.1.6)

Per the compliance plan (`docs/frankentui-compliance-plan.md`):

- **Attribution:** MIT file-level comments (`// Adapted from FrankentUI (MIT)`)
  for substantial copies; `// Inspired by FrankentUI <module>` for adaptations.
  No formal attribution needed for design-only inspiration.
- **Nightly features:** FrankentUI core crates have **NO** `#![feature()]`
  directives. The nightly pinning is vestigial from pre-Edition-2024
  stabilization. Core crates likely compile on stable without modification.
- **Toolchain policy:** SBH uses nightly Rust. Unstable feature use must remain
  documented and covered. Per-PR import review checklist is mandatory.
- **Safe candidates:** ftui-core, ftui-render, ftui-style, ftui-text,
  ftui-layout all use `forbid(unsafe_code)` and have minimal deps.
- **Excluded:** ftui-extras, WASM crates, ftui-pty, ftui-i18n, frankenterm-*.

---

*This ADR is the source of architectural truth for all downstream bd-xzt.2*,
bd-xzt.3*, bd-xzt.4*, and bd-xzt.5* tasks. Changes to this ADR require
re-evaluation of affected downstream tasks.*
