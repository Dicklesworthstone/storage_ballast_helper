# Dashboard Information Architecture and Navigation Map (bd-xzt.1.4)

**Status:** ACCEPTED
**Date:** 2026-02-16
**Authors:** CalmCompass (agent, initial draft), TanBasin (agent, expansion)
**Inputs:** bd-xzt.1.1 (baseline contract), bd-xzt.1.2 (triage matrix),
bd-xzt.1.3 (integration ADR)

This document defines the operator-facing information architecture for the SBH
dashboard overhaul. It removes UI guesswork for downstream `bd-xzt.2*` and
`bd-xzt.3*` work.

References:
- `docs/dashboard-status-contract-baseline.md` (C-01..C-18 parity constraints)
- `docs/frankentui-triage-matrix.md` (screen/pattern shortlist)
- `docs/adr-tui-integration-strategy.md` (selected adaptation strategy)

---

## 1. Design Principles

1. **Time-to-correct-action under pressure:** Every screen optimizes for the
   operator question "what do I need to do right now?" Decorative elements never
   compete with actionable data.
2. **Safety floor:** Critical pressure alerts, daemon connection status, and
   active safety state are always visible regardless of which screen the
   operator is viewing. These elements cannot be hidden by navigation,
   preferences, or density settings.
3. **Progressive disclosure:** Overview shows the 80% case; drill-down surfaces
   the remaining 20%. Operators should not need to leave Overview during routine
   monitoring.
4. **Deterministic layout:** Pane positions are stable across refreshes. Data
   flows into fixed regions; regions do not jump or reorder. Operators build
   muscle memory for where to look.
5. **Graceful degradation:** Every screen renders meaningfully when data sources
   are unavailable (C-17). Degraded indicators replace missing data rather than
   crashing or showing stale values silently.

### Non-Negotiables

1. Baseline contract parity remains intact (C-01..C-18).
2. Emergency mode remains zero-write and outside TUI dependencies.
3. Degraded mode preserves critical situational awareness when daemon state is
   stale or missing.
4. Terminal lifecycle guarantees (raw mode/alt-screen cleanup and safe exit)
   remain unchanged (C-15).
5. The same workflow is reachable in <= 3 interactions from the default screen.

---

## 2. Operator Journeys

### J-1: Pressure Triage (primary, most frequent)

**Trigger:** Routine monitoring, pressure alert, post-incident check.
**Operator question:** "Is my disk about to fill up? Is it getting worse?"

```
S1 Overview → (if mount needs attention) → select mount detail
            → (if trend unclear) → S2 Action Timeline (filter by mount)
            → (if cleanup needed) → S4 Scan Candidates
```

**Key data:** Pressure gauges, EWMA rate sparklines, time-to-exhaustion,
ballast available count.

**Time budget:** Go/no-go decision within 5 seconds of opening.

### J-2: Incident Response (time-critical)

**Trigger:** Critical pressure level or disk-full alert.
**Operator question:** "What can I safely delete right now?"

```
S1 Overview (critical alert banner) → S4 Scan Candidates (sorted by score)
                                    → (verify safety) candidate detail
                                    → (release ballast) S5 Ballast Operations
```

**Key data:** Critical pressure banner, top candidates by reclaim potential,
safety veto indicators, ballast release controls.

**Time budget:** First deletable candidate within 3 seconds. Ballast release
reachable within 2 keypresses from any screen.

### J-3: Explainability Drill-Down

**Trigger:** Operator questions a decision, audit requirement.
**Operator question:** "Why did sbh decide to delete/keep this artifact?"

```
S4 Scan Candidates → select candidate → S3 Explainability Cockpit
                                       → factor contributions
                                       → posterior/Bayes display
                                       → evidence ledger
```

**Key data:** Five scored factors with weights, pressure multiplier, Bayesian
posterior, expected loss comparison, calibration score, veto status.

**Time budget:** Full L2 trace readable within one screenful.

### J-4: Ballast Management

**Trigger:** Pressure rising, proactive buffer assessment.
**Operator question:** "How much buffer do I have? Should I release more?"

```
S1 Overview (ballast summary) → S5 Ballast Operations
                               → release/replenish controls
```

### J-5: Historical Analysis

**Trigger:** Morning review, post-incident investigation.
**Operator question:** "What happened while I was away?"

```
S2 Action Timeline (default: last 24h) → severity filter
                                       → event detail
                                       → drill to S3 Explainability
```

### J-6: Log Search

**Trigger:** Debugging, searching for specific artifact or event.
**Operator question:** "When was /foo/bar/.cache last scanned?"

```
S6 Log Search → query input → results with context
              → navigate to event in S2 Action Timeline
```

### J-7: Health Monitoring

**Trigger:** After daemon restart, investigating sluggishness.
**Operator question:** "Is the daemon healthy?"

```
S1 Overview (counters row) → S7 Diagnostics
                            → performance percentiles
                            → error breakdown
```

---

## 3. Screen Topology

### 3.1 Top-Level Screens

| # | Screen | Purpose | Default Entry | Contract IDs |
| --- | --- | --- | --- | --- |
| S1 | **Overview** | Global pressure + fast action routing | Yes | C-05–C-18 |
| S2 | **Action Timeline** | Ordered event stream and severity filtering | No | C-12 |
| S3 | **Explainability Cockpit** | Decision evidence and posterior trace | No | — |
| S4 | **Scan Candidates** | Candidate ranking + factor/veto inspection | No | — |
| S5 | **Ballast Operations** | Per-volume inventory and release/replenish | No | C-11 |
| S6 | **Log Search** | JSONL/SQLite log viewing with search/filter | No | — |
| S7 | **Diagnostics** | Daemon health, performance, thread status | No | — |

### 3.2 Overlays (non-screen, float above current screen)

| ID | Surface | Trigger | Behavior |
| --- | --- | --- | --- |
| O1 | **Command Palette** | `Ctrl-P` or `:` | Fuzzy-search across screens, actions, settings. |
| O2 | **Help Overlay** | `?` | Contextual key map for current screen. Dismiss with `?` or `Esc`. |
| O3 | **VOI Overlay** | `v` | Floating panel showing VOI scheduler state. Overlays right 40% of screen. |
| O4 | **Notification Toasts** | Automatic | Top-right stack. Info auto-dismisses 5s. Warnings persist until `x`. Max 3 visible. |
| O5 | **Critical Alert Banner** | Automatic | Full-width banner below header when pressure = red/critical. Cannot be dismissed. |
| O6 | **Confirmation Dialog** | Mutating actions | Modal confirmation for ballast release and other state-changing actions. |

### 3.3 Cross-Screen Route Map

```text
S1 Overview
  -> (2) S2 Action Timeline
  -> (3) S3 Explainability Cockpit
  -> (4) S4 Scan Candidates
  -> (5) S5 Ballast Operations
  -> (6) S6 Log Search
  -> (7) S7 Diagnostics
  -> (Enter on alert/event) contextual route to S2/S3/S4/S5

S2 Action Timeline
  -> (Enter on decision event) S3 Explainability [decision preselected]
  -> (Enter on cleanup event) S4 Scan Candidates [candidate filter retained]
  -> (Enter on ballast event) S5 Ballast Operations

S3 Explainability Cockpit
  -> (open related candidate) S4 [candidate id preselected]
  -> (open related timeline) S2 [cursor at originating event]

S4 Scan Candidates
  -> (explain selected) S3 [decision/candidate linkage]
  -> (ballast fallback) S5 [when target reclaim gap remains]

S5 Ballast Operations
  -> (post-action review) S2 [new ballast event highlighted]
  -> (pressure stabilized) S1 Overview

S6 Log Search
  -> (Enter on result) S2 Action Timeline [anchored at event]
  -> (Enter on decision result) S3 Explainability

S7 Diagnostics
  -> (Enter on error) S2 Action Timeline [filtered to errors]

Any screen
  -> O1 Command Palette (Ctrl-P)
  -> O2 Help Overlay (?)
  -> O3 VOI Overlay (v)
```

---

## 4. Navigation Model

### 4.1 Global Keys (available on every screen)

| Key | Action | Notes |
| --- | --- | --- |
| `1`–`7` | Jump to screen by number | Instant switch, no animation |
| `[` / `]` | Previous / next screen | Wraps S7 → S1 and S1 → S7 |
| `Ctrl-P` or `:` | Open command palette | Fuzzy search all actions |
| `?` | Toggle help overlay | Contextual to current screen |
| `v` | Toggle VOI overlay | Float panel, not a screen switch |
| `b` | Quick ballast release | Opens confirmation dialog from any screen (J-2 fast path) |
| `Esc` | Back / close | Close overlay first; then clear selection; then exit |
| `q` | Exit dashboard | From any non-confirmation state |
| `Ctrl-C` | Exit immediately | Always exits, no confirmation |

### 4.2 Input State Precedence

Input handling priority (highest first):
1. Confirmation dialog (O6)
2. Command palette / help / overlay (O1/O2/O3)
3. In-screen focused pane
4. Global screen navigation

This prevents accidental screen switches during destructive confirmation flows.

### 4.3 Screen-Local Keys

**S1 Overview:**

| Key | Action |
| --- | --- |
| `j`/`k` or `↑`/`↓` | Select mount in pressure gauges |
| `Enter` | Drill into selected mount detail |
| `Tab` / `Shift-Tab` | Cycle focus between panes |
| `r` | Force refresh (bypass poll interval) |

**S2 Action Timeline:**

| Key | Action |
| --- | --- |
| `j`/`k` or `↑`/`↓` | Scroll event list |
| `Enter` | Open event detail / drill to S3 or S4 |
| `f` | Toggle follow mode (auto-scroll to latest) |
| `1`–`5` | Filter severity (1=trace, 2=info, 3=warn, 4=error, 5=critical) |
| `/` | Open filter/search bar |
| `c` | Clear filters |

**S3 Explainability Cockpit:**

| Key | Action |
| --- | --- |
| `j`/`k` or `↑`/`↓` | Scroll factor list / evidence timeline |
| `l` | Cycle explain level (L0 → L1 → L2 → L3) |
| `Tab` | Switch focus between factor panel and evidence panel |
| `Backspace` | Return to prior context (S4 candidate list) |

**S4 Scan Candidates:**

| Key | Action |
| --- | --- |
| `j`/`k` or `↑`/`↓` | Select candidate |
| `Enter` | Open candidate in S3 Explainability |
| `s` | Cycle sort column (score, size, age, name) |
| `S` | Reverse sort order |
| `V` | Toggle show/hide vetoed candidates |

**S5 Ballast Operations:**

| Key | Action |
| --- | --- |
| `j`/`k` or `↑`/`↓` | Select mount |
| `r` | Release one ballast file (with confirmation O6) |
| `R` | Release all ballast for mount (with confirmation O6) |
| `p` | Replenish ballast for mount |

**S6 Log Search:**

| Key | Action |
| --- | --- |
| `/` | Focus search input |
| `n` / `N` | Next / previous match |
| `c` | Toggle case sensitivity |
| `x` | Toggle context lines |
| `Enter` | Jump to event in S2 Action Timeline |

**S7 Diagnostics:**

| Key | Action |
| --- | --- |
| `j`/`k` or `↑`/`↓` | Scroll metrics |
| `Tab` | Switch focus between panels |
| `Enter` | Drill into error → S2 Action Timeline |

### 4.4 Command Palette Action Catalog

The command palette provides fuzzy-searchable access to:

1. **Screen jumps:** "Go to Overview", "Go to Scan Candidates", etc.
2. **Overlay toggles:** "Toggle VOI Overlay", "Show Help"
3. **Operational actions:** "Release Ballast", "Force Refresh", "Export Log"
4. **Settings:** "Toggle High Contrast", "Change Density", "Set Refresh Rate"
5. **Navigation history:** Recently visited screens (MRU order)

Matching uses prefix > substring > subsequence ranking with recency boost.

---

## 5. Always-On vs Drill-Down Information Placement

### Always-on (visible on every screen)

| Signal | Placement | Rationale |
| --- | --- | --- |
| Worst pressure level + mount | Header bar (left) | Immediate severity context |
| Daemon mode (`LIVE`/`DEGRADED`/`STALE`) | Header bar (center) | Prevent false confidence in stale data |
| Exhaustion horizon (if rate > 0) | Header bar (right) | Time-to-failure drives urgency |
| Active safety state (veto/breaker summary) | Status strip | Prevent unsafe action assumptions |
| Active operation indicator (scan/clean in-flight) | Footer | Prevent conflicting operator actions |
| Connection status (green/yellow/red dot) | Footer (right) | Daemon liveness at a glance |
| Current screen name + key hints | Footer (left) | Orientation and discoverability |

### Drill-down (shown only on focus)

| Detail | Home Screen | Trigger |
| --- | --- | --- |
| Full evidence ledger + posterior math | S3 | `Enter` from decision list |
| Candidate factor contributions + veto reasons | S4 | `Enter` on candidate row |
| Per-volume ballast history + release preview | S5 | Focus ballast table row |
| Full log search context windows | S6 | `/` then search |
| VOI component breakdown + observation payload | O3 | `v` |
| Performance percentiles (p50/p95/p99) | S7 | Navigate to S7 |

---

## 6. Pane Priority Per Screen

Priority semantics:
- `P0`: must render first; never hidden regardless of terminal width
- `P1`: visible by default; may collapse on narrow terminals (< 100 col)
- `P2`: optional/secondary; collapses first; available via expand/scroll

### S1 Overview

| Pane | Priority | Narrow (<100 col) | Wide (>=100 col) |
| --- | --- | --- | --- |
| Pressure gauges + level badges | P0 | Top block, stacked | Left primary column |
| EWMA sparklines + rate labels | P0 | Below gauges | Right of gauges (side-by-side) |
| Ballast quick status | P1 | Inline compact row | Dedicated column (wide) |
| Last scan summary | P1 | Inline with ballast | Below sparklines |
| Counters (scans/del/freed/err/RSS) | P1 | Single summary row | Below last scan |
| Activity log (last N events) | P1 | Tabbed with trends | Bottom section |
| Performance HUD (frame time) | P2 | Hidden | Bottom-right (optional) |

#### Responsive Layout Wireframes

**Narrow (80–99 col):**
```
┌─ SBH v0.5.0  [LIVE]  uptime: 2h 15m ──── S1 Overview ─┐
│ CRITICAL: /tmp at 94% (est. exhaustion ~12 min)         │
├─────────────────────────────────────────────────────────┤
│ Pressure Gauges                                          │
│   /home  [████████░░░░░░░░░░░░] 42%  GREEN              │
│   /tmp   [██████████████████░░] 94%  CRITICAL ⚠         │
├─────────────────────────────────────────────────────────┤
│ EWMA Trends (30 readings)                                │
│   /home  ▁▂▃▃▄▃▂▂▃▃▄▅▆▇▆▅▄▃▂▁  1.2 MB/s (stable)     │
│   /tmp   ▃▄▅▆▇██▇▆▅▅▆▇█▇▆▅▅▄  4.8 MB/s (accel) ⚠     │
├─────────────────────────────────────────────────────────┤
│ Ballast: 8/10 avail  Last: 14:32 (5 cand, 2 del)       │
│ Scans: 42 Del: 18 (3.2 GB) Err: 0 RSS: 12 MB          │
├─────────────────────────────────────────────────────────┤
│ Activity (last 5)                                        │
│  14:32 INFO  scan: 5 candidates, 2 deleted              │
│  14:31 WARN  /tmp pressure 72% → 94%                    │
│  14:30 INFO  ballast release /tmp (1 file, 1 GB)        │
├─ [1-7]screens [?]help [v]VOI [b]ballast ● LIVE ────────┤
```

**Wide (150+ col):**
```
┌─ SBH v0.5.0  [LIVE]  uptime: 2h 15m ──────────────────────────── S1 Overview ──────────────────────────┐
│ CRITICAL: /tmp at 94% (est. exhaustion ~12 min)                                                         │
├─────────────────────────────────┬──────────────────────────────────────────┬─────────────────────────────┤
│ Pressure Gauges                 │ EWMA Trends (30 readings)                │ Ballast                     │
│  /home [████████░░░░] 42% GRN   │  /home ▁▂▃▃▄▃▂▂▃▄▅▆▇▆▅▄▃▂ 1.2 MB/s    │  /home ██████████ 5/5 avail │
│  /tmp  [██████████░░] 94% CRT ⚠ │  /tmp  ▃▄▅▆▇██▇▅▅▆▇█▇▆▅▅ 4.8 MB/s ⚠  │  /tmp  ██████░░░░ 3/5 (2r) │
├─────────────────────────────────┴──────────────────────────────────────────┴─────────────────────────────┤
│ Scan: 14:32:01 (5 cand, 2 del)  Scans: 42  Del: 18 (3.2 GB freed)  Err: 0  RSS: 12 MB  PID: 54321    │
├──────────────────────────────────────────────────────────────────────────────┬───────────────────────────┤
│ Activity Log                                                                 │ Performance               │
│  14:32 INFO  scan: 5 candidates, 2 deleted                                  │  render: 4ms  fps: 30     │
│  14:31 WARN  /tmp pressure 72% → 94%                                        │  p50: 3ms  p95: 8ms       │
│  14:30 INFO  ballast release /tmp (1 file, 1 GB)                            │  p99: 12ms                │
├─ [1-7]screens [?]help [v]VOI [:]palette [b]ballast ─────────────────────────────────────── ● LIVE ──────┤
```

### S2 Action Timeline

| Pane | Priority |
| --- | --- |
| Event list with severity and timestamp | P0 |
| Severity filter tabs (ALL/INFO/WARN/ERROR/CRIT) | P0 |
| Event detail pane (selected row expanded) | P1 |
| Auxiliary metrics (rate, pressure at event time) | P2 |

### S3 Explainability Cockpit

| Pane | Priority |
| --- | --- |
| Candidate header (path, size, decision, score) | P0 |
| Factor contribution bars (location/name/age/size/structure) | P0 |
| Evidence summary (posterior, loss, calibration) | P0 |
| Guard check results (open-file, min-age, protection, ancestor) | P1 |
| Related candidate/event links | P1 |
| Raw ledger payload view (L3) | P2 |

### S4 Scan Candidates

| Pane | Priority |
| --- | --- |
| Candidate table (score, size, age, action, safety) | P0 |
| Sort/filter controls | P1 |
| Factor decomposition bars (selected candidate) | P1 |
| Safety veto details | P1 |
| Raw metadata panel | P2 |

### S5 Ballast Operations

| Pane | Priority |
| --- | --- |
| Per-volume inventory + pressure linkage | P0 |
| Action controls (release/replenish with confirmation) | P0 |
| Projected free-space delta after release | P1 |
| Historical ballast events | P2 |

### S6 Log Search

| Pane | Priority |
| --- | --- |
| Search bar with query input | P0 |
| Results list with match highlighting | P0 |
| Match count and navigation (n/N) | P1 |
| Context lines around matches | P1 |
| Filter controls (type, severity, time range) | P2 |

### S7 Diagnostics

| Pane | Priority |
| --- | --- |
| Daemon status (uptime, PID, RSS, version) | P0 |
| Error summary (count by category) | P0 |
| Performance percentiles (p50/p95/p99) | P1 |
| Thread health status | P1 |
| Dropped log events count | P1 |
| Frame time history (render latency) | P2 |

---

## 7. Data Source Mapping

Every pane is backed by a specific data source. This mapping ensures adapters
(bd-xzt.2.3, bd-xzt.2.4) produce exactly the data each screen requires.

| Pane / Element | Data Source | Adapter | Staleness Handling |
| --- | --- | --- | --- |
| Pressure gauges | `state.json` → `PressureState.mounts` | `StateFileAdapter` | Fall back to `FsStatsCollector` (C-17) |
| EWMA sparklines | `state.json` → `MountPressure.rate_bps` | `StateFileAdapter` + ring buffer | Show "(no data)" if < 2 readings |
| Ballast summary | `state.json` → `BallastState` | `StateFileAdapter` | Show "(unknown)" if daemon down |
| Counters row | `state.json` → `Counters` | `StateFileAdapter` | Show "--" for each missing field |
| Last scan | `state.json` → `LastScanState` | `StateFileAdapter` | Show "(no scans yet)" |
| Activity log | SQLite telemetry DB | `TelemetryAdapter` | Show "(no database available)" (C-12) |
| Timeline events | SQLite + JSONL fallback | `TelemetryAdapter` | Degrade to JSONL if SQLite unavailable |
| Scan candidates | Live scan results or cached | `ScanResultsAdapter` | Show "(run scan first)" if no data |
| Decision records | SQLite telemetry DB | `TelemetryAdapter` | Show "(no records)" if unavailable |
| VOI scheduler | Daemon state or extended state | `VoiAdapter` | Show "(VOI disabled)" if not configured |
| Performance HUD | Local frame timing | In-process ring buffer | Always available when rendering |
| Connection dot | `state.json` mtime vs 90s threshold | `StateFileAdapter` | Green/yellow/red |
| Log search results | SQLite + JSONL | `TelemetryAdapter` | Show "(backend unavailable)" |
| Diagnostics | `state.json` + in-process metrics | `StateFileAdapter` + local | Partial data with degraded labels |

---

## 8. Degraded Mode Tiers

Per contract C-17, every screen must handle missing data sources gracefully.

| Tier | Condition | Visual Signal | Behavior |
| --- | --- | --- | --- |
| **D0: Full** | Daemon running, state fresh, telemetry available | `[LIVE]` green | All panes populated normally |
| **D1: Stale** | `state.json` older than 90s | `[STALE 2m]` yellow | Gauges show last-known values with "(stale)" suffix. Sparklines freeze. Footer dot yellow. |
| **D2: No daemon** | `state.json` missing or unparseable | `[DEGRADED]` red | Gauges use `FsStatsCollector` live stats. Rate/ballast/counters show "(daemon not running)". Footer dot red. |
| **D3: No telemetry** | SQLite and JSONL both unavailable | D0/D1/D2 + telemetry warning | Activity log, timeline, search show "(no database available)". |
| **D4: Terminal too small** | < 80 col or < 10 rows | Single line | `"Terminal too small (need 80x10, have WxH). Resize or use sbh status."` |

---

## 9. Preference Integration Points

Per bd-xzt.2.10 (preferences model), the following IA elements are
configurable through operator preferences:

| Preference | Default | Effect on IA |
| --- | --- | --- |
| `default_screen` | `1` (Overview) | Which screen loads on dashboard startup |
| `density` | `normal` | `compact`: hide P2 panes, reduce row padding. `spacious`: more padding, show all panes. |
| `hints` | `on` | `on`: key hints in footer. `off`: minimal footer. |
| `follow_mode` | `on` | S2 Action Timeline starts in follow mode |
| `show_vetoed` | `false` | S4 shows/hides vetoed candidates by default |
| `refresh_ms` | `1000` | Poll interval (min 100ms per C-03) |

**Safety visibility floor:** Regardless of density or hint settings, the
following are never hidden:
- Critical alert banner (O5)
- Connection status dot (footer)
- Pressure level badges in gauges
- Degraded mode indicators
- `[LIVE]`/`[DEGRADED]`/`[STALE]` header label

---

## 10. Accessibility

| Concern | Approach |
| --- | --- |
| Color dependence | All pressure levels use text labels (GREEN/YELLOW/ORANGE/RED/CRITICAL) alongside color. Gauge fill patterns vary per level. |
| High-contrast mode | Toggle via command palette. Replaces gradients with high-contrast pairs (black/white, black/yellow, black/red). |
| No-color mode | `--no-color` CLI flag or `NO_COLOR` env var. All color removed; info conveyed through text labels and ASCII patterns. |
| Keyboard-only | All navigation is keyboard-driven. No mouse required. Mouse click/scroll as optional enhancement. |

---

## 11. Migration Path from Current Dashboard

The current dashboard (`src/cli/dashboard.rs`, 738 lines) maps to the new IA:

| Current Section | New Location | Notes |
| --- | --- | --- |
| Header (version, mode, uptime) | Global header bar | Expanded with screen name, connection dot |
| Pressure Gauges | S1 P0 pane | Upgraded with level badges, time-to-exhaustion |
| EWMA Trends | S1 P0 pane | Upgraded with Braille sparklines |
| Last Scan | S1 P1 pane | Same data, cleaner layout |
| Ballast Status | S1 P1 pane + S5 screen | Summary on S1, detail on S5 |
| Counters/PID | S1 P1 pane | Same data, better formatting |
| Exit footer | Global footer bar | Expanded with screen tabs, connection indicator |

New screens S2–S7 and overlays O1–O6 have no equivalent in the current
dashboard.

---

## 12. Workflow-to-Screen Acceptance Mapping

| Workflow | Primary Path | Fallback Path | Completion Signal |
| --- | --- | --- | --- |
| Pressure triage | S1 → select mount → S2 or S4 | S1 → S5 if reclaim shortfall | Pressure below alert threshold |
| Incident response | S1 → S4 → review → S5 ballast | S1 → `b` quick ballast | Space recovered, pressure falling |
| Explainability | S1/S2 → S3 | Command palette → S3 | Operator sees decision + evidence |
| Candidate review | S1 → S4 | S2 cleanup event → S4 | Candidate chosen/rejected with rationale |
| Ballast response | S1 → S5 → O6 confirm | S2 ballast event → S5 | Release event in S2, reflected in S1 |
| Log investigation | S2 → S6 search | Command palette → S6 | Query answered |
| Health check | S1 counters → S7 | Command palette → S7 | Daemon healthy or issue identified |

Each major workflow is reachable from S1 in one direct navigation or one
contextual drill-down.

---

## 13. Implementation Guardrails for Downstream Beads

1. `bd-xzt.2.5` and `bd-xzt.2.6` must implement the global navigation contract
   and pane priority model exactly as defined in sections 4 and 6.
2. `bd-xzt.3.1` through `bd-xzt.3.5` must expose listed P0 panes at all
   terminal widths >= 80 columns.
3. `bd-xzt.3.11` must preserve the safety visibility floor (section 9) even
   under compact preferences.
4. `bd-xzt.4.*` verification must test:
   - Screen switching determinism (`1..7`, `[`/`]`)
   - Overlay precedence and safe escape behavior (section 4.2)
   - Workflow paths in the acceptance mapping (section 12)
   - Degraded mode tiers D0–D4 (section 8)

---

*This document is the source of truth for dashboard screen topology,
navigation flow, and information hierarchy. All bd-xzt.2* and bd-xzt.3*
implementation tasks must reference the screen numbers and pane priorities
defined here.*
