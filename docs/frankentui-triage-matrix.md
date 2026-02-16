# FrankentUI Triage Matrix (bd-xzt.1.2)

Disposition analysis of FrankentUI showcase elements for SBH TUI overhaul.
Feeds directly into the integration ADR (bd-xzt.1.3).

## Executive Summary

FrankentUI is a full custom TUI framework (20+ crates, ~4M lines) built by the
same author as SBH. It provides excellent UX patterns for operator dashboards,
but **requires nightly Rust** while SBH targets stable. Direct dependency is
blocked; selective adaptation of UX patterns and data structures is the
recommended path.

## Framework Assessment

| Property | FrankentUI | SBH Current |
| --- | --- | --- |
| Toolchain | **nightly** (rust-toolchain.toml) | **stable** (rust-toolchain.toml) |
| License | MIT (Jeffrey Emanuel) | MIT (Jeffrey Emanuel) |
| TUI backend | ftui-tty (custom) + crossterm (legacy) | crossterm 0.28 (optional, `tui` feature) |
| Architecture | Elm-style model/update/cmd (ftui-runtime) | Direct crossterm draw loop |
| Render pipeline | ftui-render (custom cells, frames) | Raw crossterm queue/execute |
| Widget library | ftui-widgets (50+ widgets) | Hand-rolled gauges/sparklines (738 lines) |
| Layout engine | ftui-layout (constraint-based, Flex) | Fixed grid with manual cursor positioning |
| Dependency count | ~25 direct + deep transitive tree | Minimal (crossterm only for TUI) |
| Edition | 2024 | 2024 |

## Showcase Screen Disposition Matrix

### Tier 1: MUST COPY (direct SBH feature mapping)

These screens implement UX patterns that map directly to existing or planned SBH
operator workflows. Their designs should be adapted into SBH's TUI.

| Screen | Size | SBH Mapping | Disposition | Key Elements to Extract |
| --- | --- | --- | --- | --- |
| `dashboard.rs` | 175KB | `sbh dashboard` / `sbh status --watch` | **ADAPT** | Multi-panel layout (pressure gauges, sparkline charts, bar charts, counters, activity log). Animated gradient title. Responsive reflow (40x10 to 200x50+). Real-time data refresh pattern. |
| `explainability_cockpit.rs` | 48KB | `sbh explain --id` | **ADAPT** | Evidence ledger view with timeline. DiffSummary/ResizeSummary data models. Compact timeline rendering. Posterior/Bayes factor display. Panel focus navigation. |
| `action_timeline.rs` | 54KB | Activity log in daemon loop | **ADAPT** | Event stream viewer with severity-based filtering. Ring buffer event storage. Detail panel for selected events. Follow mode (auto-scroll). Deterministic event generation pattern. |
| `voi_overlay.rs` | 27KB | VOI scheduler visualization | **ADAPT** | VoiDebugOverlay widget with decision/posterior/observation/ledger sections. VoiSampler snapshot display. Section focus navigation. Expandable detail mode. |
| `log_search.rs` | 84KB | JSONL log viewing | **ADAPT** | LogViewer widget with live streaming, `/` search, `n`/`N` navigation, filter mode, case sensitivity toggle, context lines toggle, match count indicator. |
| `notifications.rs` | 21KB | `sbh` notification channels | **ADAPT** | Toast notification queue with priority, auto-dismiss, manual dismiss, action buttons. Position-aware rendering. Queue lifecycle management. |
| `command_palette_lab.rs` | 32KB | Command navigation within TUI | **ADAPT** | Command palette with fuzzy/prefix/substring matching. Bayesian scoring for hint ranking. Evidence ledger for ranking transparency. |

### Tier 2: SHOULD ADAPT (useful UX patterns, domain-specific data needed)

| Screen | Size | SBH Mapping | Disposition | Key Elements to Extract |
| --- | --- | --- | --- | --- |
| `performance_hud.rs` | 54KB | Daemon health / self-monitor display | **ADAPT** | FPS/latency ring buffer. Percentile computation (p50/p95/p99). Braille sparklines. Degradation tier indicators. Stress/overload detection. |
| `accessibility_panel.rs` | 18KB | Operator accessibility | **ADAPT** | High-contrast toggle, reduced-motion toggle, screen-reader hints. Good UX practice for operator tooling. |
| `async_tasks.rs` | 154KB | Scan/deletion progress visibility | **ADAPT (selective)** | Task progress tracking, status indicators, cancelation. Only the progress display pattern is needed; the async runtime itself is not. |
| `data_viz.rs` | 33KB | Pressure trend visualization | **ADAPT (selective)** | Data charting patterns for time-series pressure data. |

### Tier 3: REJECT (demo-only, not needed for SBH)

| Screen | Size | Reason for Rejection |
| --- | --- | --- |
| `visual_effects.rs` | 167KB | Plasma/particle effects. Visually impressive but has no operator utility. |
| `mermaid_showcase.rs` | 225KB | Diagram rendering. Not relevant to disk-pressure monitoring. |
| `mermaid_mega_showcase.rs` | 289KB | Extended diagram rendering. Same as above. |
| `shakespeare.rs` | 62KB | Text rendering demo with Shakespeare corpus. No SBH relevance. |
| `quake.rs` | 36KB | Game demo (Quake-style rendering). Entertainment only. |
| `theme_studio.rs` | 68KB | Interactive theme customization. Overkill for SBH's fixed operational UI. |
| `code_explorer.rs` | 84KB | Source code browsing. Not an SBH workflow. |
| `drag_drop.rs` | 36KB | Drag-and-drop demo. No operator need. |
| `kanban_board.rs` | 40KB | Kanban board. Not relevant to disk monitoring. |
| `form_validation.rs` | 28KB | Form validation demo. SBH config is file-based. |
| `forms_input.rs` | 44KB | Form input demo. Same as above. |
| `intrinsic_sizing.rs` | 27KB | Layout engine sizing demo. Framework-internal concern. |
| `layout_lab.rs` | 72KB | Layout experimentation. Framework-internal. |
| `layout_inspector.rs` | 30KB | Layout debugging. Framework-internal. |
| `determinism_lab.rs` | 46KB | Determinism testing. Relevant to FrankentUI internals, not SBH. |
| `advanced_text_editor.rs` | 66KB | Text editor. Not an SBH workflow. |
| `file_browser.rs` | 39KB | File browsing. SBH's scanner handles file discovery differently. |
| `hyperlink_playground.rs` | 18KB | Hyperlink rendering demo. Minimal operator value. |
| `i18n_demo.rs` | 50KB | Internationalization. SBH is English-only for now. |
| `markdown_live_editor.rs` | 24KB | Markdown editing. Not relevant. |
| `markdown_rich_text.rs` | 43KB | Rich text rendering. Could be useful for help text but low priority. |
| `mouse_playground.rs` | 86KB | Mouse interaction demo. SBH is keyboard-driven. |
| `snapshot_player.rs` | 83KB | Snapshot playback. Framework testing tool. |
| `table_theme_gallery.rs` | 42KB | Table theming. SBH needs tables but not theme galleries. |
| `terminal_capabilities.rs` | 84KB | Terminal detection. SBH can rely on crossterm's detection. |
| `virtualized_search.rs` | 74KB | Virtualized search demo. Pattern is useful but scope is demo-specific. |
| `widget_gallery.rs` | 73KB | Widget showcase. Demo-only meta-screen. |
| `widget_builder.rs` | 36KB | Widget builder. Framework authoring tool. |
| `responsive_demo.rs` | 22KB | Responsive layout demo. The pattern matters; the demo does not. |
| `inline_mode_story.rs` | 22KB | Inline mode demo. SBH uses alt-screen, not inline. |
| `advanced_features.rs` | 32KB | Advanced feature demo. Meta-screen. |
| `macro_recorder.rs` | 55KB | Macro recording. No operator need. |

## Widget Library Triage

Key ftui-widgets components relevant to SBH:

| Widget | ftui-widgets Source | SBH Need | Disposition |
| --- | --- | --- | --- |
| `sparkline.rs` (18KB) | Braille + block sparklines | Pressure rate trends | **ADAPT** — SBH already has a basic sparkline; upgrade to Braille encoding |
| `progress.rs` (34KB) | MiniBar, progress bars | Pressure gauges, scan progress | **ADAPT** — SBH has render_gauge; upgrade with color gradients |
| `table.rs` (87KB) | Rich tables with sorting/scrolling | Stats, blame, scan results | **ADAPT** — replace hand-rolled tables with proper widget |
| `log_viewer.rs` (73KB) | Streaming log with search/filter | JSONL log display | **ADAPT** — high value for operator debugging |
| `toast.rs` (94KB) | Toast notifications | Alert display | **ADAPT (selective)** — only the rendering pattern |
| `notification_queue.rs` (30KB) | Notification queue management | Alert queue lifecycle | **ADAPT** — queue logic is framework-independent |
| `command_palette/` | Fuzzy command search | TUI command navigation | **ADAPT** — the matching algorithm is reusable |
| `panel.rs` (24KB) | Panel containers | Dashboard sections | **ADAPT** — extract layout pattern |
| `badge.rs` (5.6KB) | Status badges | Pressure level badges | **ADAPT** — small, self-contained |
| `status_line.rs` (19KB) | Status line widget | Footer/header bars | **ADAPT** — extract pattern |
| `voi_debug_overlay` | VOI debug display | VOI scheduler overlay | **ADAPT** — data model and display pattern |
| `block.rs` (32KB) | Block containers with borders | Section containers | **ADAPT** — standard widget pattern |

## Dependency and Toolchain Impact

### Direct FrankentUI Dependencies (if vendored)

| Crate | Required By | Stable Rust? | Notes |
| --- | --- | --- | --- |
| `ahash` 0.8 | ftui-core, ftui-widgets | Yes | Alternative HashMap hasher |
| `arc-swap` 1.8 | ftui-core | Yes | Atomic pointer swap |
| `bitflags` 2.10 | ftui-core, ftui-widgets | Yes | Flag types |
| `unicode-width` 0.2 | ftui-core, ftui-text, ftui-widgets | Yes | Character width |
| `unicode-segmentation` 1.12 | ftui-core, ftui-text, ftui-widgets | Yes | Grapheme clusters |
| `unicode-display-width` 0.3 | ftui-core | Yes | Display width |
| `web-time` 1.1 | ftui-core, ftui-widgets, ftui-runtime | Yes | WASM-compat time |
| `signal-hook` 0.4 | ftui-core (Unix) | Yes | Already in SBH (0.3) |
| `crossterm` 0.29 | ftui-core (optional) | Yes | SBH uses 0.28 |
| `tracing` 0.1 | ftui-runtime, ftui-widgets | Yes | Structured logging |
| `im` 15.1 | ftui-runtime (optional, hamt) | Yes | Persistent data structures |

### Nightly-Only Features Used by FrankentUI

FrankentUI's `rust-toolchain.toml` specifies nightly. Areas where nightly
features may be used (requires deeper audit by bd-xzt.1.6):

- Potential use of unstable `#[feature(...)]` attributes
- SIMD optimizations in ftui-simd crate
- Potential nightly-only compiler flags or lints

### Impact on SBH's Stable Toolchain

**BLOCKER**: FrankentUI cannot be added as a direct cargo dependency without
switching SBH to nightly. This is unacceptable per SBH's stability guarantees.

**Mitigation strategies** (ranked by preference):

1. **Selective adaptation** (RECOMMENDED): Extract UX patterns, data models, and
   rendering logic from showcase screens. Re-implement using SBH's existing
   crossterm backend or ratatui (stable-compatible). Zero new framework deps.

2. **Selective vendoring**: Copy specific self-contained widget source files
   (badge.rs, sparkline.rs) into SBH's codebase, adapting them to use crossterm
   directly instead of ftui-render. Requires per-file audit for nightly usage.

3. **ratatui bridge**: Adopt ratatui (which shares conceptual DNA with
   FrankentUI but works on stable) as SBH's TUI framework, then adapt
   FrankentUI's screen designs to ratatui's widget API.

4. **Full vendor** (NOT RECOMMENDED): Copy entire ftui-* workspace into SBH.
   Massive complexity increase, forces nightly, and creates a maintenance burden
   for framework-level code that is not SBH's core competency.

## Risks and Mitigations

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Nightly lock-in from direct dependency | **Critical** | Use selective adaptation (strategy 1). Never add ftui-* to Cargo.toml. |
| Dependency fan-out bloating SBH binary | **High** | Adapt patterns, not dependencies. SBH's `opt-level = "z"` and `strip = true` require lean deps. |
| UX design drift from FrankentUI upstream | **Low** | SBH adapts designs once; it does not track upstream. Forked UX is intentional. |
| Adapted code quality divergence | **Medium** | Apply SBH's pedantic+nursery clippy lints to all adapted code. Run `rch exec "cargo clippy"` on every change. |
| Performance regression from richer TUI | **Medium** | SBH dashboard is polled at configurable intervals (min 100ms per C-03). Budget rendering within poll interval. FrankentUI's perf-hud patterns provide the monitoring primitives. |
| Accessibility gap | **Low** | Adapt FrankentUI's accessibility panel patterns. Ensure high-contrast mode works with SBH's `colored` output. |
| Loss of zero-write emergency mode | **Critical** | New TUI features must remain optional (`tui` feature gate). Emergency mode must never depend on TUI code paths. |

## Ranked Shortlist: "Must Copy" UX Elements

Priority-ordered list of UX elements that should be adapted from FrankentUI
into SBH's TUI overhaul:

| Rank | Element | FrankentUI Source | SBH Target | Contract IDs Affected |
| --- | --- | --- | --- | --- |
| 1 | Multi-panel dashboard layout | `dashboard.rs` | `src/cli/dashboard.rs` | C-06, C-18 |
| 2 | Pressure gauge with color gradients | `dashboard.rs` (MiniBar usage) | Dashboard pressure section | C-09, C-18 |
| 3 | EWMA sparkline with Braille encoding | `dashboard.rs` (Sparkline usage) | Dashboard rate trends | C-10, C-18 |
| 4 | Evidence ledger view | `explainability_cockpit.rs` | `sbh explain` TUI mode | New capability |
| 5 | Action timeline with severity filters | `action_timeline.rs` | Dashboard activity panel | C-12, C-18 |
| 6 | Log viewer with search/filter | `log_search.rs` (LogViewer) | JSONL log inspection | New capability |
| 7 | VOI overlay | `voi_overlay.rs` (VoiDebugOverlay) | VOI scheduler display | New capability |
| 8 | Command palette | `command_palette_lab.rs` | TUI command navigation | New capability |
| 9 | Toast notification queue | `notifications.rs` | Alert display in dashboard | New capability |
| 10 | Performance HUD (latency percentiles) | `performance_hud.rs` | Daemon health panel | New capability |
| 11 | Ballast bar chart | `dashboard.rs` (BarChart) | Dashboard ballast section | C-11, C-18 |
| 12 | Keyboard shortcut help overlay | `dashboard.rs` (HelpEntry) | Dashboard help | C-16 |

## Conclusion

FrankentUI provides outstanding UX design patterns for the SBH TUI overhaul.
The critical constraint is the nightly toolchain requirement, which makes direct
dependency impossible. **Selective adaptation** — extracting UX designs, data
models, and rendering patterns while re-implementing them on SBH's stable
crossterm (or ratatui) foundation — is the recommended strategy.

This analysis is actionable for the integration ADR (bd-xzt.1.3) without
requiring re-research of FrankentUI's codebase.

---

*Generated by TanBasin for bd-xzt.1.2. References baseline contract from
bd-xzt.1.1 (`docs/dashboard-status-contract-baseline.md`). Licensing analysis
delegated to bd-xzt.1.6 (PearlSeal).*
