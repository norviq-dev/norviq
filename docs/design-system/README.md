# Norviq Design System

**Runtime Security Platform for AI Agent Tool Calls.**

Norviq is a cloud-native security command center that monitors and enforces policies on
LLM agent tool calls in Kubernetes. It sits in the data path of agentic workloads, evaluates
every tool invocation against Rego/OPA policies, and renders a real-time verdict —
**ALLOW · BLOCK · ESCALATE · AUDIT** — while scoring the trustworthiness of each agent
identity (SPIFFE). Think *Datadog meets Wiz, for AI agent security*.

Audience: **security engineers, DevOps, and SREs** monitoring AI agent behaviour in production.
The product is a dark **SOC (Security Operations Center) command center** — premium, cinematic,
high-density. Operators live in this screen for hours; everything is tuned for fast scanning,
low eye-strain on dark surfaces, and instant colour-coded triage.

---

## Sources

This system was reverse-engineered from the product's own front-end codebase:

| Source | Location | Notes |
|---|---|---|
| Front-end app (React + TS + Vite) | `src/` (mounted via File System Access API) | Source of truth for all tokens, components, screens |
| Design tokens | `src/index.css` | Copied verbatim into `colors_and_type.css` |
| Pages | `src/pages/*.tsx` | Dashboard, PolicyCatalog, AuditLog, AgentMonitor, ThreatGraph, Settings |
| Domain components | `src/components/common/*` | ScoreGauge, DecisionBadge, TrustBadge, KPICard, DataTable, DonutChart |
| Charts | `src/components/charts/*` | CategoryBars, VolumeChart (ECharts) |
| Layout | `src/components/layout/*` | Shell, Sidebar, Header |
| Primitives | `src/components/ui/*` | shadcn/ui (Base UI flavour) — button, badge, card, table, tabs, dialog, sheet, select… |

No Figma file, slide deck, or logo asset was provided initially. The brand mark (Algiz-inspired
"Y" + lowercase **norviq** wordmark) was later supplied as artwork and processed into the
transparent PNG assets in `assets/` (see Iconography).

**Tech the product uses:** React, TypeScript, Vite, Tailwind v4, shadcn/ui (Base UI),
ECharts (`echarts-for-react`), Monaco editor (`@monaco-editor/react`) for Rego/YAML,
Lucide icons, REST at `/api/v1/*` plus a `/ws/audit` WebSocket for the live audit stream.

---

## Product surfaces (6 pages)

1. **Dashboard** — KPI strip, semicircle **Security Score** gauge, category-score bars,
   recent-blocks table, 24h tool-call volume line chart, trust-distribution donut.
2. **Policies** — Rego policy catalog grouped by namespace; Monaco editor; version history
   with restore; a detail Sheet with mode/rate-limit/keyword controls and a live YAML preview.
3. **Audit Log** — filterable, live (WebSocket) stream of every tool-call verdict; stat tiles,
   volume chart, expandable JSON event detail.
4. **Agents** — SPIFFE-identified agents with trust scores & violation counts; per-agent
   trust history, tool-usage bars, and Reset/Freeze actions.
5. **Threats** — **Threat Modeling**: attack-path graph (agents → tools → data sources), ranked
   attack paths by risk, MITRE ATLAS coverage, and high-risk filtering.
6. **Settings** — API base URL, connection test, save.

---

## CONTENT FUNDAMENTALS

How Norviq writes copy.

- **Voice: terse, operational, machine-adjacent.** This is an instrument panel, not a marketing
  site. Labels are short noun phrases — "Total Calls 24h", "Block Rate %", "Avg Latency ms",
  "Trust Distribution", "Category Scores". No articles, no filler.
- **Casing.** Labels & titles use **Title Case** ("Security Command Center", "Tool Call Volume").
  The product name is set **ALL CAPS** in the sidebar lockup (`NORVIQ`). Decision/trust pills are
  rendered **UPPERCASE** via CSS (`text-transform: uppercase`) from lowercase source values
  (`allow`, `block`, `high`, `frozen`).
- **Person.** Effectively **person-less / imperative.** Buttons are bare verbs: "Apply",
  "Dry-Run", "Restore", "Reset Trust", "Freeze Agent", "Test Connection", "Save Settings".
  No "you", rarely "your". The UI states facts about the system, not the user.
- **Numbers carry trend context, tersely.** KPI deltas read like ops shorthand:
  "↑12% vs yesterday", "↓8% false positives", "↓ healthier traffic", "↑ fast path stable".
  Arrows (↑/↓) prefix the delta; the comparison is clipped to a few words.
- **Risk is named in three tiers:** "Low Risk" / "Medium Risk" / "High Risk" (gauge),
  mirrored by trust tiers High / Medium / Low / Frozen.
- **Honest about gaps.** Unbuilt areas say so plainly: "Coming in Phase 2",
  "Mock force-directed graph wireframe", "API unavailable. Showing partial data.",
  "Status: Offline". No hype to paper over missing features.
- **Identifiers stay raw & monospaced.** SPIFFE IDs, rule IDs, namespaces, and JSON payloads
  are shown verbatim in JetBrains Mono — never prettified or truncated into prose.
- **Emoji: none.** Status is communicated with colour, the `●/○` live indicator, and arrows —
  not emoji. Keep it out.
- **Vibe:** a calm, authoritative flight deck. Confident, precise, zero exclamation marks.

Example strings, verbatim from the product:
> "Security Command Center" · "Blocked Today" · "↓8% false positives" ·
> "Agent SPIFFE contains…" · "Live ●" · "API unavailable. Showing partial data." ·
> "Confirm Restore" · "Coming in Phase 2"

---

## VISUAL FOUNDATIONS

The motifs and rules that make a screen look like Norviq.

### Colour
- **A deep navy "void" stack**, not pure black. Four background steps climb from
  `--bg-void #060b18` → `--bg-surface #0c1425` → `--bg-surface-hover #111d35`
  → `--bg-elevated #152040`. Elevation = lighter, bluer.
- **Hairline borders in `#1a2744`** separate everything; active/focused strokes brighten to
  `#2a3f6a`. Borders do the structural work that shadows would do on a light theme.
- **One interactive accent: electric blue `#3b7bf7`** (hover `#5a93ff`). Used for the logo,
  primary buttons, focus rings, the volume line, and a faint `--accent-glow` halo.
- **Four decision colours are sacred** and must never be reassigned:
  ALLOW green `#00e5a0`, BLOCK red `#ff3b5c`, ESCALATE amber `#ffb020`, AUDIT violet `#7c5cfc`.
  Trust tiers reuse the same green/amber/red plus a grey `#4a5a78` for Frozen.
- **Semantic colours appear as tinted pills**, never solid fills: text at full colour on a
  `15%`-alpha wash of the same hue with a `30%`-alpha border (e.g. `#00E5A015` bg /
  `#00E5A030` border). This keeps the dark canvas calm while staying instantly readable.
- **Text is a 3-step cool-grey ramp:** primary `#e8edf5`, secondary `#8494b2`, muted `#4a5a78`.

### Type
- **Outfit** (geometric humanist sans) for everything UI — weights 400/500/600/700/800;
  600 is the default for titles & values.
- **JetBrains Mono** (400/500) for all identifiers, code, JSON, Rego, YAML.
- Scale runs 11px → 40px (see `colors_and_type.css`). Big numerals (KPI 32px, gauge 40px) are
  the loudest type on screen; labels drop to 11px secondary-grey. Tabular numerals for stats.
- Tight tracking on large numerals (−0.02em); `0.05em` letter-spacing + uppercase on pills only.

### Backgrounds
- The app body is a **single radial gradient**: `radial-gradient(circle at top right,
  #122041 0%, var(--bg-void) 45%)` — a faint blue aurora bleeding from the top-right into black.
  This is the only gradient on the page background. No images, no textures, no repeating patterns.
- Panels add their **own subtle top-to-bottom gradient** (`rgba(18,28,48,.9) → --bg-surface`)
  plus an 8px backdrop blur for a glassy, layered-on-glass feel.

### The panel (the core container)
- `.panel`: navy vertical gradient, 1px `--border` stroke, `--radius-lg` (14px) corners,
  `box-shadow: 0 1px 3px rgba(0,0,0,.3)`, `backdrop-filter: blur(8px)`. Everything substantial
  lives in a panel. KPI cards add a coloured glow shadow keyed to their metric
  (`0 0 20px <color>20`).
- **Corner radii:** 6 / 10 / 14 / 20px. Cards = 14px, inputs/buttons ≈ 10px, pills = 4px,
  decision/trust badges = 4px (sharper than the rounded shadcn default — deliberate, terminal-like).

### Elevation & shadow
- Shadows are **quiet**: a single soft `0 1px 3px rgba(0,0,0,.3)` card shadow. Depth is
  communicated by background lightness + borders, not heavy drop shadows.
- **Glow, not shadow, signals "live/important":** the accent halo (`--shadow-glow`) and the
  per-KPI coloured glow are the only luminous effects.

### Motion
- **Restrained and fast.** Global `--transition: 150ms ease`. Page mounts fade+rise
  (`fadeIn`, 6px translateY, 0.2s ease). KPI numbers count up over 500ms via rAF.
- **Hover:** cards lift 0.5–2px (`-translate-y-0.5`); decision badges scale to 1.05;
  rows wash to `--bg-surface-hover`; ghost buttons fill with `--muted`.
- **Press:** buttons nudge down 1px (`active:translate-y-px`). No bounce, no spring, no
  long easings. Everything feels immediate, like a real console.

### Layout
- Fixed **220px sidebar** (collapses to a 56px icon rail), **64px top header**, content on a
  6px-gutter responsive grid (`gap-4`/`gap-6`). KPI strips are 4-up; charts pair 2-up; tables full-width.
- Generous internal padding (16–24px) inside dense panels keeps the data legible.

### Transparency & blur
- Used **purposefully, not decoratively:** panels blur what's behind them (glass); semantic
  pills are alpha-tinted; the sheet/dialog overlays dim the canvas. Never blur for its own sake.

---

## ICONOGRAPHY

- **System: Lucide** (`lucide-react` in source). Clean, **outline / stroke icons**, ~1.75–2px
  stroke, rounded line caps, 16–18px in the UI. This is the only icon family — keep it consistent.
- **Where icons appear:** sidebar nav (one per page), header (search, bell), and inside
  controls (chevrons, check, close, panel-toggle). They are **monochrome**, inheriting
  `currentColor` — secondary-grey at rest, primary-white or accent-blue when active.
- **Sidebar nav glyphs (exact mapping from source):**
  Dashboard → `layout-dashboard`, Policies → `clipboard-list`, Audit Log → `activity`,
  Agents → `bot`, Threats → `network`, Settings → `settings`.
- **Brand mark:** the **Algiz-inspired geometric "Y"** — two beveled blades rising from a split
  central stem — with the lowercase **norviq** wordmark (Outfit 600). Use the transparent PNGs in
  `assets/` (`norviq-mark-*.png`, `norviq-lockup-*.png`): white on dark surfaces, navy on light.
  See `assets/README.md`. The mark reads cleanly down to 16px (favicon/app icon).
- **Status glyphs, not icons:** the live indicator uses filled/hollow circles `● / ○` and a
  small coloured dot (`h-2 w-2 rounded-full`, emerald = healthy / red = down). Trend deltas use
  the arrow characters `↑ ↓`. These unicode marks are intentional and part of the vocabulary.
- **Emoji: never.**
- **How to use here:** load Lucide from CDN (`https://unpkg.com/lucide@latest`) and call
  `lucide.createIcons()`, or inline the specific SVGs. Do **not** substitute another icon set or
  draw bespoke SVG icons — match Lucide's stroke style exactly. (No icon files existed in the
  codebase to copy, so CDN Lucide is the canonical source.)

---

## Index / manifest

Root files:
- **`README.md`** — this file. Product context, content + visual foundations, iconography.
- **`colors_and_type.css`** — all design tokens (colour, type, radius, shadow, motion) as CSS
  variables, plus semantic type classes (`.norviq-h1`, `.norviq-stat`, `.norviq-code`…) and the
  `.norviq-panel` / `.norviq-app-bg` surface primitives. Import this first in any artifact.
- **`SKILL.md`** — Agent-Skills-compatible entry point for using this system.

Folders:
- **`preview/`** — small HTML specimen cards (colours, type, spacing, components) that populate
  the Design System tab.
- **`ui_kits/dashboard/`** — high-fidelity, interactive recreation of the Norviq command center
  (sidebar, header, KPI cards, gauge, charts, tables, badges, policy editor). See its README.
- **`fonts/`** — self-hosted Outfit `.ttf` files (weights 100–900); JetBrains Mono via Google Fonts.
- **`assets/`** — note on iconography/logo sourcing (Lucide via CDN; logo lockup).

No `slides/` folder exists — **no slide deck or presentation template was provided**, so none
were created. Share a deck and I'll build matching sample slides.

---

## Caveats / substitutions

- **Outfit is self-hosted** from the uploaded brand `.ttf` files in `fonts/` (weights 100–900),
  wired via `@font-face` in `colors_and_type.css`. **JetBrains Mono** is still delivered from
  Google Fonts (no local files uploaded for it; CDN delivery is fine).
- **Icons load from CDN Lucide.** The product uses `lucide-react`; the CDN build is the same
  icon set. No icon files existed to copy.
- **No logo image was provided initially**; the final mark is now in `assets/` (Algiz "Y" +
  lowercase **norviq**), keyed from supplied artwork into transparent PNGs. If you have **vector
  (SVG) source**, share it and I'll vendor an infinitely-scalable version.
