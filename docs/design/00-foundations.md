# 00 — Foundations: the existing design system

Everything here was read from source at `f41c77f`. Only **two** stylesheets exist in the whole app:
`ui/src/index.css` (680 lines, global) and `ui/src/components/policies/BuilderSteps.css` (357 lines,
builder only). There is no `App.css`.

---

## 1. Theme: dark only, no light variant

`ui/index.html:2` is `<html lang="en" class="dark">` — hard-coded. There is **no theme switcher, no
`localStorage` key, no `data-theme` attribute, and zero `prefers-color-scheme` rules** in the built
stylesheet. Every token below is the only value.

**Do not design a light mode.** If you believe one is needed, raise it as a separate proposal.

## 2. Colour tokens — `ui/src/index.css:24-116`

### Surfaces
| Token | Value | Use |
|---|---|---|
| `--bg-void` | `#0d0d0d` | page background |
| `--bg-surface` | `#171717` | panels, cards |
| `--bg-surface-hover` | `#1f1f1f` | row hover, secondary button |
| `--bg-elevated` | `#252525` | inputs, popovers, nested panels |
| `--bg-sidebar` | `#121212` | sidebar panel |
| `--border` | `#2a2a2a` | default border |
| `--border-active` | `#3a3a3a` | hover/active border |

### Text
| Token | Value |
|---|---|
| `--text-primary` | `#ffffff` |
| `--text-secondary` | `#a0a0a0` |
| `--text-muted` | `#666666` |
| `--text-faint` | `#555555` |

### Decision colours — the four canonical semantics
| Token | Value | Means |
|---|---|---|
| `--allow` | `#00e5a0` | allowed / healthy / pinned |
| `--block` | `#ff3b5c` | blocked / drift / critical |
| `--escalate` | `#ffb020` | warning / awaiting approval / needs attention |
| `--audit` | `#7c5cfc` | observe-only / neutral-informational |

Aliases exist because ~29 call sites used undefined names: `--success`→allow, `--danger`→block,
`--warning`→escalate, `--good`→allow.

### Brand accent
`--accent: #2ddab8` (teal) · `--accent-hover: #5ae8cc` · `--accent-glow: #2ddab830`.
Also `--section-title: #2ddab8` and `--chart-line: #2ddab8`.

### Trust
`--trust-high: #00e5a0` · `--trust-medium: #ffb020` · `--trust-low: #ff3b5c` · `--trust-frozen: #666666`.

### Alpha convention — important
Status pills are built from a **literal hex + 2-digit alpha suffix** triple, not from `rgba()`:

```
background: <HEX>15   (≈8%)
color:      <HEX>
borderColor:<HEX>30   (≈19%)
```

e.g. allow = `#00E5A015` / `#00E5A0` / `#00E5A030`. Reuse this exact recipe for any new status colour.

> There is an **enforced test** — `ui/src/lib/palette-consistency.test.ts` — that fails the build if new
> colours drift from the palette. Introducing a novel hex will break CI.

## 3. Radius

Effective values (the app's plain `:root` px values beat Tailwind's layered `calc()` ones):
`--radius-sm: 6px` · `--radius-md: 10px` · `--radius-lg: 14px` · `--radius-xl: 20px`.
Pills use a hard-coded `border-radius: 4px`.

## 4. Typography

- **Sans: Outfit**, self-hosted TTF, 9 weights (100–900) at `ui/public/fonts/`. Not an npm dep.
- **Mono: JetBrains Mono** via `@fontsource/jetbrains-mono`, **only weights 400 and 500 are imported.**
  Do not specify mono 600/700 — it will synthesise.

⚠️ **The declared type scale is dead.** `--text-4xl … --text-xs` exist in `:root` but have **zero
consumers**. Real sizes are hard-coded. The ones actually in use:

| Context | Size | Weight |
|---|---|---|
| `.page-title` | 22px | 600 |
| `.page-sub` | 13px | — |
| `.panel-title` | 16px | 600 |
| `.panel-sub` | 12px | — |
| `.kpi-value` | 32px | 600, `tabular-nums` |
| StatTile value | 24px | 600, `tabular-nums` |
| `.kpi-label` | 11px | 500 |
| `.btn` | 14px | 500 |
| `.tbl th` | 11px | 500 |
| `.tbl td` | 13px | — |
| `.pill` | 11px | 600, uppercase, `letter-spacing: .03em` |
| Builder inline controls | 11.5px | — |
| Builder hints | 10.5px | — |

*(Opinion: the 10.5/11.5px sizes in the builder are below the rest of the app and are part of why that
surface feels cramped. A redesign may raise them — say so if you do.)*

`.mono` class = `font-family: var(--font-mono)`. Applied to every identifier: tool names, agent classes,
digests, rego.

## 5. Component kit — `ui/src/components/common/`

These exist and should be reused. Anything you invent beyond them is new engineering work — flag it.

### `KitButton`
`variant`: `primary | secondary | outline | ghost | destructive | save` (default `primary`).
`size?: "sm"`. `icon?: LucideIcon` — always rendered leading at **15px**.

| Variant | Background | Colour |
|---|---|---|
| primary | `--accent` #2ddab8 | `#fff` |
| secondary | `--bg-surface-hover` | `--text-primary` |
| outline | `--bg-elevated`, border `--border-active` | `--text-primary` |
| ghost | transparent | `--text-secondary` |
| destructive | `#ff3b5c20` | `--block` |
| save | `--allow` #00e5a0 | `#04130d` |

Base: `height: 32px; padding: 0 14px; radius: 10px; font-size: 14px; gap: 7px`. `sm`: `27px / 0 10px /
13px / radius 8px`.

⚠️ `.btn:disabled { pointer-events: none }` — **a disabled button cannot show a `title` tooltip.** The
current UI relies on exactly that and the explanation never appears. If a control is disabled, its reason
must be rendered as visible text, not a tooltip.

### `Panel`
Props: `title?, sub?, action?, pad? (default true), className?, style?, children, data-testid?`.
`background: --bg-surface; border: 1px solid --border; radius: 14px; box-shadow: 0 1px 3px rgba(0,0,0,.3)`.
`.panel-pad { padding: 18px }`. Head is flex space-between: title (16/600) + sub (12/secondary) left,
`action` right.

⚠️ `.panel` has `backdrop-filter: blur(8px)`, which makes **every panel its own stacking context**. Any
tooltip or popover that must escape a panel has to be portaled. This is already documented in-code as
the reason chart tooltips are portaled.

### `PageHead`
Props: `title, subtitle?, actions?`. Renders `.page-head` (flex, space-between, `margin-bottom: 20px`)
with `h1.page-title` + `.page-sub`, and `.page-actions` (flex, gap 10) on the right.
**Every page uses this.** New pages must.

### `StatTile`
Props: `{ label, value: number, color? }`. A `Panel` with an 11px label and a 24px `tabular-nums` value,
`value.toLocaleString()`. Used by MCP Servers, Intents, Agent Monitor.

### `KPICard`
Props: `{ label, value, trend?, color?, testid? }`. 32px value with a 500ms count-up animation. Currently
**only used on the Dashboard**. A hover *lift* was deliberately removed because it faked a click
affordance — don't reintroduce it.

### `DataTable`
Props: `{ columns, rows, onRowClick?, selectedKey?, rowKey?, filterable? (default true), placeholder? }`.

- **No sorting. No pagination.** Callers pass pre-ordered rows.
- Filtering is a substring match over `JSON.stringify(row)` — crude but global.
- `.tbl th` 11px/500/secondary, `.tbl td` 13px, `border-top: 1px solid --border`, **`white-space: nowrap`**
  with an `overflow-x: auto` wrapper.
- Missing values render as `—`.
- Rows are `cursor: pointer` with hover background **whether or not `onRowClick` is provided** — a real
  fake-affordance bug on `/intents`.
- Two hard-coded responsive rules: a column keyed `session_id` hides below 1440px, `latency_ms` below
  1024px.

### `DecisionBadge` / `TrustBadge` / `.pill`
`.pill { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; padding:
3px 8px; border-radius: 4px; border: 1px solid }`. `.pill.hoverable:hover { transform: scale(1.05) }`.
`DecisionBadge` takes `allow | block | escalate | audit`; unknown values fall back to `audit`.

### `Toast` — the only async-feedback surface
Bottom-right, max-width 420px, `role="alert"`. Kinds: success / error / warning / info. **Error toasts
are sticky until dismissed.** Testids `toast-success`, `toast-error`, etc.

⚠️ Errors currently surface as **raw response bodies** — `apiSend` throws `new Error(await
response.text())`, so a 422 toast literally reads `{"detail":"no recorded traffic for class …"}`, braces
and all. Any design showing an error state should assume this needs fixing.

### Others available
`BrandLoader` / `BrandLoaderOverlay` (canonical loading mark), `ApplyResultPanel`, `SystemHealthBanner`
(global outage strip), `ClusterScoped` / `RemoteClusterNotice` (remote-cluster placeholder), `FreshnessBadge`,
`PolicyHierarchy`, `FrameworkEmblem`.

## 6. Layout shell

`Shell.tsx`: `.app` → **`Sidebar` (icon rail + expandable panel)** → `.main.main-content` → `Header` →
`SystemHealthBanner` → `<main class="content">{page}</main>`.

### Sidebar — two levels
A narrow **icon rail** switches *sections*; an **expanded panel** lists that section's groups.

**Section `SECURITY OPERATIONS`**
- group `ENFORCEMENT`: Policy Catalog `/policies/catalog` · Policy Packs `/policies/packs` · Target Settings `/policies/targets` · **Propose from traffic `/intents`** (icon `Crosshair`)
- group `MONITORING`: Audit Log `/audit` · Agents `/agents` · **MCP Servers `/mcp`** (icon `Plug2`)
- group `TESTING`: Policy Tester `/test` · Red Team `/redteam`
- group `COMPLIANCE`: Compliance `/compliance`

**Section `OVERVIEW`**
- group `ANALYTICS`: Overview
- group `THREAT INTEL`: Asset Graph · Attack Graph

**➡️ The new Tools page needs a home.** Recommendation *(opinion)*: `MONITORING`, directly above
`MCP Servers`, since it is inventory rather than enforcement.

### Header / topbar
Namespace selector (`All namespaces` ▾) · **time-range chip group (`1h 6h 24h 7d 30d`)** · global search
(`⌘K`) · notifications · account avatar.

The time-range chips currently appear on Overview. **The Tools page should use them** — `GET
/api/v1/tools` takes a `range` parameter (`24h | 7d | 30d | 90d`, default `30d`) that governs the
observed tier's window.

## 7. Icons

`lucide-react`, **61 distinct icons already imported.** Prefer these. Ones relevant to these briefs:
`ShieldCheck`, `ShieldAlert`, `AlertTriangle`, `CheckCircle2`, `XCircle`, `RefreshCw`, `Plug2`,
`Crosshair`, `Wand2`, `Play`, `FileText`, `PencilLine`, `Plus`, `X`.

Standard sizes: **15px inside buttons**, 12–14px inside pills and inline hints, 16px in panel heads.

## 8. Charts

**ECharts 6** (5 components: donuts + bars) and **D3 7** (2 graph canvases). Monaco for the rego editor.
Chart slots: `--chart-1: #2ddab8`, `--chart-2: #00e5a0`, `--chart-3: #ffb020`, `--chart-4: #ff3b5c`,
`--chart-5: #7c5cfc`. Donut track `--donut-track: #1f1f1f`.

There is a shared ECharts tooltip style block copied into four chart files — reuse it rather than
inventing tooltip styling.

## 9. Spacing and responsive

`.stack { display: flex; flex-direction: column; gap: 16px }` is the standard page rhythm — **every page
root should be `className="page-enter stack"`**. Panel padding 18px. Page-head margin-bottom 20px.
Grid gaps 5 (20px) via Tailwind utilities.

Breakpoints in real use: **1439px** (laptop) and **1023px** (tablet), via `hide-laptop` / `hide-tablet`
utility classes that are `display: none !important`.

## 10. Classes that do NOT exist — do not assume them

Verified absent from `index.css`. `/intents` uses all of these, which is why it renders wrong:

`.row` · `.wrap` · `.field` · `.stat-row` · `.rule-list` · `.badge` (and `.badge warn` / `.badge ok`) ·
`.mono-sm` · `.small` · bare `.page`

Also: the button modifier is **`.btn-primary`**, not `.btn primary` (space = descendant selector).

Real equivalents: `.stack` for vertical rhythm, `.pill` for badges, `.muted` for de-emphasis,
`.page-enter` for the page fade, `.mono` for monospace, `.field-label` for form labels.

## 11. What the kit is missing

Things these briefs need that **do not exist yet** and are new engineering work:

1. **A tree / disclosure component** — for rendering a tool's nested argument structure.
2. **A multi-select / token input** — every "list of values" today is a comma-separated text box.
3. **Table sorting and pagination** — `DataTable` has neither.
4. **A segmented control** — mode switching is done with bespoke cards in the builder.
5. **A side-by-side diff** — MCP Servers renders approved-vs-served as two `<pre>` blocks.
6. **An inline "why is this disabled" pattern** — required because disabled buttons can't show tooltips.
7. **A provenance badge** — for `declared` vs `observed`. Central to briefs 01 and 02.
