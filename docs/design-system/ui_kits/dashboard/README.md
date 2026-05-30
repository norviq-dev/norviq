# Norviq Dashboard — UI Kit

A high-fidelity, interactive recreation of the Norviq **Security Command Center** — the web
app security engineers use to monitor and enforce policy on LLM-agent tool calls in Kubernetes.
Built from the product's own React/TypeScript source (`src/`), reusing its exact tokens, layout,
and component behaviour. These are cosmetic recreations for prototyping — not production code.

## Run it
Open `index.html`. It boots a single-page app with working client-side navigation across all
six surfaces. No build step — React + Babel + ECharts + Lucide load from CDN; fonts come from
the design system's `colors_and_type.css` (Outfit self-hosted, JetBrains Mono via CDN).

## Screens (click the sidebar)
- **Dashboard** — KPI strip, semicircle Security Score gauge, category-score bars, recent-blocks
  table, 24h tool-call volume line chart, trust-distribution donut.
- **Policies** — catalog grouped by priority tier (Workload › Agent-Class › Namespace), Rego
  editor, version history with restore. Click any policy to open the **detail sheet** with the
  label-based **Policy Target** control (agent-class auto-discovery, workload override, namespace
  catch-all warning) and enforcement settings.
- **Audit Log** — filterable, **live-streaming** verdict feed (toggle Live), stat tiles, volume
  chart, click a row for the expandable JSON event detail.
- **Agents** — SPIFFE-identified agents with trust scores & violations; select one for trust
  history, tool usage, and Reset/Freeze actions (state updates live).
- **Threats** — **Threat Modeling**: an attack-path graph (agents → tools → data sources) with
  risk-glowing nodes and pulsing high-risk edges, a ranked attack-path list, MITRE ATLAS coverage,
  filters, and a "high-risk only" toggle. Click a node for details.
- **Settings** — API base URL, connection test, webhook/sidecar-injection status.

## Files
| File | Role |
|---|---|
| `index.html` | Entry point; loads scripts in order |
| `kit.css` | Component styling (shell, panel, buttons, table, tabs, sheet, editor) |
| `data.js` | Mock data shaped like `/api/v1/*` (records, agents, label-based policies, deployments) |
| `components.jsx` | `Icon`, `DecisionBadge`/`TrustBadge`, `Button`, `Panel`, `KPICard`, `Sidebar`, `Header`, `DataTable` |
| `charts.jsx` | ECharts `ScoreGauge`, `CategoryBars`, `VolumeChart`, `DonutChart` |
| `pages-dashboard.jsx` · `pages-audit.jsx` · `pages-policies.jsx` · `pages-agents.jsx` · `pages-misc.jsx` | The six pages |
| `app.jsx` | Root shell + hash routing |

## Notes & conventions
- Each `.jsx` is a `text/babel` script that exports its components to `window` (Babel scripts
  don't share lexical scope by default beyond global declarations). Edit a page in isolation.
- The signature container is `.panel` (gradient navy, hairline border, `blur(8px)`). Decision
  and trust state always render as tinted pills, never solid fills.
- The **label-based policy model** is the source of truth: deployments opt in via `norviq=enabled`
  and are classified by `norviq.io/agent-class=<class>`; policies match by workload (highest),
  agent-class (medium), or namespace (lowest). See `data.js` → `POLICIES` / `DEPLOYMENTS`.
- Charts and the policy editor are faithful visual recreations; the Rego "editor" is a static
  syntax-highlighted view (the product uses Monaco) — intentionally simplified.
