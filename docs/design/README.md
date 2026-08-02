# Norviq console redesign — design brief pack

**For:** Claude Design (or any designer producing high-fidelity mockups)
**From:** engineering, 2026-08-02
**Deliverable requested:** a professional, coherent dashboard across four surfaces

---

## 0. Read this first

Norviq is a **runtime policy enforcement point (PEP) for LLM agent tool calls on Kubernetes**. When an
agent tries to call a tool — `send_email`, `execute_sql`, `stripe_refund` — the call is intercepted and
evaluated against policy before it runs. The console is where a security operator writes and inspects
that policy.

The single idea the whole product turns on, and the one the current UI hides:

> **An allowlist of tool names is not an intent.** "This bot may call `send_email`" is what the agent
> framework's tool binding already gives you. The security control is "…and only to `@acme.com`
> recipients, and never carrying a credential." That is *argument-level* scoping, and it is Norviq's
> reason to exist.

Everything in these briefs serves making that idea visible and easy to act on.

## 1. Where the code is

| | |
|---|---|
| Repo root | `/Users/san/Documents/Development/norviq/norviq-migration/repo` |
| **Branch** | **`integrate/mcp-and-builder`** — use this, not `main` |
| HEAD at time of writing | `f41c77f` |
| Status | 59 commits ahead of `main`, **not merged**, no PR open |
| Stack | React 18 + Vite + TypeScript, React Router; FastAPI + OPA/Rego backend |
| UI source | `ui/src/` |
| Running instance | AKS, helm revision 8. `kubectl port-forward -n norviq svc/norviq-ui 3000:80` → http://localhost:3000 |

Do **not** design against `main`. The Tools API and the argument-scope editor described here exist only
on this branch.

## 2. The four surfaces

Read `00-foundations.md` first — it is the shared design system and applies to all four.

| # | Brief | Surface | Route | State |
|---|---|---|---|---|
| 1 | [`01-tools-page.md`](01-tools-page.md) | **Tools** | *(new — no route yet)* | **Does not exist.** Net-new page. |
| 2 | [`02-visual-policy-builder.md`](02-visual-policy-builder.md) | **Visual Policy Builder** | modal over `/policies/catalog` | Exists, 2,558 lines, needs restructure |
| 3 | [`03-mcp-servers.md`](03-mcp-servers.md) | **MCP Servers** | `/mcp` | Exists, structurally sound, needs elevation |
| 4 | [`04-propose-from-traffic.md`](04-propose-from-traffic.md) | **Propose from traffic** | `/intents` | Exists but **renders unstyled** — see brief |

Supporting reference: [`05-data-contracts.md`](05-data-contracts.md) — every API payload, with real
example responses you can design against.

## 3. The problems this pack exists to solve

These are the actual, observed failures. Each brief expands on the ones it owns.

### P1 — The product's core capability is invisible *(highest priority)*

In the builder's allowlist mode, a tool appears as a chip. To scope its arguments you must notice and
click a small ghost affordance on that chip reading **`+ scope`**. Nothing else on the screen suggests
per-argument scoping exists.

> Product owner, verbatim: *"in the allow list user has to click on scope to further drill down into
> scope — user does not know there is such option exists."*

This is the differentiator between Norviq and a tool allowlist, and it is behind an unlabeled chip
button. **Fixing this is the primary job of brief 02.**

### P2 — There is nowhere to see what tools exist

A `GET /api/v1/tools` registry now exists and is populated, but it is consumed only inside the builder's
autocomplete and warning logic. No page answers *"what tools does Norviq know about here, and how well
does it know them?"* **Brief 01.**

### P3 — Provenance must be visible and must never be merged

The registry returns two tiers that mean different things:

- **`mcp_declared`** — read from a definition an operator approved. Carries a JSON Schema, so its
  arguments can be scoped.
- **`observed`** — the name appeared in real traffic. Proves it exists; says nothing about its shape.

These were previously flattened into one set together with *substring fragments* (`post`, `http`,
`delete` — not tool names), and the union was treated as an existence oracle. The result: the UI
suggested names that could not exist, then suppressed its own warning for exactly those names. That bug
is fixed in code. **The design must not reintroduce it by rendering one undifferentiated list.**

### P4 — An oracle, never a gate

Deny-by-default *requires* authoring a rule for a tool nobody has called yet. So the registry informs;
it never restricts. Free text must remain everywhere. Any design that turns the tool picker into a
closed dropdown breaks the product.

### P5 — `/intents` is styled against classes that do not exist

Verified: `.row`, `.stat-row`, `.rule-list`, `.badge`, `.mono-sm`, `.field`, and bare `.page` are **not
defined** in `ui/src/index.css`, and `className="btn primary"` should be `btn btn-primary`. The page's
"KPI row" stacks vertically, its badges render as plain text, and its primary CTA looks identical to
secondary buttons. It was written against a different design system and never visually reviewed.
**Brief 04.**

### P6 — Two surfaces author the same thing

`/intents` (propose from observed traffic) and the builder (author by hand) both produce deny-by-default
policy. There is a handoff between them, and it **refuses** rather than warns when a restriction cannot
be carried across — correctly, because a warning that can be clicked through is how a weaker policy gets
saved. But the refusal has no visible state before you click. **Briefs 02 and 04.**

### P7 — Naming is inconsistent

The sidebar says **"Propose from traffic"**; the page `<h1>` says **"Intents"**. An incomplete rename.
Pick one and use it everywhere.

## 4. What "professional dashboard" should mean here

The audience is a security engineer, not a consumer. Optimise for:

- **Density with hierarchy.** They will scan 40 rows looking for one anomaly. Tables over cards.
- **Provenance and confidence, always visible.** Every claim the UI makes should show where it came
  from. This product's failure mode is confidently stating something it inferred.
- **Empty states that teach.** The default state of a fresh install is *empty* — MCP injection ships
  off. The empty state is the most-seen screen, not an edge case.
- **No fake affordances.** The current UI has rows styled `cursor: pointer` with no click handler, and
  disabled buttons whose explanatory tooltips are unreachable because `pointer-events: none`.
- **Dark only.** There is no light theme and no toggle. Do not design one. See `00-foundations.md`.

## 5. Scale to design for

| Thing | Typical | Getting started | Notes |
|---|---|---|---|
| MCP servers per namespace | 3–8 | 0–1 | 4 in the repo's own realistic fixture |
| Tool definitions (declared) | 10–40 | 0 | 12 in the fixture |
| Observed tool names | 5–30 per namespace | 0 | unbounded in a large estate; no pagination exists |
| Namespaces | 3–12 | 1 | |

**There is no pagination on any of these endpoints and no sorting in `DataTable`.** If a design needs
either, say so explicitly — it is a backend change.

## 6. How to use this pack

1. Read `00-foundations.md` — tokens, components, layout shell, and what is *missing* from the kit.
2. Read `05-data-contracts.md` — design against real payloads, not invented ones.
3. Take the surface briefs in priority order: **01 (Tools) → 02 (Builder) → 04 (Propose) → 03 (MCP)**.
4. Each brief ends with a **Required components** list and **Acceptance criteria**. Treat those as the
   contract.

Every fact in this pack was verified against source at `f41c77f`. Where something is a judgement call
rather than a fact, it is marked *(opinion)*.
