# 04 — Propose from traffic

**Status:** exists, `ui/src/pages/Intents.tsx` (356 lines), route `/intents`, nav group `ENFORCEMENT`,
icon `Crosshair`.
**Priority:** 3 of 4.
**⚠️ This page currently renders incorrectly** — see §2. Do not treat the live screen as intent.

---

## 1. What it is

The counterpart to hand-authoring. Instead of writing an allowlist from memory, this page reads what an
agent class **actually did** and proposes a deny-by-default intent from that evidence, then replays
recorded traffic against it so you can see what it would have refused *before* enforcing.

Its own framing, and it is good:

> *"Start from what the class actually did, not from memory — an allowlist written from memory is both
> too wide and missing the one tool that matters."*

Three steps: **propose → dry run → save as draft** (or hand off to the builder). Nothing here enforces —
a draft lands in a table the evaluator never reads. Enforcement only ever begins in Policy Catalog.

> ## ⚠️ Update — two of the defects below are FIXED in code
>
> Since this brief was written, §2 (broken CSS vocabulary) and §6 (the invisible, near-universal handoff
> refusal) have been fixed. Both sections are kept because they explain *why* the page looks and behaves
> as it does in any screenshot taken before that commit — but do not re-solve them.
>
> **What changed:**
> - Every undefined class is gone: the page root is now `page-enter stack`, the KPI tiles are a real
>   grid, badges are `.pill` with allow/escalate tones, buttons are `KitButton`, and the near-miss cell
>   wraps instead of scrolling horizontally.
> - `server:` / `from:` scoping now **converts** into an `mcp.server` grant fact instead of refusing.
>   It was only ever unrepresentable because a grant could not carry a scalar fact — which it now can —
>   and because the two halves spell three MCP fields differently (`server` vs `mcp.server`). The
>   refusal still exists for what genuinely has no grant form.
> - When it *does* refuse, it now says so **in place, with every reason, before the button is pressed**
>   (`data-testid="handoff-blocked"`), rather than as a tooltip on a button that looked enabled.
> - Disabled actions state their reason as visible text, because `.btn:disabled` sets
>   `pointer-events: none` and can never show a tooltip.
> - The H1 and the nav now agree: both say **Propose from traffic**.
>
> **Still open for design:** everything in §4 (rules render as raw operators and raw regexes),
> §5 (`params_available: false` deserves to be a designed state), §7 (destructive class-name edit,
> raw-JSON errors, silent dry-run), and §8 (the near-miss explainer deserves to be a component).

## 2. Read this before looking at the live page

**The page was styled against CSS classes that do not exist** *(fixed — see the update above)*.
Verified against `ui/src/index.css`:

| Class used | Reality | Visible consequence |
|---|---|---|
| `page` (bare) | undefined — only `.page-title`, `.page-sub`, `.page-enter` exist | no page-enter fade; **no vertical gap between panels** (other pages use `.stack`, gap 16px) |
| `row`, `wrap` | undefined | every "row" stacks vertically |
| `field` | undefined | the input goes full-width and the CTA drops onto its own line |
| `btn primary` | wrong — the modifier is `btn-primary` | **the primary CTA renders identical to secondary buttons** — transparent, no fill |
| `stat-row` | undefined | the KPI row stacks vertically instead of forming a row |
| `rule-list` | undefined | default `<ul>` with browser bullets |
| `badge warn` / `badge ok` | undefined — the real primitive is `.pill` | **`matched nothing` and `3 calls` render as unstyled text**, no colour, indistinguishable from each other |
| `mono-sm` | undefined | raw regexes render in the proportional font |
| `small` | undefined | hints render at body size |

`grep` confirms `Intents.tsx` is the **only** file using this vocabulary. It was written against a
different design system and never visually reviewed.

**So: the redesign starts from the page's intent, not its appearance.** Much of what looks like a layout
problem is a class-name problem, and fixing it is cheap. Judge the information architecture on its
merits.

## 3. Current structure

**PageHead** — title `Intents`, sub *"What each agent class is FOR. Anything an intent does not state is
denied."*

⚠️ **The sidebar says "Propose from traffic"; the H1 says "Intents".** Pick one. *(Opinion: the nav label
describes the job better; "intent" is the noun for the artefact.)*

**Panel "Propose from traffic"** — sub as quoted in §1. One field, `Agent class` (placeholder
`support-bot`), one button `Propose intent` (`Wand2`), busy label `Proposing…`.

That is the entire first-run page. Everything else appears only after a proposal.

### After propose
- **params warning** (conditional, §5)
- **stat tiles**: `Rules` · `Calls sampled` · `Would allow` · `Would block` (last two only after dry-run;
  `Would block` turns `#FF3B5C` when non-zero)
- **Panel "Proposed intent"** — sub *"Every rule is an ALLOW. There is no deny list — deny is the absence
  of a match."* Actions: `Dry run` (`Play`) · `Save as draft` (`FileText`) · `Open in Visual Builder`
  (`PencilLine`)
- a hint until dry-run has happened: *"Dry run this against recorded traffic before saving — the draft is
  only worth having once you know what it would have refused."*
- the rule list

### After dry run
A panel whose **title switches on the result**:
- blocking → `What this would have refused`, sub *"Each row names the rule that came closest and the
  single clause that failed — tighten the rule, or accept the denial."*
- clean → `Nothing legitimate would break`, sub *"Every recorded call is covered by a rule. That is the
  point at which this is safe to draft."*

Body: a 2-column table (`Tool` | `Why it would be denied`), or `{n} recorded calls replayed, none
refused.`

### After save
A panel: *"Draft `{id}` saved and **not enforcing**. Review and apply it from Policy Catalog — that is
the only place enforcement begins."*

## 4. How a rule is displayed — the biggest content problem

Each rule renders as a monospace id, optional badge, and **one flat interpunct-joined sentence**:

```
send-send-email                                   [3 calls]
verb is send · param_paths.to matches ^[^@]+@acme\.com$ · data_classes noneOf secret
```

Problems:
1. **Raw regexes are shown to humans.** `^[^@]+@acme\.com$` is the actual on-screen text.
2. **Raw operator names** — `noneOf`, `subsetOf`, `anyOf`, `maxCount`, `notMatches` reach the screen verbatim.
3. **`match` and `require` are flattened into one string**, though the engine's own schema notes they
   "read differently to a human": `match` = *which calls this rule is about*, `require` = *what must hold
   for them*. That is the difference between scope and condition, and it is erased.
4. **Nothing is editable.** The only way to change a proposal is to hand it to the builder.
5. Every proposed rule carries the identical trailing clause `data_classes noneOf secret` (it is
   hardcoded), so it becomes visual noise on every row.

*(Opinion: this is where the redesign earns its keep. `param_paths.to matches ^[^@]+@acme\.com$` should
read as something like **"recipient must look like `…@acme.com`"**, with the regex available on demand.)*

## 5. `params_available: false` — a first-class state

When parameter capture is off (`NRVQ_AUDIT_CAPTURE_MASKED_PARAMS`, **default off**), the audit log holds
no call arguments, so the proposal can only constrain **tool names**. Current copy:

> **Proposed from tool names only.** The audit log for this class carries no call parameters, so this
> proposal cannot constrain recipients, data classes or SQL tables. Enable parameter capture, or supply
> sample calls, before relying on a destination-level rule.

This is honest and important: the proposal degrades to exactly the thing the product says is not enough.
**Because the flag is off by default, this is the common case, not the exception.** Design it as a
primary state.

## 6. The handoff, and its invisible refusal

`Open in Visual Builder` converts the proposal into a builder graph.

When a restriction **cannot be represented** in the builder, the handoff **refuses** — it does not warn.
That is deliberate: *"A warning that can be clicked through is how the permissive version gets saved."*

**But the refusal has no visible state before you click.** The button looks identical either way; the
only pre-click signal is a multi-line native `title` tooltip. On click you get a sticky red toast in the
bottom-right, far from the button, showing only the first reason plus `(+N more)`.

⚠️ **And it fires on most real proposals.** Any rule scoped by MCP server has no allowlist-grant
equivalent — and the proposer adds server scoping to every rule derived from MCP traffic. **The refusal
is the default experience, not the edge case.**

*(Opinion: this is the single biggest UX failure on the page. The button should show its state before it
is pressed, and the reasons — all of them — should be readable in place.)*

Other refusal causes: an `answer`/`content` plane rule; a rule that doesn't scope by tool name; a nested
path like `param_paths.filters.ids[0]`; a field with no grant equivalent (`verb`, `trust`, `pin_status`).

## 7. Other defects

| # | Defect |
|---|---|
| 1 | **Editing one character of the class name silently destroys** the proposal, the dry-run report and the saved-draft banner — after a replay that may have taken seconds |
| 2 | Errors render as **raw JSON**: `{"detail":"no recorded traffic for class 'support-bot'; …"}` |
| 3 | A successful dry run pushes **no toast**; a failed one leaves the page byte-identical to before it was attempted |
| 4 | `Save as draft` and `Open in Visual Builder` have **no busy state**, unlike propose/dry-run |
| 5 | Disabled buttons can't show their tooltips (`pointer-events: none`), so "why is this disabled?" is unanswerable — and `Open in Visual Builder` disabled by `namespace = all` still shows the *enabled* tooltip |
| 6 | The blocked-calls table gets an unrequested `Filter rows…` box and `cursor: pointer` rows **with no click handler** |
| 7 | The near-miss string can list several failed clauses, in a `white-space: nowrap` cell inside a horizontal scroller — **the most important text on the page is the one guaranteed to need scrolling** |
| 8 | The panel promises *"the single clause that failed"*; the data often lists several |
| 9 | The near-miss denominator counts invisible predicates — a rule showing 3 clauses can report `met 4/6`, and the missing two appear nowhere |
| 10 | Rule cards and failure rows describe the same clause in **two different machine dialects** (`tool_name in select_rows` vs `tool_name in ['select_rows']`) |
| 11 | `Save as draft` is admin-only server-side but not gated in the UI — a viewer gets a 403 toast |
| 12 | The proposal's name, class, target namespace and rule count are never shown together |
| 13 | Zero empty state: no class entered = just a disabled button, no example, no link to find a class name |

## 8. The near-miss explainer — the page's best idea

When a replayed call is refused, the engine explains itself:

```
no intent rule matched; closest send-send-email met 3/4,
failed: param_paths.to matches ^[^@]+@acme\.com$
```

*(Opinion: this is genuinely excellent and is currently buried in a nowrap table cell below the fold. It
deserves to be a designed component — "this call missed by one clause, here is which" — not a string.)*

## 9. Required components

| Component | Exists? |
|---|---|
| `PageHead`, `Panel`, `StatTile`, `DataTable`, `KitButton`, Toast | ✅ |
| **Correct class names** | 🔧 fix — most of the visual problem |
| **Rule card** — match vs require separated, humanised predicates | ❌ new |
| **Predicate renderer** — regex → prose, with the raw form on demand | ❌ new |
| **Near-miss component** | ❌ new |
| **Pre-click disabled/refused state** with all reasons inline | ❌ new |
| **Stepper** for propose → dry-run → draft | ❌ new |

## 10. Acceptance criteria

1. The page uses classes that exist and matches the rest of the app.
2. One name for this surface, in the nav and the H1.
3. A rule reads as a sentence a security engineer can check, with the raw form available.
4. `match` and `require` are visibly different things.
5. The handoff shows whether it will refuse **before** it is clicked, with every reason readable in place.
6. `params_available: false` is designed as a primary state.
7. Editing the class name does not silently destroy work.
8. Every async action has a busy state and a result.
9. The near-miss explanation is readable without horizontal scrolling.
