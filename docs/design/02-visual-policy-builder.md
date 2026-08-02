# 02 — Visual Policy Builder

**Status:** exists. `ui/src/components/policies/BuilderSheet.tsx` — **2,558 lines**, one component.
Own stylesheet: `ui/src/components/policies/BuilderSteps.css` (357 lines).
**Priority:** 2 of 4. **This brief owns problem P1, the most important issue in the pack.**

---

## 1. What it is

A full-screen sheet over `/policies/catalog`, opened from `Create ▸ Visual Builder`. It compiles a
click-authored graph into OPA/Rego **in the browser, live**, with the generated policy shown in a
read-only Monaco pane on the right. Save requires a passing dry-run against recorded traffic.

Layout today: an overlay `.sheet`, split roughly **50/50** — authoring steps on the left, compiled rego
on the right.

## 2. The problem this redesign exists to fix

> **P1 — the product's core capability is invisible.**

In **Allowlist mode**, each allowed tool renders as a chip:

```
┌─────────────────────────────┐
│ stripe_refund   + scope   × │      ← unscoped
└─────────────────────────────┘
┌─────────────────────────────┐
│ http_post     scoped · 2  × │      ← scoped
└─────────────────────────────┘
```

`+ scope` is a small ghost affordance inside the chip. Its `title` is *"Scope {tool} by its arguments"*.
Clicking it opens the panel where the entire value of the product lives — the place you say *"…and only
to `@acme.com` recipients"*.

**Nothing else on the screen indicates that panel exists.** The step is titled "What should it do?", the
section is titled "ALLOWED TOOLS", and the visible mental model is "type tool names into a list." An
operator can complete the whole flow — author, dry-run, save, enforce — and never learn that argument
scoping is available.

The consequence, in the product's own words (from the generated policy header): a hand-written allowlist
*"restates the agent framework's tool binding instead of adding a control."*

**Success for this brief = an operator who has never used Norviq understands, without being told, that a
tool can be narrowed by its arguments — and does it.**

## 3. Current structure (what you are redesigning)

Three numbered steps down the left, each collapsible with a `✓ Done` marker.

### Step 1 — "Who is this policy for?"
Three tier cards, exactly one selected:

| Card | Copy |
|---|---|
| **Agent class** | "Every agent of one class, across the namespace." · e.g. `report-gen` |
| **Namespace** | "Every agent in one namespace, whatever its class." · e.g. `default` |
| **Workload** | "One Deployment's agents only." · e.g. `checkout` · *"Deployments only — other workload kinds are never evaluated."* |

Then: `Agent class` text input, `Target namespace` input.

### Step 2 — "What should it do?"
Two mode cards:

| Card | Copy |
|---|---|
| **Tighten-only rules** | "Add blocks on top of what's already allowed. Everything not matched keeps its current outcome." |
| **Allowlist (deny by default)** | "Deny everything for this scope except the tools you list." |

⚠️ **These two modes invert the meaning of a condition.** The same clause `data_classes noneOf [secret]`
means *"allowed only if it carries no secret"* in allowlist mode and *"BLOCK when it carries no secret"*
in rules mode. This is a genuine cognitive hazard and the current cards do not convey it. *(Opinion: the
mode choice deserves more than two cards of equal weight — it changes the meaning of everything below.)*

#### Rules mode body
Rule cards → condition rows (`ConditionChip`). Condition types offered: detector, keyword, tool name is
one of, trust below, source+verb, parameter regex. Each has a label and a hint line.

#### Allowlist mode body
- `ALLOWED TOOLS` + explanatory line: *"Every tool call for this class is BLOCKED by default — only the
  tools listed below are allowed (and only when every enabled refinement below also holds)."*
- tool name input (`+ Add`), with a registry-backed datalist and three warning states (§5)
- the chip list
- **the per-tool scope panel** — the thing nobody finds
- `REFINEMENTS`: four checkboxes — `Read-only`, `No external egress`, `Namespace-scoped`,
  `Rate-limit (advisory)`

### The scope panel (currently behind `+ scope`)
Header: *"When `{tool}` is called, allow it only if:"*
Sub: *"Every line must hold. A parameter that isn't supplied fails its line — so omitting an argument
can't be used to skip a constraint."*

Two kinds of row, which read left-to-right as sentences:

**Constraint rows** — address ONE named argument (`tool_params[field]`):
`field · verb · value · ×` plus a full-width hint.
Verbs: must match · must NOT match · must be one of · must not be any of · at most · must be present ·
must be absent · host must be one of.
Hints are copy-pasteable, e.g. *"e.g. `(?i)^\s*select\b` — only read statements"*.

**Fact rows** — engine-derived facts about the **whole call**:
`field(read-only) · verb · value · ×`.
Field labels: *data it carries* · *SQL tables* · *any parameter value* · *recipient addresses* ·
*destination URLs* · *destination hosts* · *URL schemes* · *payload size (bytes)* · *call depth* ·
*agent trust score* · *operation verb* · *MCP pin status* … and, new, **`argument <path>`** for a
tool's own declared arguments.
Verbs: must not include · must be within · must include one of · at most (count) · at most · at least ·
is exactly · is one of · matches regex · does NOT match regex.

Two add-dropdowns at the bottom: `+ scope what it carries / reaches…` and `+ add a constraint…`.
The first now has **two optgroups**: `{tool} arguments (declared)` — the tool's own arguments, with
unusable ones disabled and the reason inline — and `what the call carries or reaches`.

### Step 3 — "Check & enforce"
`Run dry-run` · `Save & enforce` · `Cancel`, plus the dry-run result panel.

### Right pane
`COMPILED REGO (LIVE, READ-ONLY)` — Monaco, plus a stats line: `5,941 / 65,536 bytes · 78 / 500 lines ·
0 / 25 regex ops`.

## 4. Design direction *(opinions — argue with them)*

### 4a. Make scoping a visible step, not a hidden drill-down
Options worth exploring:
- Give each allowed tool a **row**, not a chip — with its scope summarised inline and always visible
  (`send_email — any arguments` vs `send_email — recipients within @acme.com`). A row has room to
  advertise; a chip does not.
- Show, per tool, **what could be scoped**: for a declared tool with a schema, "5 arguments available".
  That single fact would have solved P1 on its own.
- Consider a **guided second step** after adding tools: *"You've allowed 3 tools. Narrow what they may
  do?"* — with a clear skip.
- Show the **cost of not scoping**, honestly. The product already has the sentence: an unscoped
  allowlist is what the agent framework already gives you.

### 4b. Rebalance the two panes
The rego pane takes ~50% of a very wide sheet and is read-only, unreadable to most operators, and never
edited. *(Opinion: it should be collapsible or a tab, with the reclaimed width going to authoring.)*
Keep it available — it is genuinely load-bearing for expert trust — but stop paying half the screen for
it by default.

### 4c. Make the mode fork safer
Rules mode's failure is silent: a rule that matches nothing simply never fires, and the policy looks
enforcing. Allowlist mode's failure is loud: the tool is denied. The UI should reflect that asymmetry —
the copy already differs (*"this rule will never fire"* vs *"this entry won't match until such a tool
appears"*) but nothing else does.

### 4d. Bring the registry forward
The builder now knows which tools are **declared** (schema, scopeable) vs **observed** (name only). Today
that surfaces as one small note under the input. It could shape the whole tool-adding experience.

## 5. The three registry states — must all be visible

| State | Condition | Current copy | Tone |
|---|---|---|---|
| **Unknown** | not in the registry | `⚠ "{name}" is not in this namespace's tool registry — this entry won't match until such a tool appears` (allowlist) / `…— this rule will never fire` (rules) | warning, `--escalate` |
| **Declared** | `source === "mcp_declared"` | `declared by an MCP server in this namespace` + `— its arguments can be scoped` when a schema exists | informational, muted |
| **Observed** | in the registry, no schema | *(nothing today)* | — |

Plus a **fourth, silent state**: when the registry is empty or the fetch failed, `registry === null` and
**all warnings are suppressed**. This is deliberate — *ignorance is not evidence of absence*, and an
empty registry is the default in most deployments. The design must not turn silence into a false all-clear.

**Non-negotiable: these are advisory. They never block Add, Dry-run or Save.** Deny-by-default requires
authoring rules for tools nobody has called yet.

## 6. Known defects to design away

| # | Defect | Where |
|---|---|---|
| 1 | Scope drill-down undiscoverable | the whole point of this brief |
| 2 | A `not`-wrapped fact renders **nothing** — it is compiled and enforced but invisible and uneditable | fact rows |
| 3 | Fact field names are **read-only spans** — to change a field you delete the row and re-add | fact rows |
| 4 | Constraint/fact inputs use `className="mono"` **without `.input`** — raw browser styling, no height, radius or elevated background. They look unfinished next to every other field in the app. | both row types |
| 5 | Row order is inconsistent: the fact dropdown renders **first** in the add row, but fact rows render **after** constraint rows | scope panel |
| 6 | 10.5–11.5px type throughout, below the rest of the app | scope panel |
| 7 | `--text-dim` is used but **is not a defined token** | hint lines |
| 8 | Disabled buttons can't show their `title`, so "why can't I save?" is unanswerable | step 3 |
| 9 | Two different vocabularies for one concept: "constraints" (one argument) vs "facts" (whole call). Operators must learn both. *(Opinion: worth unifying in the UI even though they differ in the engine.)* | scope panel |

## 7. Required components

| Component | Exists? |
|---|---|
| `Panel`, `KitButton`, `.pill`, Monaco editor | ✅ |
| **Provenance badge** (declared / observed / unknown) | ❌ new — shared with brief 01 |
| **Argument tree / picker** with disabled+reason states | ❌ new — shared with brief 01 |
| **Token / multi-select input** for value lists | ❌ new — today every list is comma-separated text |
| **Segmented control** for the mode fork | ❌ new |
| **Collapsible / tabbed side pane** for the rego | ❌ new |
| **Inline "why disabled"** pattern | ❌ new |

## 8. Acceptance criteria

1. A first-time operator discovers argument scoping **without being told it exists.**
2. For every allowed tool it is visible, without clicking, whether it is scoped and whether it *could* be.
3. The rules/allowlist fork communicates that it inverts the meaning of conditions.
4. Registry warnings are visible, honest, and never block authoring.
5. A negated fact is visible somewhere, even if not editable.
6. Every disabled control states its reason as text.
7. The rego pane remains reachable but no longer costs half the screen by default.
8. Scope rows use the app's real input styling.
