# 01 — Tools page *(new)*

**Status:** does not exist. Net-new page, no route allocated.
**Priority:** 1 of 4.
**Backend:** ready and deployed. `GET /api/v1/tools` — `norviq/api/routers/tools.py`.

---

## 1. Why this page must exist

Norviq now knows what tools exist in a namespace, and **nothing shows it to anyone.** The registry is
consumed only inside the policy builder's autocomplete and its unknown-tool warning.

The question the page answers, which nothing currently answers:

> *What tools does Norviq know about in this namespace — and how well does it know each one?*

"How well" is the substance. A tool Norviq has a **declared definition** for can have its arguments
scoped by policy. A tool it has merely **seen in traffic** can only be allowed or denied by name. That
distinction determines what security an operator can actually express, and today it is invisible.

## 2. The one rule that governs this page

**Two tiers. Never merged. Always labelled.**

| Tier | `source` | What it means | What you can do with it |
|---|---|---|---|
| **Declared** | `mcp_declared` | An MCP server published a definition and an operator approved it. Carries a JSON Schema. | Allow it; **scope its arguments**; see its description, server, pin status and scan findings |
| **Observed** | `observed` | The name appeared in real, non-synthetic traffic in the selected window. | Allow it by name only |

This is not a nicety. The bug this endpoint was built to retire was exactly a UI that flattened sources
of different strength into one list and then treated the union as proof of existence. A single
undifferentiated table of tool names reintroduces it.

**A third state is common and must be designed for:** a declared tool whose schema is *missing*.
`source: "mcp_declared"`, `pin_status: "pinned"`, but `schema_available: false` and `input_schema: null`.
This is not rare or exceptional — the proxy stores the canonical definition as a bare 8 KiB slice, and
because JSON keys are serialised alphabetically, `description` sorts before `inputSchema`; a long or
deliberately padded description evicts the schema entirely. **"Declared but unscopeable" needs its own
visual treatment**, distinct from both "declared and scopeable" and "observed".

## 3. Data

Full contract in [`05-data-contracts.md`](05-data-contracts.md). Summary:

```
GET /api/v1/tools?range=30d&namespace=analytics
→ 200, a BARE JSON ARRAY (no envelope, no total, no pagination)
```

Query params: `namespace` (omit or `all` for every readable namespace), `range` ∈ `24h | 7d | 30d | 90d`
(default `30d`, governs the **observed** tier's lookback only).

Per row:

| Field | Type | Notes |
|---|---|---|
| `name` | string | the identifier policy matches on |
| `name_skeleton` | string | server-computed evasion-normalised form; equals `name` for ordinary ASCII names. **Differs when the name contains homoglyphs or zero-width characters — that is a security signal worth surfacing.** |
| `source` | `"mcp_declared"` \| `"observed"` | |
| `namespace` | string | |
| `server_id` | string \| **null** | null for observed |
| `pin_status` | `"pinned"` \| `"drift"` \| `"quarantined"` \| **null** | null for observed |
| `scan_severity` | `"none"…"critical"` \| **null** | null for observed |
| `description` | string \| **null** | **null when withheld** — see §4 |
| `description_withheld` | boolean | |
| `input_schema` | object \| **null** | JSON Schema |
| `schema_available` | boolean | false on truncation, parse failure, or no schema |
| `last_seen_at` | ISO8601 \| **null** | declared only |

Realistic 14-row example response is in `05-data-contracts.md` — **design against it directly.**

## 4. A hard content-safety constraint

When `description_withheld` is `true`, the server sends `description: null` **on purpose**. The stored
definition holds the *pre-sanitize* text — the exact prompt-injection payload the firewall stripped
before the model ever saw it. Rendering it would put the attack in front of the operator instead.

**The UI must never try to obtain that description another way** (e.g. from `/mcp/pins`
`approved_canonical`, which does contain it). Show the fact of withholding, plus the scan findings that
justify it. Suggested treatment *(opinion)*: a muted italic line — *"description withheld — flagged by
the definition scanner"* — with a link to the findings.

## 5. Page structure

Follow the app's page pattern: `PageHead` (title + subtitle + actions) then a `.stack` of panels.

### Header
- Title: **`Tools`**
- Subtitle *(proposed copy)*: *"Every tool Norviq knows about in this namespace, and how it knows about it."*
- Actions: `Refresh` (`RefreshCw`, `outline` variant), matching MCP Servers.
- **Use the topbar's namespace selector and the `1h 6h 24h 7d 30d` time-range chips.** The range chips
  are real here — they change the observed window. Note the API takes `24h|7d|30d|90d`, so `1h` and `6h`
  either need mapping or should be suppressed on this page. Flag which you choose.

### Stat tiles
`StatTile` row, matching MCP Servers' five-tile pattern. Proposed:

| Label | Value | Colour rule |
|---|---|---|
| `Tools known` | total rows | default |
| `Declared` | `source === "mcp_declared"` | default |
| `Scopeable` | declared **and** `schema_available` | `--allow` when > 0 |
| `Observed only` | `source === "observed"` | `--escalate` when > 0 *(opinion — it means unscopeable traffic)* |
| `Flagged` | `scan_severity` ∈ high/critical | `--block` when > 0 |

### Main table
`DataTable`-shaped. Proposed columns:

| Column | Content | Style |
|---|---|---|
| Tool | `name`; append a warning glyph when `name_skeleton !== name` | `.mono` |
| Source | provenance badge — **declared** / **observed** | pill |
| Scope | **`Scopeable` / `Name only` / `No schema`** — the answer to "what can I do with this" | pill |
| Server | `server_id` or `—` | `.mono`, muted |
| Pin | `pin_status` uppercased | pill; drift → `--block`, quarantined → `--escalate`, pinned → `--allow` |
| Scan | `scan_severity`; render `none` as the muted word `clean` | pill |
| Arguments | count of addressable paths, e.g. `3 of 5` | muted |
| Last seen | `last_seen_at` localised, or `—` | `.mono`, muted |

The **Scope** column is the page's reason to exist. It should be the second thing the eye lands on.

### Detail panel
Clicking a row opens a detail panel (MCP Servers already does this — reuse the interaction).

For a **declared, scopeable** tool:
- `server_id / tool_name` as the title
- description, or the withheld notice
- **the argument tree** — the most valuable thing on the page (see §6)
- pin status and scan findings
- **a primary action: `Scope this tool in a policy →`** which deep-links into the builder with the tool
  pre-added. *(This is the fix for problem P1 approached from the other side — see brief 02.)*

For an **observed** tool:
- an honest explanation that Norviq has no definition, what that costs (arguments cannot be scoped), and
  how to fix it (route the tool through the MCP proxy)
- a link to Audit Log filtered to that tool name

## 6. The argument tree — the centrepiece

Given `input_schema`, the UI can already compute exactly which arguments a policy can address. The logic
exists and is tested: `ui/src/lib/toolSchema.ts` → `schemaPaths(schema): SchemaPath[]`.

```ts
interface SchemaPath {
  path: string;         // dotted, e.g. "filters.customer"
  type: string;         // "string" | "integer" | "array" | "object" | "unknown"
  addressable: boolean; // can a policy match on it
  note?: string;        // why not, or a caveat — ALWAYS show this
  enumValues?: string[];
  required: boolean;
}
```

**Three outcomes to design, all of which must be visible — never hide the unusable ones:**

| Outcome | Example | Treatment |
|---|---|---|
| **Addressable** | `to` (string), `filters.customer` (nested string) | normal, selectable; mark `required` with `*` |
| **Not addressable — type** | `retries` (integer) | disabled + reason: *"integer arguments never appear in param_paths — only text does"* |
| **Not addressable — shape** | `attachments` (array) | disabled + reason: *"list arguments are indexed at runtime (…[0], …[1])"* |

Why type matters, so the design respects it: the engine only records **string** leaves. A policy written
against a numeric argument compares against `""` forever — inside a deny-by-default grant that is a
permanent block. Offering it would be offering a control that silently cannot work.

Why they must still be *shown*: silently omitting an argument teaches the operator it does not exist.
That is the capability-fragment bug in reverse.

Bounds: depth ≤ 12, ≤ 256 paths. `enumValues` should be surfaced — they are the legal values.

## 7. Empty and edge states

**The empty state is the default, not an edge case.** Helm ships `webhook.injection.mcp.enabled: false`,
so a fresh install has zero declared tools. Design it as a first-class screen.

| State | When | Requirement |
|---|---|---|
| **Nothing at all** | no pins, no traffic | Explain both tiers and how to populate each. Mirror MCP Servers' tone: *"A server appears here the first time an agent runs a `tools/list` through the Norviq MCP proxy."* |
| **Observed only** | traffic but no MCP | The most common real state. Should read as *"Norviq sees these being called but has no definitions — here's what that costs you."* Not an error. |
| **Loading** | | `BrandLoader` |
| **Fetch failed** | | Must be distinguishable from empty. "We don't know" ≠ "there is nothing." |
| **Two servers, same tool name** | legitimate and expected | See §8 |
| **Long list** | 40+ rows | No pagination exists. Filter is a whole-row substring match. |

## 8. The collision case — must be handled

Two different MCP servers in one namespace can legitimately serve the same `tool_name` (`read_file` on
both `filesystem` and a second server is a real case in the repo's own fixtures). The API returns **both
rows**, same `name`, different `server_id`. Nothing merges them.

At enforcement time the engine sees only the **bare name**, so a policy naming `read_file` matches
*both*. Name prefixing exists but is off by default and deliberately so.

**The design must:**
1. never key a row on `tool_name` alone (the current MCP page does, producing duplicate React keys)
2. make the duplication visible rather than confusing
3. warn that a policy on this name will govern both

## 9. Required components

| Component | Exists? | Note |
|---|---|---|
| `PageHead`, `Panel`, `StatTile`, `DataTable`, `KitButton`, `.pill` | ✅ | reuse |
| **Provenance badge** (declared/observed) | ❌ new | shared with brief 02 |
| **Scopeability badge** (scopeable / name-only / no schema) | ❌ new | |
| **Argument tree / disclosure list** | ❌ new | shared with brief 02 |
| **Detail side panel** | ~ | MCP Servers has an inline one; consider a shared pattern |
| Table sorting | ❌ backend/component work | flag if your design needs it |

## 10. Acceptance criteria

1. Declared and observed are visually distinct at a glance, and never appear as one undifferentiated list.
2. "Can I scope this tool's arguments?" is answerable **without clicking**.
3. A declared-but-schema-missing tool is distinguishable from both other states.
4. A withheld description is never rendered, and its absence is explained.
5. The empty state teaches how to populate both tiers.
6. Two servers serving one tool name are legible, not confusing.
7. Nothing on the page restricts what an operator may later type into a policy — it informs only.
